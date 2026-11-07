"""URL character CNN — the first deep-learning tier.

Input: the URL string (≤ 200 chars) as a sequence of character ids. Architecture: embedding →
three parallel 1-D convolutions (kernel 3/5/7) → global max-pool → dense → sigmoid. ~60k params,
well under 1 MB in ONNX, so it can run inside the extension on every navigation.

Honesty rules, same as the tabular harness:
- GroupKFold by registered domain (temporal once there is depth) — never random.
- Report recall at fixed FPR, pick the threshold from the FP target.
- Shorteners are excluded as inputs; the model sees landing URLs when we have them.
- Known artifact: benign Tranco rows are bare hosts (https://host/) while phish have paths. Until the
  benign link harvest (source *_links) exists at volume, the number is optimistic. The report says so.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.model_selection import GroupKFold

from .db import DATA_DIR, connect
from .feeds import split_host
from .features import SHORTENERS
from .train import recall_at_fpr

MODELS_DIR = DATA_DIR / "models"
MAXLEN = 200
CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%"
VOCAB = {c: i + 2 for i, c in enumerate(CHARS)}  # 0 pad, 1 unknown
VOCAB_SIZE = len(CHARS) + 2


def encode(url: str) -> np.ndarray:
    u = url.lower()
    u = u.split("://", 1)[1] if "://" in u else u  # scheme carried as a feature elsewhere; strip here
    ids = [VOCAB.get(c, 1) for c in u[:MAXLEN]]
    return np.array(ids + [0] * (MAXLEN - len(ids)), dtype=np.int64)


class UrlCNN(nn.Module):
    def __init__(self, emb: int = 32, ch: int = 64):
        super().__init__()
        self.emb = nn.Embedding(VOCAB_SIZE, emb, padding_idx=0)
        self.convs = nn.ModuleList([nn.Conv1d(emb, ch, k, padding=k // 2) for k in (3, 5, 7)])
        self.head = nn.Sequential(nn.Dropout(0.3), nn.Linear(ch * 3, 64), nn.ReLU(), nn.Dropout(0.3), nn.Linear(64, 1))

    def forward(self, x):                       # x: (B, L) int64
        e = self.emb(x).transpose(1, 2)         # (B, emb, L)
        pooled = [torch.relu(c(e)).amax(dim=2) for c in self.convs]
        return self.head(torch.cat(pooled, dim=1)).squeeze(1)  # logits


# Malicious URLs on these hosts are opaque IDs (a published Slides deck, a Drive file, a OneDrive
# share): the string carries no attacker-chosen signal, and training on them teaches the model that
# every such link is phishing. They are redirectors/containers; their LANDING URL is used when known.
OPAQUE_ID_HOSTS = re.compile(
    r"^(docs\.google\.com/(presentation|document|spreadsheets|forms)/|drive\.google\.com/|forms\.gle/|"
    r"1drv\.ms/|onedrive\.live\.com/|[a-z0-9-]+\.sharepoint\.com/|www\.dropbox\.com/(s|scl)/|"
    r"firebasestorage\.googleapis\.com/|storage\.googleapis\.com/|s3\.amazonaws\.com/|[a-z0-9.-]+\.s3\.amazonaws\.com/|"
    r"www\.canva\.com/design/|www\.flowcode\.com/|qr\.io/|api\.qrserver\.com/)", re.I)


def is_opaque(url: str) -> bool:
    u = url.lower().split("://", 1)[-1]
    return bool(OPAQUE_ID_HOSTS.match(u))


def load_rows(con, limit_per_class: int | None = None, benign_links: bool = True):
    """(url, y, group, first_seen). Uses the final landing URL when a live snapshot exists.
    Adds harvested benign link URLs (paths!) from data/url_corpus/benign_links.parquet if present."""
    rows = con.execute(
        """SELECT u.url, u.label, u.registered_domain, u.first_seen,
                  (SELECT s.final_url FROM snapshots s WHERE s.url_id=u.id AND s.landing_kind IN ('live','platform_page')
                   ORDER BY s.id DESC LIMIT 1)
           FROM urls u"""
    ).fetchall()
    from .features import known_benign_domains, is_redirect_to_benign
    benign_domains = known_benign_domains(con)
    out, cnt = [], {0: 0, 1: 0}
    rng = np.random.default_rng(0)
    rows = list(rows)
    if benign_links:
        import pandas as pd
        for name in ("benign_links.parquet", "benign_sitemaps.parquet", "benign_api.parquet"):
            lp = DATA_DIR / "url_corpus" / name
            if lp.exists():
                for u, g in pd.read_parquet(lp)[["url", "group"]].itertuples(index=False):
                    rows.append((u, "benign", g, "", None))
    rng.shuffle(rows)
    for url, label, reg, first_seen, final in rows:
        if reg in SHORTENERS and not final:
            continue
        u = final or url
        y = int(label != "benign")
        if y and (is_opaque(u) or is_redirect_to_benign(label, u, benign_domains)):
            continue
        try:
            _, g = split_host(u)
        except Exception:
            g = reg
        if limit_per_class and cnt[y] >= limit_per_class:
            continue
        cnt[y] += 1
        out.append((u, y, g, first_seen))
    return out


def train_eval(rows, epochs: int = 6, batch: int = 512, device: str | None = None, folds: int = 5) -> dict:
    device = device or ("mps" if torch.backends.mps.is_available() else "cpu")
    X = np.stack([encode(r[0]) for r in rows]); y = np.array([r[1] for r in rows], dtype=np.float32)
    groups = np.array([r[2] for r in rows])
    oof = np.zeros(len(rows), dtype=np.float32)
    pos_w = torch.tensor([(len(y) - y.sum()) / max(1, y.sum())], device=device)
    for k, (tr, te) in enumerate(GroupKFold(n_splits=folds).split(X, y, groups)):
        model = UrlCNN().to(device)
        opt = torch.optim.AdamW(model.parameters(), lr=2e-3, weight_decay=1e-4)
        lossf = nn.BCEWithLogitsLoss(pos_weight=pos_w)
        Xtr, ytr = torch.from_numpy(X[tr]), torch.from_numpy(y[tr])
        for ep in range(epochs):
            model.train(); perm = torch.randperm(len(tr))
            for i in range(0, len(tr), batch):
                idx = perm[i:i + batch]
                xb, yb = Xtr[idx].to(device), ytr[idx].to(device)
                opt.zero_grad(); loss = lossf(model(xb), yb); loss.backward(); opt.step()
        model.eval()
        with torch.no_grad():
            Xte = torch.from_numpy(X[te])
            oof[te] = np.concatenate([torch.sigmoid(model(Xte[i:i + 2048].to(device))).cpu().numpy() for i in range(0, len(te), 2048)])
    from sklearn.metrics import average_precision_score, roc_auc_score
    res = {"n": int(len(y)), "n_pos": int(y.sum()), "roc_auc": float(roc_auc_score(y, oof)), "pr_auc": float(average_precision_score(y, oof)),
           "operating_points": {}, "device": device, "epochs": epochs}
    for f in (0.001, 0.01, 0.05):
        r, thr = recall_at_fpr(y, oof, f)
        res["operating_points"][f"fpr_{f}"] = {"recall": r, "threshold": float(thr)}
    return res


def fit_full_and_export(rows, epochs: int = 6, batch: int = 512, device: str | None = None) -> Path:
    device = device or ("mps" if torch.backends.mps.is_available() else "cpu")
    X = torch.from_numpy(np.stack([encode(r[0]) for r in rows])); y = torch.tensor([r[1] for r in rows], dtype=torch.float32)
    pos_w = torch.tensor([(len(y) - y.sum()) / max(1, y.sum())], device=device)
    model = UrlCNN().to(device); opt = torch.optim.AdamW(model.parameters(), lr=2e-3, weight_decay=1e-4); lossf = nn.BCEWithLogitsLoss(pos_weight=pos_w)
    for ep in range(epochs):
        model.train(); perm = torch.randperm(len(y))
        for i in range(0, len(y), batch):
            idx = perm[i:i + batch]; opt.zero_grad(); loss = lossf(model(X[idx].to(device)), y[idx].to(device)); loss.backward(); opt.step()
    model.eval().cpu()
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    out = MODELS_DIR / "url_cnn.onnx"
    torch.onnx.export(model, torch.zeros(1, MAXLEN, dtype=torch.int64), str(out), input_names=["chars"], output_names=["logit"],
                      dynamic_axes={"chars": {0: "batch"}, "logit": {0: "batch"}}, opset_version=17, dynamo=False)
    (MODELS_DIR / "url_cnn_vocab.json").write_text(json.dumps({"chars": CHARS, "maxlen": MAXLEN, "pad": 0, "unk": 1}))
    torch.save(model.state_dict(), MODELS_DIR / "url_cnn.pt")
    return out


def verify_onnx(path: Path, sample_urls: list[str]) -> list[float]:
    import onnxruntime as ort
    sess = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
    x = np.stack([encode(u) for u in sample_urls])
    logit = sess.run(["logit"], {"chars": x})[0]
    return (1 / (1 + np.exp(-logit))).tolist()


def run_probes(onnx_path: Path, probes_path: Path, thr_1pct: float) -> str:
    """Score the fixed tricky-URL probe set; return a markdown table. 'miss' = wrong side of the 1%-FPR threshold."""
    lines = [l.split("\t") for l in probes_path.read_text().splitlines() if "\t" in l]
    urls = [u for _, u in lines]
    probs = verify_onnx(onnx_path, urls)
    out, misses = ["| want | prob | verdict | url |", "|---|---|---|---|"], 0
    for (want, u), p in zip(lines, probs):
        got = "p" if p >= thr_1pct else "b"
        miss = got != want
        misses += miss
        out.append(f"| {want} | {p:.3f} | {'MISS' if miss else 'ok'} | {u} |")
    return f"**probes: {len(lines)-misses}/{len(lines)} correct at the 1%-FPR threshold ({thr_1pct:.3f})**\n\n" + "\n".join(out)
