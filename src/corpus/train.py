"""Baseline model + evaluation harness.

The harness is the asset: it reports recall at FIXED false-positive rates (0.1%, 1%) and picks the
operating threshold from an FP target, never from accuracy. Every later model (URL char-CNN, page
encoder, fused) is scored by this same code.

Split policy:
- If first_seen spans >= MIN_TEMPORAL_DAYS, split temporally: train on the past, test on the most
  recent ~20% of days. This is the honest setting for phishing (infrastructure rotates).
- Otherwise GroupKFold by registered domain of the final URL so no host appears on both sides.
Model: sklearn HistGradientBoosting (no native deps). Probabilities calibrated with isotonic
regression on out-of-fold predictions.
"""
from __future__ import annotations

import json
import pickle
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve
from sklearn.model_selection import GroupKFold

from .db import DATA_DIR

MODELS_DIR = DATA_DIR / "models"
MIN_TEMPORAL_DAYS = 14
META_COLS = {"url_id","orig_url","final_url","label","y","source","first_seen","group","landing_kind"}
FP_TARGETS = (0.001, 0.01, 0.05)


def prepare(df: pd.DataFrame):
    X = df.drop(columns=[c for c in META_COLS if c in df.columns]).copy()
    X["tld"] = X["tld"].astype("category").cat.codes  # ordinal; fine for trees
    return X.astype(float), df["y"].to_numpy()


def recall_at_fpr(y, p, fpr_target):
    fpr, tpr, thr = roc_curve(y, p)
    ok = np.where(fpr <= fpr_target)[0]
    if not len(ok):
        return 0.0, 1.0
    i = ok[-1]
    return float(tpr[i]), float(thr[i])


def split_plan(df: pd.DataFrame):
    days = pd.to_datetime(df["first_seen"]).dt.floor("D")
    span = (days.max() - days.min()).days
    if span >= MIN_TEMPORAL_DAYS:
        cutoff = days.quantile(0.8)
        return "temporal", [(np.where(days <= cutoff)[0], np.where(days > cutoff)[0])]
    gkf = GroupKFold(n_splits=5)
    return "group5fold", list(gkf.split(df, df["y"], groups=df["group"]))


def run(features_path: Path, report_path: Path | None = None) -> dict:
    df = pd.read_parquet(features_path)
    X, y = prepare(df)
    mode, folds = split_plan(df)
    oof = np.zeros(len(df))
    for tr, te in folds:
        clf = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.05, max_leaf_nodes=31,
                                             l2_regularization=1.0, class_weight="balanced", random_state=0)
        clf.fit(X.iloc[tr], y[tr])
        oof[te] = clf.predict_proba(X.iloc[te])[:, 1]
    tested = np.concatenate([te for _, te in folds])
    y_t, p_t = y[tested], oof[tested]
    iso = IsotonicRegression(out_of_bounds="clip").fit(p_t, y_t)
    p_cal = iso.predict(p_t)
    res = {
        "mode": mode, "n": int(len(df)), "n_pos": int(y.sum()), "n_neg": int((1 - y).sum()), "n_tested": int(len(tested)),
        "roc_auc": float(roc_auc_score(y_t, p_t)), "pr_auc": float(average_precision_score(y_t, p_t)),
        "by_label": {lab: int(n) for lab, n in df["label"].value_counts().items()},
        "by_source": {s: int(n) for s, n in df["source"].value_counts().items()},
        "operating_points": {},
    }
    for f in FP_TARGETS:
        r, thr = recall_at_fpr(y_t, p_cal, f)
        res["operating_points"][f"fpr_{f}"] = {"recall": r, "threshold": thr}
    # final model on everything + permutation-free importance proxy (gain is unavailable in HGB; use
    # a quick drop-column-free approach: single-feature AUC) — cheap and good enough for a first read
    final = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.05, max_leaf_nodes=31,
                                           l2_regularization=1.0, class_weight="balanced", random_state=0).fit(X, y)
    single = {}
    for c in X.columns:
        v = X[c].to_numpy()
        if np.nanstd(v) == 0:
            continue
        a = roc_auc_score(y, np.nan_to_num(v))
        single[c] = float(max(a, 1 - a))
    res["top_single_feature_auc"] = dict(sorted(single.items(), key=lambda kv: -kv[1])[:15])
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    oof_df = df[["url_id", "final_url", "label", "source", "group", "y"]].copy()
    oof_df["p_raw"] = oof; oof_df["p_cal"] = iso.predict(oof)
    oof_df.to_parquet(MODELS_DIR / "baseline_oof.parquet", index=False)
    with open(MODELS_DIR / "baseline_hgb.pkl", "wb") as fh:
        pickle.dump({"model": final, "calibrator": iso, "columns": list(X.columns), "trained_at": datetime.utcnow().isoformat()}, fh)
    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(render(res))
    return res


def render(r: dict) -> str:
    ops = "\n".join(f"| {k.replace('fpr_','')} | {v['recall']:.3f} | {v['threshold']:.3f} |" for k, v in r["operating_points"].items())
    feats = "\n".join(f"| {k} | {v:.3f} |" for k, v in r["top_single_feature_auc"].items())
    return f"""# Baseline report — {datetime.utcnow():%Y-%m-%d %H:%M} UTC

Split: **{r['mode']}**  ·  rows {r['n']:,} (pos {r['n_pos']:,} / neg {r['n_neg']:,})  ·  tested {r['n_tested']:,}
Labels: {r['by_label']}
Sources: {r['by_source']}

ROC AUC **{r['roc_auc']:.4f}**   PR AUC **{r['pr_auc']:.4f}**

## Operating points (calibrated, out-of-fold)
| target FPR | recall | threshold |
|---|---|---|
{ops}

## Strongest single features (AUC, either direction)
| feature | AUC |
|---|---|
{feats}

## Read this honestly
- {'Temporal split: the number above is what to expect on tomorrow\'s phish.' if r['mode']=='temporal' else 'GROUP split, not temporal: hosts never leak across folds, but time does. Expect the real-world number to be lower until the corpus has >=14 days of first_seen depth and this flips to temporal automatically.'}
- Positives are feed-sourced (PhishTank/OpenPhish/URLhaus); negatives are Tranco + platform pages. Anything the feeds systematically miss, the model has never seen.
- The FPR targets are measured on this negative set. 1% here is not 1% of a real user's browsing; the benign distribution in the wild is broader and mostly boring, which usually helps.
"""
