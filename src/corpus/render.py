"""Mac side of the rendering stage. The VM (vm/render_worker.py) does the browsing; this module
builds its worklist, ships it, pulls results, and merges them as NEW snapshot rows with rendered=1.

Which URLs get rendered: malicious labels whose latest raw snapshot is app_shell / js_redirect /
empty / client_redirect (the phish is behind JavaScript), plus a slice of 'live' ones so the content
model trains on rendered DOM for everything, plus benign at the same mix so negatives match.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .db import DATA_DIR, SNAP_DIR, connect, tx
from .crawl import classify_landing, is_text_body
from .feeds import now_iso

REN_DIR = DATA_DIR / "render"
WORK = REN_DIR / "worklist.json"
RESULTS = REN_DIR / "out"
RENDER_KINDS = ("app_shell", "js_redirect", "empty", "client_redirect", "redirect_dead", "live")


def vm_target() -> str:
    cfg = DATA_DIR / "render_vm.json"
    if not cfg.exists():
        raise SystemExit("data/render_vm.json missing: {\"host\": \"cc@192.168.64.X\"}")
    return json.loads(cfg.read_text())["host"]


def build_worklist(con, limit: int, benign_ratio: float = 0.5) -> list[dict]:
    q = """SELECT u.id, u.url FROM urls u JOIN snapshots s ON s.url_id=u.id
           WHERE s.id=(SELECT max(id) FROM snapshots WHERE url_id=u.id) AND s.landing_kind IN ({kinds})
             AND u.label {op} 'benign'
             AND NOT EXISTS (SELECT 1 FROM snapshots r WHERE r.url_id=u.id AND r.rendered=1)
           ORDER BY CASE s.landing_kind WHEN 'live' THEN 1 ELSE 0 END, u.first_seen DESC LIMIT ?"""
    kinds = ",".join(f"'{k}'" for k in RENDER_KINDS)
    n_mal = int(limit * (1 - benign_ratio)); n_ben = limit - n_mal
    mal = con.execute(q.format(kinds=kinds, op="!="), (n_mal,)).fetchall()
    ben = con.execute(q.format(kinds="'live','platform_page'", op="="), (n_ben,)).fetchall()
    return [{"id": i, "url": u} for i, u in mal + ben]


def push(limit: int) -> int:
    con = connect()
    _ensure_schema(con)
    items = build_worklist(con, limit)
    REN_DIR.mkdir(parents=True, exist_ok=True); RESULTS.mkdir(exist_ok=True)
    WORK.write_text(json.dumps(items))
    host = vm_target()
    subprocess.run(["ssh", host, "mkdir -p ~/render/in ~/render/out && rm -f ~/render/out/*"], check=True)
    subprocess.run(["scp", "-q", str(WORK), f"{host}:~/render/in/worklist.json"], check=True)
    subprocess.run(["scp", "-q", str(Path(__file__).resolve().parents[2] / "vm/render_worker.py"), f"{host}:~/render/render_worker.py"], check=True)
    subprocess.run(["ssh", host, "cd ~/render && nohup .venv/bin/python render_worker.py > worker.log 2>&1 &"], check=True)
    return len(items)


def pull() -> dict:
    host = vm_target()
    RESULTS.mkdir(parents=True, exist_ok=True)
    subprocess.run(["rsync", "-aq", f"{host}:~/render/out/", str(RESULTS) + "/"], check=True)
    log = subprocess.run(["ssh", host, "tail -2 ~/render/worker.log"], capture_output=True, text=True).stdout.strip()
    con = connect(); _ensure_schema(con)
    merged = skipped = 0
    with tx(con):
        for jp in sorted(RESULTS.glob("*.json")):
            rec = json.loads(jp.read_text())
            uid = int(rec["id"])
            if con.execute("SELECT 1 FROM snapshots WHERE url_id=? AND rendered=1 AND fetched_at>=?", (uid, _iso(rec["t"]))).fetchone():
                skipped += 1; continue
            html = (rec.get("html") or "").encode("utf-8", "ignore")
            html_path = None
            if html:
                import hashlib
                d = hashlib.sha256(html).hexdigest(); p = SNAP_DIR / d[:2] / f"{d}.bin"
                p.parent.mkdir(parents=True, exist_ok=True); p.exists() or p.write_bytes(html); html_path = str(p.relative_to(SNAP_DIR))
            png = RESULTS / f"{uid}.png"
            kind = classify_landing(rec.get("status"), rec.get("final_url"), "text/html", html, True,
                                    orig_url=rec["url"]) if rec.get("ok") else "http_error"
            # The browser already followed client-side redirects and executed the app shell's JS: a
            # rendered DOM with real content is 'live' even if it still contains a meta-refresh tag or
            # sits on a JS-app host. Takedown/auth_wall/platform_page/empty verdicts stand.
            if kind in ("client_redirect", "js_redirect", "redirect_dead", "app_shell") and len(html) > 2000:
                kind = "live"
            con.execute(
                """INSERT INTO snapshots(url_id,fetched_at,ok,error,status_code,final_url,redirect_chain,response_headers,content_type,
                   content_length,html_path,tls_json,elapsed_ms,intercepted,body_sha256,magic_hex,content_disposition,landing_kind,
                   rendered,screenshot_path,render_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)""",
                (uid, _iso(rec["t"]), int(bool(rec.get("ok"))), rec.get("error"), rec.get("status"), rec.get("final_url"),
                 None, None, "text/html", rec.get("html_len"), html_path, None, None, 0, None, None, None, kind,
                 str(png.relative_to(DATA_DIR)) if png.exists() else None,
                 json.dumps({k: rec.get(k) for k in ("title","n_password","n_forms","n_inputs","n_iframes","n_requests","third_party_hosts","console","visible_text")})))
            merged += 1
    return {"merged": merged, "skipped": skipped, "worker_log": log}


def _iso(t: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ensure_schema(con):
    cols = {r[1] for r in con.execute("PRAGMA table_info(snapshots)")}
    for col, typ in (("rendered", "INTEGER NOT NULL DEFAULT 0"), ("screenshot_path", "TEXT"), ("render_json", "TEXT")):
        if col not in cols:
            con.execute(f"ALTER TABLE snapshots ADD COLUMN {col} {typ}")
    con.commit()
