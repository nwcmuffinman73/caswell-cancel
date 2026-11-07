"""SQLite corpus store.

Design rules that matter for the model later:
- Every row carries a timestamp so we can do TEMPORAL train/validation splits.
- Labels are per-source so disagreements between feeds are visible, not averaged away.
- Snapshots are separate from URLs: one URL may be crawled many times as it ages or dies.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DB_PATH = DATA_DIR / "corpus.sqlite"
SNAP_DIR = DATA_DIR / "snapshots"

SCHEMA = """
CREATE TABLE IF NOT EXISTS urls (
  id          INTEGER PRIMARY KEY,
  url         TEXT NOT NULL UNIQUE,
  host        TEXT NOT NULL,
  registered_domain TEXT NOT NULL,
  label       TEXT NOT NULL CHECK (label IN ('benign','phishing','malware','unknown')),
  source      TEXT NOT NULL,
  source_rank INTEGER,
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_urls_label ON urls(label);
CREATE INDEX IF NOT EXISTS idx_urls_first_seen ON urls(first_seen);
CREATE INDEX IF NOT EXISTS idx_urls_domain ON urls(registered_domain);

CREATE TABLE IF NOT EXISTS snapshots (
  id            INTEGER PRIMARY KEY,
  url_id        INTEGER NOT NULL REFERENCES urls(id),
  fetched_at    TEXT NOT NULL,
  ok            INTEGER NOT NULL,
  error         TEXT,
  status_code   INTEGER,
  final_url     TEXT,
  redirect_chain TEXT,
  response_headers TEXT,
  content_type  TEXT,
  content_length INTEGER,
  html_path     TEXT,
  tls_json      TEXT,
  elapsed_ms    INTEGER,
  intercepted   INTEGER NOT NULL DEFAULT 0,
  body_sha256   TEXT,
  magic_hex     TEXT,
  content_disposition TEXT,
  landing_kind  TEXT
);
CREATE INDEX IF NOT EXISTS idx_snap_url ON snapshots(url_id);
CREATE INDEX IF NOT EXISTS idx_snap_fetched ON snapshots(fetched_at);

CREATE TABLE IF NOT EXISTS ingest_runs (
  id        INTEGER PRIMARY KEY,
  source    TEXT NOT NULL,
  ran_at    TEXT NOT NULL,
  fetched   INTEGER NOT NULL,
  inserted  INTEGER NOT NULL,
  updated   INTEGER NOT NULL,
  note      TEXT
);
"""


def connect(path: Path = DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript(SCHEMA)
    _migrate(con)
    return con


def _migrate(con: sqlite3.Connection) -> None:
    cols = {r[1] for r in con.execute("PRAGMA table_info(snapshots)")}
    adds = {
        "intercepted": "INTEGER NOT NULL DEFAULT 0",
        "body_sha256": "TEXT",
        "magic_hex": "TEXT",
        "content_disposition": "TEXT",
        "landing_kind": "TEXT",
    }
    for col, typ in adds.items():
        if col not in cols:
            con.execute(f"ALTER TABLE snapshots ADD COLUMN {col} {typ}")
    con.execute("CREATE INDEX IF NOT EXISTS idx_snap_landing ON snapshots(landing_kind)")
    con.commit()


@contextmanager
def tx(con: sqlite3.Connection):
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
