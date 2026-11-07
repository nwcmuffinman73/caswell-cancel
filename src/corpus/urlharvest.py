"""Benign URL strings with realistic paths, harvested read-only from stored benign HTML.

Not crawled, not inserted into `urls`: the URL model only needs the string. Keeps links whose
registered domain is either the page's own domain or a Tranco top-50k domain, so the label stays
benign with high confidence. Output: data/url_corpus/benign_links.parquet (url, group, src_domain).
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import pandas as pd
from bs4 import BeautifulSoup

from .db import DATA_DIR, SNAP_DIR, connect
from .feeds import split_host

OUT = DATA_DIR / "url_corpus" / "benign_links.parquet"
SKIP = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|js|woff2?|xml|rss|mp[34]|zip|pdf)(\?|$)|^(mailto|tel|javascript|data):", re.I)


def harvest(max_per_page: int = 40, cap: int = 200_000, top_n: int = 50_000) -> pd.DataFrame:
    con = connect()
    top = {r[0] for r in con.execute("SELECT registered_domain FROM urls WHERE source='tranco' AND source_rank<=?", (top_n,))}
    bad = {r[0] for r in con.execute("SELECT registered_domain FROM urls WHERE label IN ('phishing','malware')")}
    pages = con.execute(
        """SELECT u.registered_domain, s.final_url, s.html_path FROM urls u JOIN snapshots s ON s.url_id=u.id
           WHERE u.label='benign' AND s.landing_kind IN ('live','platform_page') AND s.html_path IS NOT NULL
             AND s.id=(SELECT max(id) FROM snapshots WHERE url_id=u.id)""").fetchall()
    seen, out = set(), []
    for reg, base, html_path in pages:
        p = SNAP_DIR / html_path
        if not p.exists():
            continue
        try:
            soup = BeautifulSoup(p.read_bytes()[:400_000], "lxml")
        except Exception:
            continue
        n = 0
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or SKIP.search(href):
                continue
            full = urljoin(base, href).split("#")[0]
            if not full.startswith("http") or len(full) > 200 or full in seen:
                continue
            sp = urlsplit(full)
            if sp.path in ("", "/") and not sp.query:
                continue  # we have plenty of bare hosts already
            try:
                _, r2 = split_host(full)
            except Exception:
                continue
            if r2 in bad or (r2 != reg and r2 not in top):
                continue
            seen.add(full); out.append((full, r2, reg)); n += 1
            if n >= max_per_page or len(out) >= cap:
                break
        if len(out) >= cap:
            break
    df = pd.DataFrame(out, columns=["url", "group", "src_domain"])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(OUT, index=False)
    return df


# ------------------------------------------------------------------ sitemaps of top sites
# Real deep paths on well-known domains (github.com/<org>/<repo>, nytimes.com/2026/…): the benign
# distribution a user actually browses. Read-only, network-only, nothing written to the DB.
import re as _re
import httpx as _httpx
from concurrent.futures import ThreadPoolExecutor as _TPE, as_completed as _asc

SITEMAP_OUT = DATA_DIR / "url_corpus" / "benign_sitemaps.parquet"
_LOC = _re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", _re.I)


def _fetch(c, url):
    try:
        r = c.get(url)
        return r.text if r.status_code == 200 and len(r.content) < 15_000_000 else ""
    except Exception:
        return ""


def _sitemap_urls(c, domain: str, per_domain: int) -> list[str]:
    cands = []
    robots = _fetch(c, f"https://{domain}/robots.txt") or _fetch(c, f"https://www.{domain}/robots.txt")
    cands += [m.strip() for m in _re.findall(r"(?im)^sitemap:\s*(\S+)", robots)]
    cands += [f"https://{domain}/sitemap.xml", f"https://www.{domain}/sitemap.xml", f"https://{domain}/sitemap_index.xml"]
    out, seen_maps = [], set()
    for sm in cands[:6]:
        if sm in seen_maps or len(out) >= per_domain:
            continue
        seen_maps.add(sm)
        body = _fetch(c, sm)
        if not body:
            continue
        locs = _LOC.findall(body)
        if "<sitemapindex" in body[:2000].lower():
            for child in locs[:3]:
                if len(out) >= per_domain:
                    break
                cb = _fetch(c, child)
                out += [u for u in _LOC.findall(cb) if u.startswith("http")][: per_domain - len(out)]
        else:
            out += [u for u in locs if u.startswith("http")][: per_domain - len(out)]
    # keep only URLs on the same registered domain, with a path, de-duplicated
    keep, seen = [], set()
    for u in out:
        try:
            _, r2 = split_host(u)
        except Exception:
            continue
        sp = urlsplit(u)
        if r2 == domain and (sp.path not in ("", "/") or sp.query) and len(u) <= 200 and u not in seen:
            seen.add(u); keep.append(u)
    return keep


def harvest_sitemaps(top_n: int = 1500, per_domain: int = 60, workers: int = 24) -> pd.DataFrame:
    con = connect()
    domains = [r[0] for r in con.execute(
        "SELECT DISTINCT registered_domain FROM urls WHERE source='tranco' AND source_rank<=? ORDER BY source_rank", (top_n,))]
    bad = {r[0] for r in con.execute("SELECT registered_domain FROM urls WHERE label IN ('phishing','malware')")}
    domains = [d for d in domains if d not in bad]
    c = _httpx.Client(timeout=_httpx.Timeout(12.0, connect=6.0), follow_redirects=True, verify=False,
                      headers={"User-Agent": "CaswellCancel-corpus/0.1 (+research; sitemap read)"})
    rows = []
    with c, _TPE(max_workers=workers) as ex:
        futs = {ex.submit(_sitemap_urls, c, d, per_domain): d for d in domains}
        for f in _asc(futs):
            d = futs[f]
            for u in f.result():
                rows.append((u, d, d))
    df = pd.DataFrame(rows, columns=["url", "group", "src_domain"])
    SITEMAP_OUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(SITEMAP_OUT, index=False)
    return df


# ------------------------------------------------------------------ public APIs for benign deep paths
# on hosts the probe set flagged (github.com has no sitemap). Unauthenticated GitHub API: 60 req/hr.
API_OUT = DATA_DIR / "url_corpus" / "benign_api.parquet"


def harvest_github(calls: int = 50) -> pd.DataFrame:
    import random, time
    c = _httpx.Client(timeout=20, headers={"User-Agent": "CaswellCancel-corpus/0.1", "Accept": "application/vnd.github+json"})
    rows, since = [], random.randint(1, 900_000_000)
    for _ in range(calls):
        try:
            r = c.get("https://api.github.com/repositories", params={"since": since})
        except Exception:
            break
        if r.status_code != 200:
            break
        batch = r.json()
        if not batch:
            break
        for repo in batch:
            u = repo.get("html_url")
            if u:
                rows.append((u, "github.com", "github.com"))
                # a few realistic deep paths per repo
                for suffix in ("/issues", "/blob/main/README.md", "/releases", "/pulls"):
                    rows.append((u + suffix, "github.com", "github.com"))
        since = batch[-1]["id"] + random.randint(1, 50_000)
        time.sleep(0.3)
    df = pd.DataFrame(rows, columns=["url", "group", "src_domain"])
    if API_OUT.exists():
        df = pd.concat([pd.read_parquet(API_OUT), df]).drop_duplicates("url")
    API_OUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(API_OUT, index=False)
    return df
