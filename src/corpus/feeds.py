"""Feed ingesters. Each returns an iterable of (url, label, rank_or_None).

Sources:
- tranco:    top-1M benign list, research-grade, manipulation resistant. https://tranco-list.eu
- openphish: free community feed, ~hourly, plain text one URL per line.
- urlhaus:   abuse.ch malware-distribution URLs. CSV. May require an Auth-Key (abuse.ch policy 2025+);
             set URLHAUS_AUTH_KEY in env if the anonymous endpoint refuses.
- phishtank: verified phishing URLs. Bulk CSV works without a key (registration closed 2026).

Benign URLs from Tranco are hostnames only; we store them as https://<host>/ and let the crawler
follow redirects to the real landing page.
"""
from __future__ import annotations

import csv
import io
from json import loads as json_loads
import os
import zipfile
from collections.abc import Iterator
from datetime import datetime, timezone

import httpx
import tldextract

from .db import tx

UA = "CaswellCancel-corpus/0.1 (+research; contact in repo)"
_ext = tldextract.TLDExtract(cache_dir=None)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def split_host(url: str) -> tuple[str, str]:
    """Return (host, registered_domain)."""
    host = httpx.URL(url).host.lower()
    e = _ext(host)
    reg = ".".join(p for p in (e.domain, e.suffix) if p) or host
    return host, reg


# ---------------------------------------------------------------- fetchers

def tranco(limit: int = 100_000, client: httpx.Client | None = None, tail_sample: int = 0,
           tail_from: int = 100_000) -> Iterator[tuple[str, str, int]]:
    """Top-`limit` hosts, plus (optionally) `tail_sample` hosts drawn uniformly from ranks
    [tail_from, 1M]. The tail is where thin, small-site benign pages live; without it the negatives are
    all rich, heavy pages and the model learns page richness instead of maliciousness."""
    import random
    c = client or httpx.Client(timeout=120, follow_redirects=True, headers={"User-Agent": UA})
    r = c.get("https://tranco-list.eu/top-1m.csv.zip")
    r.raise_for_status()
    want_tail = set(random.sample(range(tail_from, 1_000_001), tail_sample)) if tail_sample else set()
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        name = z.namelist()[0]
        with z.open(name) as f:
            for line in io.TextIOWrapper(f, encoding="utf-8"):
                rank_s, host = line.strip().split(",", 1)
                rank = int(rank_s)
                if rank <= limit or rank in want_tail:
                    yield f"https://{host}/", "benign", rank
                elif rank > limit and not want_tail:
                    break


def openphish(client: httpx.Client | None = None) -> Iterator[tuple[str, str, None]]:
    c = client or httpx.Client(timeout=60, follow_redirects=True, headers={"User-Agent": UA})
    r = c.get("https://openphish.com/feed.txt")
    r.raise_for_status()
    for line in r.text.splitlines():
        u = line.strip()
        if u.startswith("http"):
            yield u, "phishing", None


def urlhaus(client: httpx.Client | None = None) -> Iterator[tuple[str, str, None]]:
    c = client or httpx.Client(timeout=120, follow_redirects=True, headers={"User-Agent": UA})
    headers = {}
    if key := os.environ.get("URLHAUS_AUTH_KEY"):
        headers["Auth-Key"] = key
    r = c.get("https://urlhaus.abuse.ch/downloads/csv_online/", headers=headers)
    r.raise_for_status()
    # CSV has '#' comment header lines, then: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
    rows = (ln for ln in r.text.splitlines() if ln and not ln.startswith("#"))
    for rec in csv.reader(rows):
        if len(rec) >= 3 and rec[2].startswith("http"):
            yield rec[2], "malware", None


def phishtank(client: httpx.Client | None = None) -> Iterator[tuple[str, str, None]]:
    """PhishTank verified+online phish. The bulk CSV is downloadable WITHOUT an app key (new
    registrations are closed as of 2026-10). Rate limited per IP to a few pulls/day; the JSON
    endpoint 429s readily, so we use CSV. If PHISHTANK_APP_KEY is set it is used."""
    key = os.environ.get("PHISHTANK_APP_KEY")
    ua = f"phishtank/{key}" if key else UA
    url = f"https://data.phishtank.com/data/{key}/online-valid.csv" if key else "https://data.phishtank.com/data/online-valid.csv"
    c = client or httpx.Client(timeout=180, follow_redirects=True, headers={"User-Agent": ua})
    r = c.get(url)
    if r.status_code == 429:
        raise RuntimeError("PhishTank rate limit (429); try again in a few hours")
    r.raise_for_status()
    rdr = csv.DictReader(io.StringIO(r.text))
    for rec in rdr:
        u = rec.get("url", "")
        if u.startswith("http") and rec.get("verified") == "yes" and rec.get("online", "yes") == "yes":
            yield u, "phishing", None


# ------------------------------------------------------------ hard negatives: benign pages on
# the same user-content platforms that host 33% of phish. Source: Common Crawl CDX index.
# Label noise: CC may contain phish on these hosts too; we exclude any host present in our
# phishing set, and anything that has since died fails the crawl anyway. Source tag 'cc_platform'
# keeps it distinguishable.
PLATFORM_HOSTS = (
    "sites.google.com", "weebly.com", "web.app", "firebaseapp.com", "wixsite.com", "wixstudio.com",
    "pages.dev", "workers.dev", "netlify.app", "vercel.app", "github.io", "glitch.me", "webflow.io",
    "godaddysites.com", "blogspot.com", "square.site", "canva.site", "000webhostapp.com", "notion.site",
    "carrd.co", "mystrikingly.com", "yolasite.com", "jimdosite.com", "webnode.page", "typeform.com",
    "jotform.com", "r2.dev", "surge.sh", "onrender.com", "herokuapp.com", "replit.app",
)


CC_FALLBACK_INDEX = "CC-MAIN-2026-39"  # last known good; refreshed whenever collinfo answers


def _cc_get(c: httpx.Client, url: str, params=None, tries: int = 3) -> httpx.Response | None:
    """index.commoncrawl.org drops connections under load; retry with backoff, never raise."""
    import time
    for i in range(tries):
        try:
            r = c.get(url, params=params)
            if r.status_code == 200:
                return r
            if r.status_code in (404, 400):
                return None
        except (httpx.TransportError, httpx.RemoteProtocolError):
            pass
        time.sleep(2 * (i + 1))
    return None


def _cc_latest_index(c: httpx.Client) -> str:
    r = _cc_get(c, "https://index.commoncrawl.org/collinfo.json")
    try:
        return r.json()[0]["id"] if r else CC_FALLBACK_INDEX
    except Exception:
        return CC_FALLBACK_INDEX


def platform_benign(limit: int = 300, client: httpx.Client | None = None, con=None) -> Iterator[tuple[str, str, None]]:
    """Up to `limit` benign URLs per platform host, one per subdomain, from random CDX index pages."""
    import random
    c = client or httpx.Client(timeout=120, follow_redirects=True, headers={"User-Agent": UA})
    idx = _cc_latest_index(c)
    bad_hosts: set[str] = set()
    if con is not None:
        bad_hosts = {r[0] for r in con.execute("SELECT host FROM urls WHERE label IN ('phishing','malware')")}
    # Platforms where each user site is a PATH, not a subdomain: dedupe on the first two path segments.
    PATH_PLATFORMS = {"sites.google.com": "sites.google.com/view/*", "docs.google.com": "docs.google.com/document/d/*"}
    for plat in PLATFORM_HOSTS:
        base = f"https://index.commoncrawl.org/{idx}-index"
        pattern = PATH_PLATFORMS.get(plat, f"*.{plat}")
        q = {"url": pattern, "output": "json", "filter": ["status:200", "mime:text/html"], "fl": "url"}
        rp = _cc_get(c, base, params={**q, "showNumPages": "true"})
        try:
            pages = int(rp.json().get("pages", 1)) if rp else 1
        except Exception:
            pages = 1
        picks = random.sample(range(pages), min(pages, 3)) if pages > 1 else [0]
        seen: set[str] = set()
        for pg in picks:
            r = _cc_get(c, base, params={**q, "page": pg, "limit": 4000})
            if r is None:
                continue
            for line in r.text.splitlines():
                try:
                    u = json_loads(line)["url"]
                    pu = httpx.URL(u)
                    h = pu.host.lower()
                    key = h if plat not in PATH_PLATFORMS else h + "/" + "/".join(pu.path.split("/")[1:3])
                except Exception:
                    continue
                if key in seen or h in bad_hosts or (plat not in PATH_PLATFORMS and h in (plat, f"www.{plat}")):
                    continue
                if any(x in u.lower() for x in ("login", "signin", "verify", "account", "secure", "wp-admin")):
                    continue  # avoid ambiguous pages even on benign hosts
                seen.add(key)
                yield u, "benign", None
                if len(seen) >= limit:
                    break
            if len(seen) >= limit:
                break


# ------------------------------------------------------------ benign DEEP pages + legit LOGIN pages,
# spidered from benign homepages we already hold. Fixes the "benign = rich homepage" artifact without
# depending on Common Crawl. Login-ish links become source 'tranco_login' (hard negatives: a real
# sign-in form on a real domain); other same-site links become 'tranco_deep'.
LOGIN_RE = __import__("re").compile(r"(log[\s_-]?in|sign[\s_-]?in|signin|login|account|my[\s_-]?account|anmelden|connexion|iniciar|entrar|portal)", __import__("re").I)
SKIP_LINK_RE = __import__("re").compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|js|pdf|zip|mp[34]|woff2?|xml|rss)(\?|$)|^(mailto|tel|javascript):|#", __import__("re").I)


def benign_spider(con, per_site: int = 3, login_per_site: int = 2, max_sites: int = 2000):
    """Yield (url, label, rank, source) from links on stored benign homepages."""
    import random
    from urllib.parse import urljoin
    from bs4 import BeautifulSoup
    from .db import SNAP_DIR
    rows = con.execute(
        """SELECT u.url, u.registered_domain, u.source_rank, s.final_url, s.html_path FROM urls u JOIN snapshots s ON s.url_id=u.id
           WHERE u.label='benign' AND u.source='tranco' AND s.landing_kind IN ('live','platform_page') AND s.html_path IS NOT NULL
             AND s.id=(SELECT max(id) FROM snapshots WHERE url_id=u.id) ORDER BY u.source_rank LIMIT ?""", (max_sites,)).fetchall()
    have = {r[0] for r in con.execute("SELECT url FROM urls")}
    for url, reg, rank, final_url, html_path in rows:
        p = SNAP_DIR / html_path
        if not p.exists():
            continue
        try:
            soup = BeautifulSoup(p.read_bytes()[:600_000], "lxml")
        except Exception:
            continue
        base = final_url or url
        same, login = [], []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or SKIP_LINK_RE.search(href):
                continue
            full = urljoin(base, href).split("#")[0]
            if not full.startswith("http") or full in have:
                continue
            try:
                _, r2 = split_host(full)
            except Exception:
                continue
            if r2 != reg:
                continue
            path = httpx.URL(full).path
            if path in ("", "/"):
                continue
            text = a.get_text(" ", strip=True)[:60]
            if LOGIN_RE.search(text) or LOGIN_RE.search(path):
                login.append(full)
            else:
                same.append(full)
        random.shuffle(same)
        seen = set()
        for u in login[:login_per_site]:
            if u not in seen:
                seen.add(u); have.add(u); yield u, "benign", rank, "tranco_login"
        for u in same[:per_site]:
            if u not in seen:
                seen.add(u); have.add(u); yield u, "benign", rank, "tranco_deep"


def platform_benign_wayback(limit: int = 300, client: httpx.Client | None = None, con=None,
                            hosts=None) -> Iterator[tuple[str, str, None]]:
    """Same idea as platform_benign but from the Internet Archive's CDX index (independent of
    Common Crawl's flaky server). One URL per subdomain, recent captures only."""
    import random
    c = client or httpx.Client(timeout=90, follow_redirects=True, headers={"User-Agent": UA})
    bad_hosts = {r[0] for r in con.execute("SELECT host FROM urls WHERE label IN ('phishing','malware')")} if con is not None else set()
    for plat in (hosts or PLATFORM_HOSTS):
        params = {"url": f"*.{plat}", "output": "json", "fl": "original", "filter": ["statuscode:200", "mimetype:text/html"],
                  "collapse": "urlkey", "from": "2025", "limit": str(limit * 20)}
        try:
            r = c.get("https://web.archive.org/cdx/search/cdx", params=params)
            if r.status_code != 200 or not r.text.strip():
                continue
            rows = r.json()[1:]
        except Exception:
            continue
        random.shuffle(rows)
        seen: set[str] = set()
        for (u,) in rows:
            try:
                pu = httpx.URL(u); h = pu.host.lower()
            except Exception:
                continue
            if h in seen or h in bad_hosts or h in (plat, f"www.{plat}"):
                continue
            if any(x in u.lower() for x in ("login", "signin", "verify", "account", "secure", "wp-admin")):
                continue
            seen.add(h)
            yield u, "benign", None
            if len(seen) >= limit:
                break


FEEDS = {"tranco": tranco, "openphish": openphish, "urlhaus": urlhaus, "phishtank": phishtank,
         "cc_platform": platform_benign, "wb_platform": platform_benign_wayback}


# ---------------------------------------------------------------- upsert

def upsert(con, source: str, rows, note: str | None = None) -> tuple[int, int, int]:
    ts = now_iso()
    fetched = inserted = updated = 0
    with tx(con):
        for url, label, rank in rows:
            fetched += 1
            try:
                host, reg = split_host(url)
            except Exception:
                continue
            row = con.execute(
                """INSERT INTO urls(url,host,registered_domain,label,source,source_rank,first_seen,last_seen)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(url) DO UPDATE SET last_seen=excluded.last_seen,
                        source_rank=COALESCE(excluded.source_rank, urls.source_rank)
                   RETURNING first_seen""",
                (url, host, reg, label, source, rank, ts, ts),
            ).fetchone()
            if row and row[0] == ts:
                inserted += 1
            else:
                updated += 1
        con.execute(
            "INSERT INTO ingest_runs(source,ran_at,fetched,inserted,updated,note) VALUES(?,?,?,?,?,?)",
            (source, ts, fetched, inserted, updated, note),
        )
    return fetched, inserted, updated
