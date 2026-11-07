"""Snapshot crawler.

For each URL: follow redirects, record the chain, capture response headers, save the HTML body,
and pull the leaf TLS certificate of the FINAL host. Everything is timestamped so a URL can be
re-crawled later to observe decay (phishing pages die in hours; that decay is itself a signal).

Deliberately simple: httpx, no JS execution. A Playwright renderer for screenshots and
post-JS DOM is a later stage and will write into the same snapshots table.
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urljoin

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .db import SNAP_DIR, tx
from .feeds import UA, now_iso

MAX_BODY = 2_000_000  # bytes stored per snapshot

TEXT_TYPES = ("text/", "html", "xml", "json", "javascript", "ecmascript")


def is_text_body(ctype: str, body: bytes) -> bool:
    """Only text-like bodies are kept on disk. Binaries (malware payloads from URLhaus, installers,
    archives) are reduced to sha256 + magic bytes so the corpus never holds executable malware."""
    c = (ctype or "").lower()
    if any(t in c for t in TEXT_TYPES):
        return True
    if not c:  # no declared type: sniff
        head = body[:512].lstrip().lower()
        return head.startswith((b"<!doctype", b"<html", b"<head", b"<body", b"<script", b"<?xml"))
    return False

# Hosts that ISP / network security products redirect blocked sites to. A snapshot whose final
# URL lands here is NOT the target page and must never be used as a training example.
INTERCEPTOR_HOSTS = (
    "cujo.io",                 # Charter Spectrum "Security Shield", Comcast xFi Advanced Security
    "block.opendns.com",       # Cisco Umbrella / OpenDNS
    "blocked.cleanbrowsing.org",
    "safebrowsing.google.com", # unlikely as a redirect target, kept defensively
    "securityshield.spectrum.net",
    "xfinity.com/learn/internet-service/security",
)


def is_intercepted(final_url: str | None) -> bool:
    if not final_url:
        return False
    u = final_url.lower()
    return any(h in u for h in INTERCEPTOR_HOSTS)


def tls_info(host: str, port: int = 443, timeout: float = 6.0) -> dict | None:
    """Leaf certificate facts. Uses an unverified context on purpose: we want to SEE bad certs."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                proto = ss.version()
    except Exception as e:
        return {"error": type(e).__name__}
    if not der:
        return {"error": "no-cert"}
    cert = x509.load_der_x509_certificate(der)
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    nb = cert.not_valid_before_utc
    na = cert.not_valid_after_utc
    return {
        "protocol": proto,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "age_days": (datetime.now(timezone.utc) - nb).days,
        "validity_days": (na - nb).days,
        "san_count": len(sans),
        "sans": sans[:50],
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "self_signed": cert.subject == cert.issuer,
    }


# ------------------------------------------------------------------ label hygiene
# A feed saying "phishing" and a 200 status does not mean we captured a phishing page. Phish live on
# shorteners and legit platforms; by the time we fetch, many have been taken down, replaced by the
# platform's login wall, or were only ever a redirector. landing_kind records what we actually got.
# Only landing_kind='live' rows are eligible as positive training examples.

AUTH_WALL_HOSTS = (
    "accounts.google.com", "login.microsoftonline.com", "login.live.com", "login.microsoft.com",
    "www.facebook.com/login", "facebook.com/login", "appleid.apple.com", "login.yahoo.com",
    "auth.openai.com", "id.atlassian.com", "login.salesforce.com", "signin.aws.amazon.com",
)
TAKEDOWN_URL_MARKERS = (
    # a shortener that lands on ITSELF is a dead/expired short link
    "qrco.de/", "q-r.to/", "l.ead.me/", "ead.me/", "myurls.bio/", "bit.ly/", "tinyurl.com/", "cutt.ly/", "rb.gy/", "t.ly/",
    "portfolio.adobe.com/missing", "flowcode.com/terms/404", "/inactive.htm", "static.hotmart.com/shortener",
    "suspended", "sedoparking.com", "parkingcrew.net", "dan.com", "afternic.com", "hugedomains.com",
    "godaddy.com/forsale", "boxmode.io", "/404", "/not-found", "/notfound", "linktr.ee/404",
)
TAKEDOWN_TITLE_RE = re.compile(
    r"(page not found|not found|404|account suspended|site suspended|domain (is )?(for sale|free to take|expired)|"
    r"this site can.t be reached|website (is )?(unavailable|disabled|expired)|inactive location|"
    r"shortener url - 404|this link is no longer|link expired|has been removed|coming soon|"
    r"index of /|apache2? .* default|welcome to nginx|iis windows server|plesk|cpanel|parked|"
    r"adobe portfolio \| build|untitled presentation|untitled document|microsoft forms$|google forms$)",
    re.I,
)
ERROR_BODY_RE = re.compile(rb"(<b>(parse|fatal) error</b>|warning: .*on line \d+|internal server error|"
                           rb"database error|error establishing a database connection)", re.I)
META_REFRESH_RE = re.compile(
    rb"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?\s*\d+\s*;\s*url\s*=\s*['"]?([^'"\s>]+)|"""
    rb"""<meta[^>]+content\s*=\s*["']?\s*\d+\s*;\s*url\s*=\s*['"]?([^'"\s>]+)['"]?[^>]*http-equiv\s*=\s*["']?refresh""",
    re.I,
)
JS_REDIRECT_RE = re.compile(
    rb"""(?:window\.|document\.|top\.|self\.|parent\.)?location(?:\.href|\.replace\(|\.assign\(|\s*=)\s*=?\s*["']((?:https?:)?//[^"']+|/[^"']+)["']""",
    re.I,
)
FRAME_RE = re.compile(rb"""<(?:frame|iframe)[^>]+src\s*=\s*["']((?:https?:)?//[^"']+|/[^"']+)["']""", re.I)
TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
# location assignment whose target is NOT a string literal (variable, Firebase lookup, decode()):
# a redirector that needs a JS engine to resolve.
JS_DYNAMIC_REDIRECT_RE = re.compile(
    rb"""(?:window\.|document\.|top\.|self\.)?location(?:\.href|\.replace\(|\.assign\(|\s*=)\s*=?\s*(?!["'])[A-Za-z_$(][^;\n]{0,120}""",
    re.I,
)
REDIRECT_TITLE_RE = re.compile(r"(redirect|loading|please wait|one moment|just a moment)", re.I)

# Link-service interstitials and dead-shortener pages: never the target.
INTERSTITIAL_TITLE_RE = re.compile(
    r"(qr code generator - shortener|warning! \| (the account that created this link|there might be a problem)|"
    r"link (has )?expired|this link is (no longer|not) (active|available)|new website 1|sample background|"
    r"website unavailable|untitled site|my site$|website takedown notice|why didn.t this qr code work|"
    r"this chatbot page is blocked|build a free website - sitebeat|error #429|too many requests|"
    r"what is scanned\.page|clone of clone of)", re.I)
# JS application shells of platforms that host phish: the content is rendered client-side, so the raw
# HTML is the platform's app bootstrap, not the phish. Real phish host, unusable as page content.
APP_SHELL_HOSTS = ("script.google.com", "express.adobe.com", "new.express.adobe.com", "www.dropbox.com", "dropbox.com/scl", "docs.google.com",
                   "drive.google.com", "app.mockplus.com", "www.canva.com", "canva.site", "sway.cloud.microsoft", "sway.office.com",
                   "forms.office.com", "forms.cloud.microsoft", "1drv.ms", "onedrive.live.com", "www.figma.com", "framer.app",
                   "sites.google.com", "lookerstudio.google.com", "www.notion.so", "notion.site", "wixsite.com", "wixstudio.com")
APP_SHELL_TITLE_RE = re.compile(r"^(adobe express|dropbox|mockplus rp|google (slides|docs|sites|forms|drive)|[^|]{0,60} - google slides|figma|canva)$", re.I)


# Legit user-content platforms: a phish landing here is still a phish (content is attacker's).
USER_CONTENT_HOSTS = (
    "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "weebly.com", "web.app",
    "firebaseapp.com", "wixsite.com", "wixstudio.com", "pages.dev", "workers.dev", "r2.dev", "netlify.app",
    "vercel.app", "github.io", "glitch.me", "webflow.io", "godaddysites.com", "blogspot.com", "square.site",
    "canva.site", "sharepoint.com", "000webhostapp.com", "notion.site", "carrd.co", "mystrikingly.com",
    "yolasite.com", "jimdosite.com", "webnode.page", "typeform.com", "jotform.com", "forms.office.com",
    "forms.cloud.microsoft", "s3.amazonaws.com", "amazonaws.com", "blob.core.windows.net", "storage.googleapis.com",
    "ipfs.io", "dweb.link", "fleek.co", "surge.sh", "repl.co", "replit.app", "onrender.com", "herokuapp.com",
)
_top_domains: set[str] | None = None


def top_domains(con=None, n: int = 5000) -> set[str]:
    """Tranco top-N registered domains, cached. A landing on one of these (that is not a user-content
    host) is the platform's own page, not a phish: 'platform_page'."""
    global _top_domains
    if _top_domains is None:
        from .db import connect
        c = con or connect()
        _top_domains = {r[0] for r in c.execute(
            "SELECT registered_domain FROM urls WHERE source='tranco' AND source_rank<=?", (n,))}
    return _top_domains


def extract_title(body: bytes) -> str:
    m = TITLE_RE.search(body[:200_000]) if body else None
    return re.sub(r"\s+", " ", m.group(1).decode("utf-8", "ignore")).strip()[:200] if m else ""


def client_redirect_target(body: bytes, base: str) -> str | None:
    """One hop of meta-refresh or trivial JS redirect. No JS engine; only literal string targets."""
    if not body or len(body) > 60_000:
        return None
    m = META_REFRESH_RE.search(body)
    tgt = next((g for g in m.groups() if g), None) if m else None
    if not tgt:
        m = JS_REDIRECT_RE.search(body)
        tgt = m.group(1) if m else None
    if not tgt and len(body) < 4000:
        # a bare frameset / single full-page iframe is a redirect in all but name
        m = FRAME_RE.search(body)
        tgt = m.group(1) if m else None
    if not tgt:
        return None
    t = urljoin(base, tgt.decode("utf-8", "ignore").strip())
    if not t.startswith(("http://", "https://")) or t == base:
        return None
    return t


def classify_landing(status: int | None, final_url: str | None, ctype: str, body: bytes | None, is_text: bool,
                     orig_url: str | None = None, hop_failed: bool = False) -> str:
    """live | auth_wall | takedown | client_redirect | redirect_dead | js_redirect | platform_page |
    app_shell | error_page | binary | empty | http_error"""
    fu = (final_url or "").lower()
    if any(h in fu for h in AUTH_WALL_HOSTS):
        return "auth_wall"
    if status is None:
        return "http_error"
    if status in (401, 402, 404, 410, 451) or status >= 500:
        return "takedown" if status in (404, 410, 451) else "http_error"
    if status == 403:
        return "http_error"  # geo/WAF block: unknown, never a positive example
    if not is_text:
        return "binary"
    if body and client_redirect_target(body, final_url or "http://x/"):
        return "redirect_dead" if hop_failed else "client_redirect"
    if not body or len(body.strip()) < 200:
        return "empty"
    if any(mk in fu for mk in TAKEDOWN_URL_MARKERS):
        return "takedown"
    title = extract_title(body)
    if TAKEDOWN_TITLE_RE.search(title) or INTERSTITIAL_TITLE_RE.search(title):
        return "takedown"
    if any(h in fu for h in APP_SHELL_HOSTS) or APP_SHELL_TITLE_RE.match(title):
        return "app_shell"
    # redirector whose target is resolved by script at runtime (firebase lookup, variable, atob...)
    # Small bodies only: real phishing kits are larger and also assign location after form submit.
    if (len(body) < 8_000 and JS_DYNAMIC_REDIRECT_RE.search(body)) or (len(body) < 60_000 and REDIRECT_TITLE_RE.search(title)):
        return "js_redirect"
    # A redirect carried us from the listed URL to a DIFFERENT major legit site's own page
    # (google.com, facebook.com, paypal.me): the phish is gone, we are looking at the platform.
    # Same-domain landings are never demoted, so benign Tranco sites stay 'live'.
    if final_url and orig_url and not any(h in fu for h in USER_CONTENT_HOSTS):
        try:
            from .feeds import split_host
            _, reg_final = split_host(final_url)
            _, reg_orig = split_host(orig_url)
            if reg_final != reg_orig and reg_final in top_domains():
                return "platform_page"
        except Exception:
            pass
    if len(body) < 1500 and ERROR_BODY_RE.search(body):
        return "error_page"
    if ERROR_BODY_RE.search(body[:2000]):
        return "error_page"
    return "live"


def fetch_one(url_id: int, url: str, client: httpx.Client) -> dict:
    t0 = time.perf_counter()
    rec: dict = {"url_id": url_id, "fetched_at": now_iso(), "ok": 0, "intercepted": 0}
    try:
        try:
            r = client.get(url)
        except httpx.ConnectError as e:
            # Tranco lists infrastructure apexes (akamai.net, cloudfront.net). If the apex has no
            # address, try the www host once before giving up.
            u = httpx.URL(url)
            if "nodename" in str(e) or "Name or service" in str(e) or "getaddrinfo" in str(e):
                if not u.host.startswith("www."):
                    r = client.get(str(u.copy_with(host="www." + u.host)))
                else:
                    raise
            else:
                raise
        chain = [str(h.url) for h in r.history] + [str(r.url)]
        body = r.content[:MAX_BODY]
        ctype = r.headers.get("content-type", "")
        # Follow up to 2 hops of meta-refresh / literal JS redirects (shortener and Google-Slides style
        # redirectors). Server-side redirects were already followed by httpx.
        hop_failed = False
        for _ in range(2):
            if not is_text_body(ctype, body):
                break
            tgt = client_redirect_target(body, str(r.url))
            if not tgt or tgt in chain:
                break
            try:
                r2 = client.get(tgt)
            except Exception as hop_err:
                hop_failed = True
                chain.append(f"!{tgt} ({type(hop_err).__name__})")
                break
            r = r2
            chain += [str(h.url) for h in r.history] + [str(r.url)]
            body = r.content[:MAX_BODY]
            ctype = r.headers.get("content-type", "")
        html_path = None
        digest = hashlib.sha256(body).hexdigest() if body else None
        if body and is_text_body(ctype, body):
            p = SNAP_DIR / digest[:2] / f"{digest}.bin"
            p.parent.mkdir(parents=True, exist_ok=True)
            if not p.exists():
                p.write_bytes(body)
            html_path = str(p.relative_to(SNAP_DIR))
        rec.update(
            ok=1,
            status_code=r.status_code,
            final_url=str(r.url),
            redirect_chain=json.dumps(chain),
            response_headers=json.dumps(dict(r.headers)),
            content_type=ctype,
            content_length=len(r.content),
            html_path=html_path,
            intercepted=int(is_intercepted(str(r.url))),
            body_sha256=digest,
            magic_hex=body[:16].hex() if body else None,
            content_disposition=r.headers.get("content-disposition"),
            landing_kind=classify_landing(r.status_code, str(r.url), ctype, body, is_text_body(ctype, body),
                                          orig_url=url, hop_failed=hop_failed),
        )
        final = httpx.URL(str(r.url))
        if final.scheme == "https":
            rec["tls_json"] = json.dumps(tls_info(final.host, final.port or 443))
    except Exception as e:
        rec["error"] = f"{type(e).__name__}: {str(e)[:200]}"
        rec["landing_kind"] = "http_error"
        # still try TLS on the original host; a dead page with a fresh cert is informative
        try:
            u = httpx.URL(url)
            if u.scheme == "https":
                rec["tls_json"] = json.dumps(tls_info(u.host, u.port or 443))
        except Exception:
            pass
    rec["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
    return rec


def store(con, rec: dict) -> None:
    cols = ["url_id","fetched_at","ok","error","status_code","final_url","redirect_chain",
            "response_headers","content_type","content_length","html_path","tls_json","elapsed_ms",
            "intercepted","body_sha256","magic_hex","content_disposition","landing_kind"]
    with tx(con):
        con.execute(
            f"INSERT INTO snapshots({','.join(cols)}) VALUES({','.join('?'*len(cols))})",
            [rec.get(c) for c in cols],
        )


def pending(con, label: str | None, limit: int, recrawl_days: int | None):
    """URLs with no snapshot (or none newer than recrawl_days), newest-first so fresh phish get
    captured before they die."""
    q = """SELECT u.id, u.url FROM urls u
           WHERE (? IS NULL OR u.label = ?)
             AND NOT EXISTS (
               SELECT 1 FROM snapshots s WHERE s.url_id = u.id AND s.intercepted = 0
                 AND (? IS NULL OR s.fetched_at > strftime('%Y-%m-%dT%H:%M:%SZ','now', ?)))
           ORDER BY u.first_seen DESC, u.source_rank ASC LIMIT ?"""
    win = f"-{recrawl_days} days" if recrawl_days else None
    return con.execute(q, (label, label, win, win, limit)).fetchall()


def run(con, label: str | None, limit: int, workers: int, recrawl_days: int | None, progress=None) -> dict:
    rows = pending(con, label, limit, recrawl_days)
    stats = {"attempted": len(rows), "ok": 0, "failed": 0}
    if not rows:
        return stats
    client = httpx.Client(
        timeout=httpx.Timeout(15.0, connect=8.0),
        follow_redirects=True,
        max_redirects=10,
        headers={"User-Agent": UA, "Accept": "text/html,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.9"},
        verify=False,  # we record bad TLS; we do not refuse it
    )
    with client, ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fetch_one, uid, url, client): uid for uid, url in rows}
        for f in as_completed(futs):
            rec = f.result()
            store(con, rec)
            stats["ok" if rec["ok"] else "failed"] += 1
            if progress:
                progress()
    return stats


def doctor(con, probes: int = 8) -> dict:
    """Probe recent malicious URLs. If the network rewrites them to a block page, report it.
    Returns {"intercepted": bool, "probed": n, "hits": n, "interceptor": host|None}."""
    rows = con.execute(
        "SELECT url FROM urls WHERE label IN ('phishing','malware') ORDER BY first_seen DESC LIMIT ?", (probes,)
    ).fetchall()
    client = httpx.Client(timeout=httpx.Timeout(10.0, connect=6.0), follow_redirects=True, verify=False,
                          headers={"User-Agent": UA})
    hits, interceptor = 0, None
    with client:
        for (u,) in rows:
            try:
                r = client.get(u)
                if is_intercepted(str(r.url)):
                    hits += 1
                    interceptor = httpx.URL(str(r.url)).host
            except Exception:
                pass
    return {"intercepted": hits >= max(1, len(rows) // 4), "probed": len(rows), "hits": hits, "interceptor": interceptor}


def triage(con) -> dict:
    """Backfill landing_kind on snapshots that lack it, from stored bodies. Returns counts by kind."""
    rows = con.execute(
        """SELECT s.id, s.ok, s.status_code, s.final_url, s.content_type, s.html_path, s.body_sha256, s.intercepted,
                  u.url, s.redirect_chain
           FROM snapshots s JOIN urls u ON u.id=s.url_id WHERE s.landing_kind IS NULL"""
    ).fetchall()
    counts: dict[str, int] = {}
    with tx(con):
        for sid, ok, status, final_url, ctype, html_path, sha, intercepted, orig_url, chain in rows:
            hop_failed = bool(chain and '"!' in chain)
            if intercepted:
                kind = "intercepted"
            elif not ok:
                kind = "http_error"
            else:
                body = (SNAP_DIR / html_path).read_bytes() if html_path and (SNAP_DIR / html_path).exists() else None
                is_text = html_path is not None
                if body is None and sha:
                    kind = "binary"
                else:
                    kind = classify_landing(status, final_url, ctype or "", body, is_text, orig_url=orig_url, hop_failed=hop_failed)
            con.execute("UPDATE snapshots SET landing_kind=? WHERE id=?", (kind, sid))
            counts[kind] = counts.get(kind, 0) + 1
    return counts


def recrawl_kind(con, kind: str, limit: int, workers: int, progress=None) -> dict:
    """Re-fetch URLs whose latest snapshot has the given landing_kind (e.g. client_redirect, now that
    the crawler follows them)."""
    rows = con.execute(
        """SELECT u.id, u.url FROM urls u JOIN snapshots s ON s.url_id=u.id
           WHERE s.id = (SELECT max(id) FROM snapshots WHERE url_id=u.id) AND s.landing_kind=?
             AND (SELECT count(*) FROM snapshots WHERE url_id=u.id AND landing_kind=?) < 2
           LIMIT ?""",
        (kind, kind, limit),
    ).fetchall()
    stats = {"attempted": len(rows), "ok": 0, "failed": 0}
    if not rows:
        return stats
    client = httpx.Client(timeout=httpx.Timeout(15.0, connect=8.0), follow_redirects=True, max_redirects=10,
                          headers={"User-Agent": UA, "Accept": "text/html,*/*;q=0.8"}, verify=False)
    with client, ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(fetch_one, uid, url, client) for uid, url in rows]
        for f in as_completed(futs):
            rec = f.result(); store(con, rec)
            stats["ok" if rec["ok"] else "failed"] += 1
            if progress: progress()
    return stats
