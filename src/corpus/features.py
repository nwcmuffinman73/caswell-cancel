"""Feature extraction: corpus snapshot → one flat row per URL.

Rules:
- Only the LATEST snapshot per URL. Eligible rows: malicious labels with landing_kind='live';
  benign with landing_kind in ('live','platform_page').
- Features are computed on the FINAL url (what the user ends up on) and the captured body. The
  original URL is kept for reference; bare shorteners contribute their landing page, never the
  shortener string itself.
- Every row carries first_seen (ISO) and group (registered domain of final URL) so the trainer
  can split temporally or by domain without leakage.
- Everything here must be computable inside the extension too (URL string, headers, TLS facts,
  DOM) — no features that need the corpus or a server.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from urllib.parse import urlparse

import pandas as pd
from bs4 import BeautifulSoup

from .db import DATA_DIR, SNAP_DIR, connect
from .feeds import split_host

SHORTENERS = {"qrco.de","q-r.to","ead.me","bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","rb.gy","shorturl.at",
              "t.ly","s.id","lnkd.in","rebrand.ly","linktr.ee","goo.gl","ow.ly","buff.ly","href.li"}
SUSPICIOUS_TOKENS = ("login","signin","sign-in","verify","verification","secure","security","account","update",
                     "confirm","banking","bank","wallet","password","credential","unlock","suspend","limited",
                     "invoice","payment","billing","support","helpdesk","webmail","recover","validate","auth")
BRANDS = ("paypal","google","gmail","microsoft","office","outlook","apple","icloud","amazon","facebook","instagram",
          "whatsapp","netflix","linkedin","dropbox","docusign","adobe","chase","wellsfargo","bankofamerica","usps",
          "fedex","dhl","irs","coinbase","binance","metamask","steam","roblox","ebay","walmart","spotify","zoom",
          "okta","github","att","verizon","xfinity","dropbox","onedrive","sharepoint","teams","webmail","roundcube","zimbra")
FREE_CAS = ("let's encrypt","letsencrypt","zerossl","buypass","google trust services","actalis","ssl.com free","cpanel")
OBFUSCATION = (b"eval(", b"unescape(", b"atob(", b"fromCharCode", b"document.write(", b"\\x", b"String.fromCharCode")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def url_features(u: str) -> dict:
    p = urlparse(u)
    host = (p.hostname or "").lower()
    try:
        _, reg = split_host(u)
    except Exception:
        reg = host
    labels = host.split(".") if host else []
    path = p.path or "/"
    q = p.query or ""
    low = u.lower()
    sub = host[: -len(reg) - 1] if host.endswith(reg) and host != reg else ""
    return {
        "url_len": len(u), "host_len": len(host), "path_len": len(path), "query_len": len(q),
        "n_dots_host": host.count("."), "n_subdomains": max(0, len(labels) - 2), "n_hyphens_host": host.count("-"),
        "n_digits_host": sum(ch.isdigit() for ch in host), "digit_ratio_url": sum(ch.isdigit() for ch in u) / max(1, len(u)),
        "host_entropy": entropy(host), "path_entropy": entropy(path), "path_depth": path.count("/"),
        "n_query_params": q.count("&") + (1 if q else 0), "has_at": int("@" in u), "has_ip_host": int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))),
        "has_punycode": int("xn--" in host), "is_https": int(p.scheme == "https"), "has_port": int(p.port not in (None, 80, 443)),
        "n_suspicious_tokens": sum(t in low for t in SUSPICIOUS_TOKENS),
        "brand_in_subdomain": int(any(b in sub for b in BRANDS)), "brand_in_path": int(any(b in path.lower() for b in BRANDS)),
        "brand_is_domain": int(any(reg.split(".")[0] == b for b in BRANDS)),
        "tld": reg.rsplit(".", 1)[-1] if "." in reg else "", "long_random_label": int(any(len(l) >= 20 and entropy(l) > 3.5 for l in labels)),
        "has_double_ext_path": int(bool(re.search(r"\.(pdf|doc|jpg|png)\.(php|html?|exe)", low))),
        "pct_encoded": low.count("%"), "has_hex_blob": int(bool(re.search(r"[0-9a-f]{24,}", low))),
    }


def tls_features(tls_json: str | None) -> dict:
    d = json.loads(tls_json) if tls_json else {}
    issuer = (d.get("issuer") or "").lower()
    return {
        "tls_ok": int(bool(d) and "error" not in d), "tls_age_days": d.get("age_days", -1), "tls_validity_days": d.get("validity_days", -1),
        "tls_self_signed": int(bool(d.get("self_signed"))), "tls_san_count": d.get("san_count", 0),
        "tls_free_ca": int(any(f in issuer for f in FREE_CAS)), "tls_wildcard": int(any(s.startswith("*.") for s in d.get("sans", []))),
        "tls_proto13": int(d.get("protocol") == "TLSv1.3"),
    }


def response_features(status, chain_json, headers_json, orig_url, final_url, content_length) -> dict:
    chain = json.loads(chain_json) if chain_json else []
    h = {k.lower(): v for k, v in (json.loads(headers_json) if headers_json else {}).items()}
    try:
        _, reg_o = split_host(orig_url); _, reg_f = split_host(final_url or orig_url)
    except Exception:
        reg_o = reg_f = ""
    return {
        "status": status or 0, "redirect_hops": max(0, len(chain) - 1), "cross_domain_redirect": int(reg_o != reg_f),
        "from_shortener": int(reg_o in SHORTENERS), "content_length": content_length or 0,
        "has_hsts": int("strict-transport-security" in h), "has_csp": int("content-security-policy" in h),
        "has_xfo": int("x-frame-options" in h), "has_powered_by": int("x-powered-by" in h),
        "server_cloudflare": int("cloudflare" in h.get("server", "").lower()), "server_nginx": int("nginx" in h.get("server", "").lower()),
        "server_apache": int("apache" in h.get("server", "").lower()), "server_litespeed": int("litespeed" in h.get("server", "").lower()),
        "has_set_cookie": int("set-cookie" in h), "cache_nostore": int("no-store" in h.get("cache-control", "").lower()),
    }


def html_features(body: bytes | None, final_url: str) -> dict:
    z = {k: 0 for k in ("n_forms","has_password","n_inputs","n_hidden_inputs","form_action_cross","form_action_empty",
         "n_scripts","n_ext_scripts","n_iframes","n_links","ext_link_ratio","n_imgs","ext_img_ratio","title_len",
         "title_brand","title_suspicious","body_text_len","text_html_ratio","n_obfuscation","has_meta_refresh",
         "favicon_external","has_onsubmit","n_base64","copyright_brand","lang_set","html_len")}
    if not body:
        return z
    html = body[:600_000]
    z["html_len"] = len(html)
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        return z
    try:
        _, reg = split_host(final_url)
    except Exception:
        reg = ""
    def external(u: str) -> bool:
        if not u or u.startswith(("#", "/", "javascript:", "data:", "mailto:")): return False
        try: _, r = split_host(u if "://" in u else "https:" + u if u.startswith("//") else "https://" + u); return r != reg
        except Exception: return False
    forms = soup.find_all("form")
    z["n_forms"] = len(forms)
    z["has_password"] = int(bool(soup.find("input", {"type": re.compile("password", re.I)})))
    inputs = soup.find_all("input"); z["n_inputs"] = len(inputs)
    z["n_hidden_inputs"] = sum(1 for i in inputs if (i.get("type") or "").lower() == "hidden")
    z["form_action_cross"] = sum(1 for f in forms if external(f.get("action") or ""))
    z["form_action_empty"] = sum(1 for f in forms if not (f.get("action") or "").strip() or (f.get("action") or "").strip() in ("#", "javascript:void(0)"))
    z["has_onsubmit"] = int(any(f.get("onsubmit") for f in forms))
    scripts = soup.find_all("script"); z["n_scripts"] = len(scripts)
    z["n_ext_scripts"] = sum(1 for s in scripts if external(s.get("src") or ""))
    z["n_iframes"] = len(soup.find_all("iframe"))
    links = [a.get("href") or "" for a in soup.find_all("a")]; z["n_links"] = len(links)
    z["ext_link_ratio"] = (sum(external(l) for l in links) / len(links)) if links else 0.0
    imgs = [i.get("src") or "" for i in soup.find_all("img")]; z["n_imgs"] = len(imgs)
    z["ext_img_ratio"] = (sum(external(i) for i in imgs) / len(imgs)) if imgs else 0.0
    title = (soup.title.get_text(" ", strip=True) if soup.title else "").lower()
    z["title_len"] = len(title); z["title_brand"] = int(any(b in title for b in BRANDS)); z["title_suspicious"] = int(any(t in title for t in SUSPICIOUS_TOKENS))
    text = soup.get_text(" ", strip=True); z["body_text_len"] = len(text); z["text_html_ratio"] = len(text) / max(1, len(html))
    z["n_obfuscation"] = sum(html.count(o) for o in OBFUSCATION)
    z["has_meta_refresh"] = int(bool(soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})))
    icon = soup.find("link", rel=re.compile("icon", re.I)); z["favicon_external"] = int(bool(icon and external(icon.get("href") or "")))
    z["n_base64"] = len(re.findall(rb"base64,[A-Za-z0-9+/]{200,}", html))
    low = text.lower()[:20000]; z["copyright_brand"] = int(("©" in low or "copyright" in low) and any(b in low for b in BRANDS))
    z["lang_set"] = int(bool(soup.html and soup.html.get("lang")))
    return z


def render_features(rendered, render_json) -> dict:
    """What only a real browser can tell us. Zero/absent for raw-crawl rows (the 'rendered' flag lets
    the model know which regime it is in)."""
    z = {"rendered": int(bool(rendered)), "r_n_password": 0, "r_n_forms": 0, "r_n_inputs": 0, "r_n_iframes": 0,
         "r_n_requests": 0, "r_n_third_party": 0, "r_text_len": 0, "r_title_brand": 0, "r_title_suspicious": 0, "r_console_errors": 0}
    if not rendered or not render_json:
        return z
    try:
        d = json.loads(render_json)
    except Exception:
        return z
    title = (d.get("title") or "").lower(); text = d.get("visible_text") or ""
    z.update(r_n_password=d.get("n_password") or 0, r_n_forms=d.get("n_forms") or 0, r_n_inputs=d.get("n_inputs") or 0,
             r_n_iframes=d.get("n_iframes") or 0, r_n_requests=d.get("n_requests") or 0,
             r_n_third_party=len(d.get("third_party_hosts") or []), r_text_len=len(text),
             r_title_brand=int(any(b in title for b in BRANDS)), r_title_suspicious=int(any(t in title for t in SUSPICIOUS_TOKENS)),
             r_console_errors=sum(1 for c in (d.get("console") or []) if "error" in c.lower()))
    return z


ELIGIBLE_SQL = """
SELECT u.id, u.url, u.label, u.source, u.first_seen, u.registered_domain,
       s.status_code, s.final_url, s.redirect_chain, s.response_headers, s.content_length, s.html_path, s.tls_json, s.landing_kind,
       s.rendered, s.render_json,
       (SELECT tls_json FROM snapshots t WHERE t.url_id=u.id AND t.tls_json IS NOT NULL ORDER BY t.id DESC LIMIT 1) AS any_tls,
       (SELECT response_headers FROM snapshots t WHERE t.url_id=u.id AND t.response_headers IS NOT NULL ORDER BY t.id DESC LIMIT 1) AS any_headers,
       (SELECT redirect_chain FROM snapshots t WHERE t.url_id=u.id AND t.redirect_chain IS NOT NULL ORDER BY t.id DESC LIMIT 1) AS any_chain
FROM urls u JOIN snapshots s ON s.url_id = u.id
WHERE s.id = COALESCE((SELECT max(id) FROM snapshots WHERE url_id = u.id AND rendered = 1),
                      (SELECT max(id) FROM snapshots WHERE url_id = u.id))
  AND ((u.label IN ('phishing','malware') AND s.landing_kind = 'live')
    OR (u.label = 'benign' AND s.landing_kind IN ('live','platform_page')))
  AND s.landing_kind != 'app_shell'
"""

USER_CONTENT = ("sites.google.com","weebly.com","web.app","firebaseapp.com","wixsite.com","wixstudio.com","pages.dev","workers.dev",
                "netlify.app","vercel.app","github.io","glitch.me","webflow.io","godaddysites.com","blogspot.com","square.site",
                "canva.site","000webhostapp.com","notion.site","carrd.co","mystrikingly.com","yolasite.com","jimdosite.com",
                "webnode.page","typeform.com","jotform.com","r2.dev","surge.sh","onrender.com","herokuapp.com","replit.app",
                "ipfs.io","dweb.link","4everland.app","azurestaticapps.net","azurewebsites.net","amazonaws.com","cloudfront.net",
                # JS-app platforms whose RENDERED pages are attacker content (lure pages); raw rows are app_shell anyway
                "express.adobe.com","new.express.adobe.com","dropbox.com","docs.google.com","drive.google.com","script.google.com",
                "sites.google.com","mockplus.com","canva.com","sway.cloud.microsoft","sway.office.com","forms.office.com",
                "forms.cloud.microsoft","1drv.ms","onedrive.live.com","figma.com","framer.app","lookerstudio.google.com","notion.so",
                "flowcode.com","linktr.ee","linkin.bio","linqapp.com","lovable.app","scanned.page","qr-codes.io","beacons.ai","bio.site")


TRANCO_CACHE = DATA_DIR / "tranco_1m.csv"


def known_benign_domains(con=None, top_n: int = 1_000_000) -> dict[str, int]:
    """registered_domain → Tranco rank for the full 1M list (cached on disk, refreshed weekly)."""
    import io, time, zipfile, httpx, tldextract
    if not TRANCO_CACHE.exists() or time.time() - TRANCO_CACHE.stat().st_mtime > 7 * 86400:
        r = httpx.get("https://tranco-list.eu/top-1m.csv.zip", timeout=120, follow_redirects=True)
        r.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            TRANCO_CACHE.write_bytes(z.read(z.namelist()[0]))
    ext = tldextract.TLDExtract(cache_dir=None)
    out: dict[str, int] = {}
    for line in TRANCO_CACHE.read_text().splitlines():
        rank_s, host = line.split(",", 1)
        e = ext(host.strip()); reg = ".".join(p for p in (e.domain, e.suffix) if p) or host
        rank = int(rank_s)
        if rank <= top_n and reg not in out:
            out[reg] = rank
    return out


def is_redirect_to_benign(label: str, final_url: str, benign_domains: dict[str, int]) -> bool:
    """A malicious-labeled entry whose landing page is a known-benign domain is not a phishing page:
    open redirects, taken-down entries bouncing to the real brand, feed noise. Exceptions:
    - user-content platforms (the content is the attacker's);
    - a DEEP path on a domain outside the top 100k: a compromised legit site hosting a kit in a
      subdirectory is a real phishing page. Its root, or any page on a top-100k domain, is not."""
    if label == "benign":
        return False
    try:
        host, reg = split_host(final_url)
        path = urlparse(final_url).path or "/"
    except Exception:
        return False
    # exempt when the landing HOST is on (or under) a user-content entry: x.weebly.com, new.express.adobe.com.
    # The parent domain itself (adobe.com) is NOT exempt.
    if any(host == h or host.endswith("." + h) or reg == h for h in USER_CONTENT):
        return False
    rank = benign_domains.get(reg)
    if rank is None:
        return False
    if rank <= 100_000:
        return True
    return path.strip("/") == ""  # low-rank domain: only the bare root is 'not a phish'



def build(out_path=None, progress=None) -> pd.DataFrame:
    con = connect()
    rows = con.execute(ELIGIBLE_SQL).fetchall()
    benign_domains = known_benign_domains(con)
    out, dropped = [], 0
    for (uid, url, label, source, first_seen, reg, status, final_url, chain, headers, clen, html_path, tls, kind,
         rendered, render_json, any_tls, any_headers, any_chain) in rows:
        fu = final_url or url
        # rendered rows carry no TLS/headers/chain of their own; borrow the raw crawl's
        tls = tls or any_tls; headers = headers or any_headers; chain = chain or any_chain
        if is_redirect_to_benign(label, fu, benign_domains):
            dropped += 1
            if progress: progress()
            continue
        body = (SNAP_DIR / html_path).read_bytes() if html_path and (SNAP_DIR / html_path).exists() else None
        try:
            _, group = split_host(fu)
        except Exception:
            group = reg
        rec = {"url_id": uid, "orig_url": url, "final_url": fu, "label": label, "y": int(label != "benign"),
               "source": source, "first_seen": first_seen, "group": group, "landing_kind": kind}
        rec.update(url_features(fu)); rec.update(tls_features(tls))
        rec.update(response_features(status, chain, headers, url, fu, clen)); rec.update(html_features(body, fu))
        rec.update(render_features(rendered, render_json))
        out.append(rec)
        if progress: progress()
    df = pd.DataFrame(out)
    df.attrs["dropped_redirect_to_benign"] = dropped
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_parquet(out_path, index=False)
    return df
