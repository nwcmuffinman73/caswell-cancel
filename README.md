# Caswell Cancel

A browser risk sensor and preventer. Deep-learning site-risk model, trained on a large labeled
corpus, shipped inside a cross-browser (WebExtensions / MV3) extension with a deterministic rule
tier in front of it.

Lineage: [CaswellCancel](https://github.com/NicholasCaswell/CaswellCancel) (2020, download gate)
is the foundation; [CaZentry](https://github.com/NicholasCaswell/CaZentry) (2024, master's
project) is the inspiration. Both are cloned under `legacy/` for reference.

## Repository map

```
src/corpus/      the data and model pipeline (Python, run via `uv run cc <command>`)
  feeds.py         where labeled URLs come from: Tranco (benign), OpenPhish/PhishTank (phishing),
                   URLhaus (malware), Common Crawl + Wayback samplers (benign pages on the same
                   platforms that host phish), a spider for deep/login pages on known-benign sites
  crawl.py         fetches each URL once: HTML, redirect chain, headers, TLS cert; follows client-side
                   redirects; classifies what actually landed (live / takedown / auth wall / app shell …);
                   refuses to crawl malicious labels when an ISP security product is rewriting them
  db.py            the SQLite corpus: urls + snapshots, timestamped so splits can be temporal
  features.py      turns a snapshot into ~85 numbers a browser extension could also compute
  train.py         the evaluation harness: recall at fixed false-positive rates, group/temporal splits,
                   calibrated thresholds; gradient-boosted baseline
  urlmodel.py      the URL character CNN (first deep-learning tier), ONNX export, fixed probe set
  urlharvest.py    benign URL strings with realistic paths (page links, sitemaps, GitHub API)
  render.py        Mac side of the rendering stage: build worklist → VM → merge results back
  cli.py           the `cc` command surface
vm/              the isolated render VM (UTM): guest setup, the Playwright worker, containment rules
extension/       the browser extension (Manifest V3, Chrome/Edge/Brave/Firefox from one codebase):
                   rule tier (download gate, drive-by, homoglyph), risk fusion, policy, popup
scripts/         daily.sh, run by launchd at 06:30: ingest every feed, crawl benign, triage
data/            NOT in git. corpus.sqlite, content-addressed snapshots (~11 GB), renders, models
legacy/          NOT in git. clones of CaswellCancel (2020) and CaZentry (2024) for reference
```

## Build order

1. **Corpus pipeline** (this stage) — ingest labeled feeds, snapshot pages daily, timestamp everything.
2. **Model** — sequence encoder (URL chars, HTML tokens) + gradient-boosted tabular features →
   one calibrated risk score. Temporal splits only. Threshold chosen for target FP rate, not accuracy.
3. **Extension** — thin MV3 shell: rule tier → local ONNX model → policy (warn / pause / cancel).

## Corpus pipeline

```sh
uv sync
uv run cc ingest tranco --limit 50000   # benign
uv run cc ingest openphish              # phishing
uv run cc ingest urlhaus                # malware   (may need URLHAUS_AUTH_KEY)
uv run cc ingest phishtank              # phishing  (keyless CSV; rate-limited per IP)
uv run cc crawl --label phishing --limit 500
uv run cc crawl --label benign --limit 500
uv run cc stats
```

Data lives in `data/` (gitignored): `corpus.sqlite` plus content-addressed snapshots.

### Why it's shaped this way

- **Timestamps on everything.** Phishing infrastructure rotates in hours. A random train/test split
  leaks hosting-provider fingerprints and reports fake 99% accuracy. We split by `first_seen`.
- **Per-source labels, never merged.** Feed disagreements stay visible.
- **Crawl newest-first.** Fresh phish get snapshotted before they die; dead pages are also kept,
  since decay rate is a feature.
- **Binaries are never stored.** URLhaus URLs are live malware payloads. Non-text responses are
  reduced to sha256 + first 16 magic bytes + Content-Disposition; only text-like bodies hit disk.
  The magic/declared-type/filename triple is exactly what the extension's download gate will judge.
- **Network interception guard.** `cc doctor` probes recent malicious URLs; `cc crawl` refuses
  malicious labels if an ISP/security product rewrites them (Spectrum Security Shield does, inline).
  Intercepted snapshots are flagged and auto-requeued.
- **Record bad TLS, don't refuse it.** The crawler disables verification deliberately so a
  self-signed or mismatched cert becomes data.

### Label hygiene (the false-positive firewall)

A feed label plus a 200 status is not a training example. `cc triage` assigns every snapshot a
`landing_kind`; only `live` rows are positives. First PhishTank+OpenPhish crawl (2026-10-11, 1,800 URLs, latest snapshot per URL):

| landing_kind | what it is | phishing rows |
|---|---|---|
| live | page content actually captured (TRAINING POSITIVE) | 804 |
| http_error | connection failed / 403 / 5xx | 379 |
| takedown | 404/410/451, parking, 'page not found', platform placeholder | 191 |
| auth_wall | redirected to accounts.google.com / MS login etc. | 172 |
| js_redirect | redirect target computed by script (Firebase lookup etc.); needs a JS engine | 144 |
| client_redirect | meta-refresh / literal JS redirect, followed up to 2 hops; leftover = loops | 35 |
| empty | body < 200 bytes | 28 |
| platform_page | redirect landed on a DIFFERENT major legit site's own page (google.com, facebook.com) | 27 |
| binary | non-text body; hash+magic kept, bytes discarded | 19 |
| error_page | PHP/server error output | 1 |

Without this step the model learns "Google sign-in page = phishing". For the **benign** label,
`live` and `platform_page` are both valid negatives (a Tranco site redirecting to another big site).

**Where phish actually live (PhishTank, 67k URLs):** 46% attacker-controlled domains, 33% legit
hosting platforms (Google Slides/Sites, Weebly, Firebase, Wix, Cloudflare Pages), 21% URL
shorteners (qrco.de, q-r.to, bit.ly). Consequences for the model:
- Domain reputation alone would flag every Weebly/Firebase site. The model must learn from page
  content and URL *path/structure*, and we need **hard negatives**: benign pages on the same
  platforms. (TODO: benign-platform sampler.)
- Shortener URLs carry no signal; the crawler follows them and we train on the landing page.
- ~4,000 PhishTank entries are published Google Slides used as redirectors. Followed via
  client-redirect hop; the Slides URL itself is a redirector, not a phish.

### Timestamps
Stored as ISO-8601 UTC with `T` and `Z`. When comparing against now in SQL use
`strftime('%Y-%m-%dT%H:%M:%SZ','now', '-N days')`, not `datetime('now')` (format mismatch
makes the comparison always true).

### Model stage (started 2026-10-12)
```sh
uv run cc features   # → data/features/features.parquet (85 cols, latest live snapshot per URL)
uv run cc train      # → data/models/baseline_hgb.pkl + baseline_report.md
```
The harness reports recall at fixed FPR (0.1% / 1% / 5%) and picks thresholds from an FP target.
Split is GroupKFold by final registered domain until first_seen spans ≥14 days, then temporal.
Current (13,477 rows; 8.8k benign, 4.4k live phish, 242 malware pages): recall 28% @ 0.1% FPR,
58% @ 1%, 76% @ 5% (group split). Landing classifier now also tags `app_shell` (JS platform shells:
Adobe Express, Dropbox, Slides, Apps Script) and link-service interstitials; neither is a training row.
~45k PhishTank URLs still uncrawled. Progression + interpretation in data/models/baseline_report.md.
URL char-CNN: `cc url-harvest --sitemaps N` then `cc url-train` → data/models/url_cnn.onnx (179 KB);
probe set data/url_corpus/probes.tsv prints every run. See data/models/url_cnn_report.md.

**Negatives now:** `cc spider` (deep + legit login pages from stored homepages), Tranco long tail
(`--tail-sample`), cc_platform (Common Crawl, flaky). All run in `cc daily`.
**Still missing:** thin benign pages (<30 KB) at volume; Common Crawl size-filtered sample when up.

### Not yet

- Headless-browser renders (post-JS DOM, screenshots) for the visual-similarity model.
- Scheduled daily ingest + crawl.
- Feature extraction and the training set exporter.
