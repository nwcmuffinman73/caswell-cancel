# Roadmap

Work ahead, roughly in order. Each item is real, scoped, and not started unless marked.

## Rendering stage (in progress)
- [x] Isolated UTM/Ubuntu VM with a Playwright worker; push/pull/merge loop
- [ ] Worker follows a lure page's primary link one hop (Adobe Express / Dropbox "view document" lures)
- [ ] Second render batch at lower concurrency targeting `js_redirect` and `empty` phish
- [ ] Render-time features: request graph, third-party hosts, form posting targets

## Content model (the real detector)
- [ ] Screenshot dataset export from rendered snapshots with brand/target labels
- [ ] Visual similarity model (PhishIntention-style): does the rendered page impersonate a known brand?
- [ ] Small DOM-token encoder as a second opinion; fuse with URL CNN and rule tier
- [ ] Export under 10 MB to ONNX; run in the extension via an offscreen document

## Evaluation
- [ ] Temporal split switches on automatically at 14 days of `first_seen` depth; publish first temporal numbers
- [ ] Hard-negative mining loop: the model's own false positives on harvested benign pages feed back as weighted negatives
- [ ] Thin-benign-page sampler (Common Crawl, size-filtered) to kill the page-richness shortcut
- [ ] Legit-login-page negatives weighted ×2–3 (decision pending)

## Extension
- [ ] Load and test in a real browser (Chrome, Firefox); fix what breaks
- [ ] Allowlist tier for well-established domains so the model never sees them
- [ ] Policy thresholds set from the FP-calibrated curves (targets: ~0.01% nav warnings after tiering, ~1% download pauses)
- [ ] Options page: thresholds, allowlist, per-site overrides
- [ ] Interstitial block page for high-confidence navigation verdicts
- [ ] Firefox packaging; Safari via Xcode converter

## Pipeline hygiene
- [ ] Tests for landing-kind classification, redirect following, feature extraction
- [ ] `cc doctor --wait` and clearer refusal messages
- [ ] Move the daily job to a small VPS so malicious crawling runs unattended without touching a home network
