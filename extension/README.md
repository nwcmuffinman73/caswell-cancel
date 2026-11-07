# Caswell Cancel — extension

Cross-browser WebExtension (Manifest V3). One codebase for Chrome, Edge, Brave, Opera, Firefox;
Safari via Xcode's converter later.

```
manifest.json          MV3; both service_worker (Chromium) and scripts (Firefox) background keys
src/background.js      wires events → rules → risk → policy
src/rules/downloadGate.js   ext/MIME/double-ext/origin/auto-download signals (CaswellCancel 2020, grown up)
src/rules/driveBy.js        referrer-based tab attribution; tab-closed-after-download (CaZentry 2024, fixed)
src/rules/homoglyph.js      brand typosquat / confusable / punycode / brand-as-subdomain
src/risk.js            fuse(rules, model); scoreWithModel() is the ML tier hook (TODO: ONNX)
src/policy.js          score → allow / warn / pause / cancel; thresholds to be set from FP target
src/store.js           storage.local ring buffer + per-tab nav timestamps
popup.html/.js         recent verdicts
vendor/browser-polyfill.min.js  webextension-polyfill 0.12 (promise API everywhere)
```

## Load for development
- Chrome/Edge/Brave: `chrome://extensions` → Developer mode → Load unpacked → this folder.
- Firefox: `about:debugging#/runtime/this-firefox` → Load Temporary Add-on → `manifest.json`.

## Test it
- Download gate: https://www.amtso.org/feature-settings-check-drive-by-download/ and
  https://testsafebrowsing.appspot.com/ (EICAR .com / .zip / .exe test files).
- Homoglyph: visit `paypa1.com`, `rnicrosoft.com`-style hosts (DNS may not resolve; the rule runs
  on navigation commit regardless).

## Status
Skeleton. Rule tier is live and self-contained; the model tier returns null until the corpus-trained
ONNX model exists. Not yet loaded in a real browser — do that before trusting any of it.
