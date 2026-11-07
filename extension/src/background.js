// Caswell Cancel — background (service worker in Chromium, event page in Firefox).
// Tier 1: deterministic rules (this file wires them). Tier 2: local ML model (risk.js, TODO).
import "../vendor/browser-polyfill.min.js";
import { assessDownload } from "./rules/downloadGate.js";
import { driveByContext, onTabClosed } from "./rules/driveBy.js";
import { assessHostname } from "./rules/homoglyph.js";
import { scoreWithModel, fuse } from "./risk.js";
import { decide, applyDownloadDecision, applyNavigationDecision } from "./policy.js";
import { logEvent, noteNavigation } from "./store.js";

// --- navigation -------------------------------------------------------------------------------
browser.webNavigation.onCommitted.addListener(async (d) => {
  if (d.frameId !== 0) return;
  await noteNavigation(d.tabId, d.url);
  let hostname = "";
  try { hostname = new URL(d.url).hostname; } catch { return; }
  if (!/^https?:/.test(d.url)) return;
  const rules = assessHostname(hostname);
  const model = await scoreWithModel({ url: d.url });
  const score = fuse(rules.score, model);
  const decision = decide(score);
  await applyNavigationDecision(d.tabId, hostname, decision, rules.reasons);
  if (decision !== "allow") await logEvent({ kind: "nav", url: d.url, score, decision, reasons: rules.reasons });
});

// --- downloads --------------------------------------------------------------------------------
// Chrome fires onCreated before the filename is known and onChanged when it is; Firefox usually has
// the filename at onCreated. Evaluate on both and act once.
const judged = new Set();

async function judge(item) {
  if (judged.has(item.id)) return;
  if (!item.filename && !item.mime) return; // nothing to judge yet
  judged.add(item.id);
  const ctx = await driveByContext(item);
  const rules = assessDownload(item, ctx);
  const model = await scoreWithModel({ url: item.finalUrl || item.url, download: true });
  const score = fuse(rules.score, model);
  const decision = decide(score);
  await applyDownloadDecision(item, decision, rules.reasons);
  await logEvent({ kind: "download", url: item.finalUrl || item.url, filename: item.filename, mime: item.mime, score, decision, reasons: rules.reasons, tabId: ctx.tabId });
}

browser.downloads.onCreated.addListener((item) => { judge(item); });
browser.downloads.onChanged.addListener(async (delta) => {
  if (!delta.filename && !delta.mime) return;
  const [item] = await browser.downloads.search({ id: delta.id });
  if (item) judge(item);
});

// --- drive-by: tab closed right after it triggered a download --------------------------------
browser.tabs.onRemoved.addListener(async (tabId) => {
  const sig = await onTabClosed(tabId);
  if (!sig) return;
  await logEvent({ kind: "driveby", downloadId: sig.downloadId, decision: "warn", score: 0.5,
    reasons: [`tab closed ${sig.msAfterDownload}ms after starting download ${sig.downloadId}`] });
  // The file may already be on disk. Surface it; removal is the user's call for now.
  const [item] = await browser.downloads.search({ id: sig.downloadId }).catch(() => []);
  if (item && item.state === "in_progress") await browser.downloads.pause(item.id).catch(() => {});
});

browser.runtime.onInstalled.addListener(() => logEvent({ kind: "lifecycle", decision: "allow", score: 0, reasons: ["installed"] }));
