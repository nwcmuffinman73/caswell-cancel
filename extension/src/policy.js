// Policy: risk score → action. Thresholds are placeholders until the corpus-trained model gives us a
// calibrated FP curve; the design rule is that they are set from a target false-positive rate, never
// from accuracy. Users can loosen them in options later.
export const THRESHOLDS = { cancel: 0.8, pause: 0.5, warn: 0.3 };

export function decide(score) {
  if (score >= THRESHOLDS.cancel) return "cancel";
  if (score >= THRESHOLDS.pause) return "pause";
  if (score >= THRESHOLDS.warn) return "warn";
  return "allow";
}

export async function applyDownloadDecision(item, decision, reasons) {
  const name = (item.filename || item.finalUrl || "").split(/[\\/]/).pop();
  if (decision === "cancel") {
    await browser.downloads.cancel(item.id).catch(() => {});
    await notify("Download blocked", `${name}\n${reasons.join("; ")}`);
  } else if (decision === "pause") {
    await browser.downloads.pause(item.id).catch(() => {});
    await notify("Download paused for review", `${name}\n${reasons.join("; ")}\nResume it from the downloads shelf if you trust it.`);
  } else if (decision === "warn") {
    await notify("Download looks unusual", `${name}\n${reasons.join("; ")}`);
  }
}

export async function applyNavigationDecision(tabId, hostname, decision, reasons) {
  if (decision === "allow") { await browser.action.setBadgeText({ tabId, text: "" }).catch(() => {}); return; }
  const color = decision === "cancel" ? "#b00020" : decision === "pause" ? "#e65100" : "#f9a825";
  await browser.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {});
  await browser.action.setBadgeText({ tabId, text: "!" }).catch(() => {});
  if (decision !== "warn") await notify("Suspicious site", `${hostname}\n${reasons.join("; ")}`);
  // TODO: interstitial block page for 'cancel' once the model tier exists; rules alone are not
  // confident enough to hard-block navigation.
}

async function notify(title, message) {
  try {
    await browser.notifications.create({ type: "basic", iconUrl: browser.runtime.getURL("icons/icon128.png"), title, message });
  } catch { /* notifications may be unavailable */ }
}
