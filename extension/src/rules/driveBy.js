// Drive-by download signals. CaZentry (2024) tried this by grabbing whichever tab was active when a
// download appeared and warning if that tab closed within 30s. The active-tab guess was racy; here we
// attribute a download to a tab by its referrer URL, and we record the navigation time so the
// download gate can see "download began N ms after the page committed".
import { lastNavigation, noteDownloadForTab, takeDownloadForTab } from "../store.js";

export async function tabForDownload(item) {
  if (!item.referrer) return null;
  try {
    const tabs = await browser.tabs.query({});
    const ref = new URL(item.referrer);
    const hit = tabs.find((t) => { try { const u = new URL(t.url); return u.origin === ref.origin && u.pathname === ref.pathname; } catch { return false; } })
      || tabs.find((t) => { try { return new URL(t.url).origin === ref.origin; } catch { return false; } });
    return hit ? hit.id : null;
  } catch { return null; }
}

export async function driveByContext(item) {
  const tabId = await tabForDownload(item);
  if (tabId == null) return { tabId: null, msSinceNavigation: null };
  const nav = await lastNavigation(tabId);
  await noteDownloadForTab(tabId, item.id);
  return { tabId, msSinceNavigation: nav ? Date.now() - nav.t : null };
}

/** Called from tabs.onRemoved. Returns a signal if the tab closed shortly after triggering a download. */
export async function onTabClosed(tabId) {
  const rec = await takeDownloadForTab(tabId);
  if (!rec) return null;
  const dt = Date.now() - rec.t;
  return dt < 30_000 ? { downloadId: rec.downloadId, msAfterDownload: dt } : null;
}
