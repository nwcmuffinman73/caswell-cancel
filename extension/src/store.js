// Ring buffer of verdict events in storage.local, read by the popup. Also per-tab navigation
// timestamps used by the drive-by rule. Service workers are ephemeral; nothing lives in memory
// across wakeups unless it is here.
const MAX_EVENTS = 200;

export async function logEvent(ev) {
  const { events = [] } = await browser.storage.local.get("events");
  events.unshift({ t: Date.now(), ...ev });
  await browser.storage.local.set({ events: events.slice(0, MAX_EVENTS) });
}

export async function noteNavigation(tabId, url) {
  const { navs = {} } = await browser.storage.local.get("navs");
  navs[tabId] = { url, t: Date.now() };
  await browser.storage.local.set({ navs });
}

export async function lastNavigation(tabId) {
  const { navs = {} } = await browser.storage.local.get("navs");
  return navs[tabId];
}

export async function noteDownloadForTab(tabId, downloadId) {
  const { tabDownloads = {} } = await browser.storage.local.get("tabDownloads");
  tabDownloads[tabId] = { downloadId, t: Date.now() };
  await browser.storage.local.set({ tabDownloads });
}

export async function takeDownloadForTab(tabId) {
  const { tabDownloads = {} } = await browser.storage.local.get("tabDownloads");
  const rec = tabDownloads[tabId];
  delete tabDownloads[tabId];
  await browser.storage.local.set({ tabDownloads });
  return rec;
}
