(async () => {
  const { events = [] } = await browser.storage.local.get("events");
  const list = document.getElementById("list");
  if (!events.length) { list.innerHTML = '<div class="empty">No events yet.</div>'; return; }
  for (const e of events.slice(0, 50)) {
    const div = document.createElement("div"); div.className = "ev";
    const when = new Date(e.t).toLocaleTimeString();
    div.innerHTML = `<div class="top"><span class="tag ${e.decision}">${e.decision}</span><b>${e.kind}</b><span style="color:#888">${when}</span><span style="margin-left:auto">${(e.score ?? 0).toFixed(2)}</span></div>
      <div class="url">${e.filename ? e.filename + " · " : ""}${e.url || ""}</div><div class="why">${(e.reasons || []).join("; ")}</div>`;
    list.appendChild(div);
  }
})();
