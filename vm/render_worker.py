#!/usr/bin/env python3
"""Render worker. Runs INSIDE the VM. Reads in/worklist.json [{id, url}], renders each URL in headless
Chromium, writes out/<id>.json (final url, title, rendered DOM, console/network summary, password
fields) and out/<id>.png (viewport screenshot). No corpus code here on purpose: this box holds
nothing but a browser and this file.
"""
import asyncio, json, sys, time, re
from pathlib import Path
from playwright.async_api import async_playwright

IN = Path.home() / "render/in/worklist.json"
OUT = Path.home() / "render/out"
CONCURRENCY = 10
NAV_TIMEOUT_MS = 20000
SETTLE_MS = 2500
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"


async def render_one(ctx, item, sem):
    async with sem:
        rid, url = item["id"], item["url"]
        rec = {"id": rid, "url": url, "ok": False, "t": time.time()}
        page = await ctx.new_page()
        reqs, console = [], []
        page.on("request", lambda r: reqs.append({"u": r.url[:300], "m": r.method, "type": r.resource_type}))
        page.on("console", lambda m: console.append(m.text[:200]) if len(console) < 50 else None)
        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
            try:
                await page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass
            await page.wait_for_timeout(SETTLE_MS)
            html = await page.content()
            rec.update(
                ok=True, status=resp.status if resp else None, final_url=page.url, title=(await page.title())[:300],
                html=html[:2_000_000], html_len=len(html),
                n_password=await page.locator("input[type=password]").count(),
                n_forms=await page.locator("form").count(),
                n_inputs=await page.locator("input").count(),
                n_iframes=await page.locator("iframe").count(),
                visible_text=(await page.evaluate("document.body ? document.body.innerText.slice(0, 20000) : ''")),
                requests=reqs[:200], n_requests=len(reqs), console=console,
                third_party_hosts=sorted({re.sub(r'^https?://([^/]+).*', r'\1', r["u"]) for r in reqs})[:100],
            )
            await page.screenshot(path=str(OUT / f"{rid}.png"), full_page=False)
        except Exception as e:
            rec["error"] = f"{type(e).__name__}: {str(e)[:200]}"
            try:
                rec["final_url"] = page.url
            except Exception:
                pass
        finally:
            await page.close()
        (OUT / f"{rid}.json").write_text(json.dumps(rec))
        return rec["ok"]


async def main():
    items = json.loads(IN.read_text())
    done = {int(p.stem) for p in OUT.glob("*.json")}
    items = [i for i in items if i["id"] not in done]
    print(f"rendering {len(items)} (skipping {len(done)} done)", flush=True)
    async with async_playwright() as p:
        # Playwright's bundled Chromium segfaults on this guest kernel (Ubuntu 26.10 / 7.3); the distro snap works.
        import os
        exe = os.environ.get("CC_CHROME", "/snap/bin/chromium") if Path("/snap/bin/chromium").exists() else None
        browser = await p.chromium.launch(headless=True, executable_path=exe,
                                          args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage", "--disable-dbus"])
        ctx = await browser.new_context(user_agent=UA, viewport={"width": 1280, "height": 800}, ignore_https_errors=True,
                                        java_script_enabled=True, accept_downloads=False, locale="en-US")
        await ctx.route(re.compile(r".*\.(mp4|webm|mp3|avi|mov|zip|exe|dmg|msi|iso)(\?.*)?$"), lambda r: r.abort())
        sem = asyncio.Semaphore(CONCURRENCY)
        results = await asyncio.gather(*(render_one(ctx, i, sem) for i in items))
        await browser.close()
    print(f"ok {sum(results)} / {len(results)}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
