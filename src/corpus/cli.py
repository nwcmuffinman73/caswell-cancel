"""`cc` command line.

  cc ingest tranco --limit 50000
  cc ingest openphish
  cc ingest urlhaus
  cc crawl --label phishing --limit 500
  cc stats
"""
from __future__ import annotations

import typer
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

from . import crawl as crawl_mod
from . import feeds
from .db import connect

app = typer.Typer(no_args_is_help=True, add_completion=False)
console = Console()


@app.command()
def ingest(source: str = typer.Argument(..., help="|".join(feeds.FEEDS)), limit: int = typer.Option(100_000, help="tranco only"),
           tail_sample: int = typer.Option(0, help="tranco only: also sample N hosts from ranks 100k–1M (thin small-site negatives)")):
    """Pull a feed and upsert its URLs with labels."""
    if source not in feeds.FEEDS:
        raise typer.BadParameter(f"unknown source {source!r}; choose from {', '.join(feeds.FEEDS)}")
    con = connect()
    fn = feeds.FEEDS[source]
    if source == "tranco":
        rows = fn(limit=limit, tail_sample=tail_sample)
    elif source in ("cc_platform", "wb_platform"):
        rows = fn(limit=min(limit, 500), con=con)
    else:
        rows = fn()
    with console.status(f"ingesting {source}…"):
        fetched, inserted, updated = feeds.upsert(con, source, rows)
    console.print(f"[bold]{source}[/]: fetched {fetched:,}  new {inserted:,}  seen-again {updated:,}")


@app.command()
def spider(per_site: int = typer.Option(3), login_per_site: int = typer.Option(2), max_sites: int = typer.Option(2000)):
    """Benign deep pages + legit login pages, spidered from stored benign homepages (no external index needed)."""
    con = connect()
    with console.status("spidering stored homepages…"):
        rows = list(feeds.benign_spider(con, per_site, login_per_site, max_sites))
    by_src = {}
    for src in ("tranco_login", "tranco_deep"):
        sub = [(u, l, r) for u, l, r, s_ in rows if s_ == src]
        f, i, up = feeds.upsert(con, src, sub)
        by_src[src] = i
    console.print(f"spider: new {by_src}")


@app.command()
def crawl(
    label: str = typer.Option(None, help="benign|phishing|malware; default all"),
    limit: int = typer.Option(200),
    workers: int = typer.Option(16),
    recrawl_days: int = typer.Option(None, help="re-snapshot URLs whose last snapshot is older than N days"),
    allow_intercepted: bool = typer.Option(False, help="crawl even if the network rewrites malicious URLs"),
):
    """Snapshot pending URLs: HTML, redirect chain, headers, TLS leaf cert."""
    con = connect()
    if label in (None, "phishing", "malware") and not allow_intercepted:
        d = crawl_mod.doctor(con)
        if d["intercepted"]:
            console.print(f"[red bold]network interception detected[/] ({d['hits']}/{d['probed']} probes → {d['interceptor']}). "
                          "Malicious-label crawl refused to protect the corpus. Fix the network path or pass --allow-intercepted.")
            raise typer.Exit(2)
    n = len(crawl_mod.pending(con, label, limit, recrawl_days))
    with Progress(console=console) as prog:
        task = prog.add_task("crawling", total=n)
        stats = crawl_mod.run(con, label, limit, workers, recrawl_days, progress=lambda: prog.advance(task))
    console.print(stats)


@app.command()
def daily(benign_limit: int = typer.Option(300), platform_limit: int = typer.Option(40)):
    """Unattended daily run: ingest every feed (each independently), crawl benign only, triage.
    Never crawls malicious labels — that needs a clean network path and is a session activity."""
    import traceback
    from datetime import datetime
    con = connect()
    console.print(f"[bold]daily[/] {datetime.now():%Y-%m-%d %H:%M}")
    for source in ("tranco", "openphish", "urlhaus", "phishtank", "cc_platform", "wb_platform"):
        try:
            fn = feeds.FEEDS[source]
            if source == "tranco":
                rows = fn(limit=50_000, tail_sample=300)
            elif source in ("cc_platform", "wb_platform"):
                rows = fn(limit=platform_limit, con=con)
            else:
                rows = fn()
            fetched, inserted, updated = feeds.upsert(con, source, rows)
            console.print(f"  {source:<11} fetched {fetched:>7,}  new {inserted:>6,}")
        except Exception as e:
            console.print(f"  {source:<11} [red]FAILED[/] {type(e).__name__}: {str(e)[:120]}")
    try:
        rows = list(feeds.benign_spider(con, 2, 1, 400))
        for src in ("tranco_login", "tranco_deep"):
            feeds.upsert(con, src, [(u, l, r) for u, l, r, s_ in rows if s_ == src])
        console.print(f"  spider      {len(rows):>7,} candidate deep/login pages")
    except Exception as e:
        console.print(f"  spider      [red]FAILED[/] {type(e).__name__}: {str(e)[:120]}")
    st = crawl_mod.run(con, "benign", benign_limit, 24, None)
    console.print(f"  crawl benign {st}")
    console.print(f"  triage {crawl_mod.triage(con)}")


@app.command()
def doctor():
    """Check whether this network path intercepts malicious URLs (ISP security products etc.)."""
    con = connect()
    with console.status("probing…"):
        d = crawl_mod.doctor(con)
    if d["intercepted"]:
        console.print(f"[red bold]INTERCEPTED[/]: {d['hits']}/{d['probed']} probes rewritten to {d['interceptor']}")
        console.print("Snapshots of malicious URLs from this network are block pages, not targets. Crawl from a clean path.")
    else:
        console.print(f"[green bold]clean[/]: {d['hits']}/{d['probed']} probes rewritten")


@app.command()
def triage(
    recrawl: str = typer.Option(None, help="after classifying, re-fetch URLs whose latest landing_kind is this (e.g. client_redirect)"),
    limit: int = typer.Option(2000),
    workers: int = typer.Option(32),
):
    """Classify what each snapshot actually captured (live / auth_wall / takedown / client_redirect / …)."""
    con = connect()
    with console.status("classifying…"):
        counts = crawl_mod.triage(con)
    console.print("classified:", dict(sorted(counts.items(), key=lambda kv: -kv[1])))
    if recrawl:
        with Progress(console=console) as prog:
            task = prog.add_task(f"re-fetching {recrawl}", total=None)
            st = crawl_mod.recrawl_kind(con, recrawl, limit, workers, progress=lambda: prog.advance(task))
        console.print(st)


@app.command()
def features(out: str = typer.Option("data/features/features.parquet")):
    """Export one feature row per eligible URL (latest live snapshot) to parquet."""
    from pathlib import Path
    from . import features as feat
    con = connect()
    n = con.execute(f"SELECT count(*) FROM ({feat.ELIGIBLE_SQL})").fetchone()[0]
    with Progress(console=console) as prog:
        task = prog.add_task("extracting", total=n)
        df = feat.build(Path(out), progress=lambda: prog.advance(task))
    console.print(f"wrote {len(df):,} rows × {df.shape[1]} cols → {out}")
    console.print(df["label"].value_counts().to_dict())


@app.command()
def train(features_path: str = typer.Option("data/features/features.parquet"), report: str = typer.Option("data/models/baseline_report.md")):
    """Train the gradient-boosted baseline and write the FP-targeted evaluation report."""
    from pathlib import Path
    from . import train as tr
    with console.status("training…"):
        res = tr.run(Path(features_path), Path(report))
    console.print(f"[bold]{res['mode']}[/] split · ROC AUC {res['roc_auc']:.4f} · PR AUC {res['pr_auc']:.4f}")
    for k, v in res["operating_points"].items():
        console.print(f"  recall @ FPR {k.replace('fpr_','')}: {v['recall']:.3f}  (thr {v['threshold']:.3f})")
    console.print(f"report → {report}")


@app.command(name="url-harvest")
def url_harvest(max_per_page: int = typer.Option(60), cap: int = typer.Option(300_000),
                sitemaps: int = typer.Option(0, help="also read sitemaps of the top-N Tranco sites (deep benign paths)")):
    """Harvest benign URL strings with paths (stored HTML links; optionally top-site sitemaps). Read-only; feeds the URL model."""
    from . import urlharvest
    with console.status("harvesting links from stored pages…"):
        df = urlharvest.harvest(max_per_page, cap)
    console.print(f"links: {len(df):,} benign URLs from {df.src_domain.nunique():,} pages' domains → {urlharvest.OUT}")
    if sitemaps:
        with console.status(f"reading sitemaps of top {sitemaps} sites…"):
            sm = urlharvest.harvest_sitemaps(top_n=sitemaps)
        console.print(f"sitemaps: {len(sm):,} benign URLs from {sm.src_domain.nunique():,} domains → {urlharvest.SITEMAP_OUT}")


@app.command(name="url-train")
def url_train(epochs: int = typer.Option(6), limit_per_class: int = typer.Option(None), export: bool = typer.Option(True),
              report: str = typer.Option("data/models/url_cnn_report.md")):
    """Train/evaluate the URL character CNN (group-split OOF), then fit on everything and export ONNX."""
    import time
    from pathlib import Path
    from . import urlmodel as um
    con = connect()
    rows = um.load_rows(con, limit_per_class)
    console.print(f"rows {len(rows):,}  pos {sum(r[1] for r in rows):,}")
    t0 = time.time()
    with console.status("cross-validating…"):
        res = um.train_eval(rows, epochs=epochs)
    console.print(f"[bold]URL CNN[/] ({res['device']}, {epochs} ep, {time.time()-t0:.0f}s) ROC AUC {res['roc_auc']:.4f} · PR AUC {res['pr_auc']:.4f}")
    for k, v in res["operating_points"].items():
        console.print(f"  recall @ FPR {k.replace('fpr_','')}: {v['recall']:.3f}  (thr {v['threshold']:.3f})")
    if export:
        with console.status("fitting on all rows + exporting ONNX…"):
            out = um.fit_full_and_export(rows, epochs=epochs)
        probs = um.verify_onnx(out, ["https://paypal.com/", "https://paypa1-secure-login.weebly.com/verify", "https://github.com/torvalds/linux",
                                     "http://192.168.1.1/admin", "https://docs.google.com/presentation/d/e/2PACX-abc/pub"])
        console.print(f"onnx → {out} ({out.stat().st_size/1024:.0f} KB)")
        probes_path = Path("data/url_corpus/probes.tsv")
        if probes_path.exists():
            table = um.run_probes(out, probes_path, res["operating_points"]["fpr_0.01"]["threshold"])
            console.print(table.splitlines()[0])
            res["probes_md"] = table
    Path(report).parent.mkdir(parents=True, exist_ok=True)
    ops = "\n".join(f"| {k.replace('fpr_','')} | {v['recall']:.3f} | {v['threshold']:.3f} |" for k, v in res["operating_points"].items())
    Path(report).write_text(f"# URL char-CNN report\n\nrows {res['n']:,} (pos {res['n_pos']:,}) · {epochs} epochs · group 5-fold OOF\n\n"
                            f"ROC AUC **{res['roc_auc']:.4f}** · PR AUC **{res['pr_auc']:.4f}**\n\n| target FPR | recall | threshold |\n|---|---|---|\n{ops}\n\n"
                            "Benign URLs: Tranco hosts + harvested page links + top-site sitemaps. Malicious opaque-ID platform URLs (Slides/Drive/OneDrive) excluded.\n\n"
                            + res.get("probes_md", ""))


@app.command()
def errors(n: int = typer.Option(25), fpr: float = typer.Option(0.01)):
    """Worst benign false positives and most-missed phish from the baseline's out-of-fold predictions."""
    import pandas as pd
    from .train import MODELS_DIR, recall_at_fpr
    df = pd.read_parquet(MODELS_DIR / "baseline_oof.parquet")
    _, thr = recall_at_fpr(df.y.to_numpy(), df.p_cal.to_numpy(), fpr)
    ben = df[df.y == 0].sort_values("p_cal", ascending=False).head(n)
    console.print(f"[bold]benign scored highest[/] (threshold @ {fpr:.1%} FPR = {thr:.3f})")
    for r in ben.itertuples():
        console.print(f"  {r.p_cal:.3f} {'FP' if r.p_cal >= thr else '  '} {r.source:<13} {r.final_url[:95]}")
    ph = df[df.y == 1].sort_values("p_cal").head(n)
    console.print(f"[bold]phish scored lowest[/]")
    for r in ph.itertuples():
        console.print(f"  {r.p_cal:.3f} {r.source:<10} {r.final_url[:100]}")
    bysrc = df.groupby("source").apply(lambda d: pd.Series({"n": len(d), "mean_p": d.p_cal.mean(), "frac_over_thr": (d.p_cal >= thr).mean()})).round(3)
    console.print(bysrc.to_string())


@app.command(name="render-push")
def render_push(limit: int = typer.Option(1000)):
    """Build a render worklist (JS-shell / redirect / empty phish + matched benign), ship it to the VM, start the worker."""
    from . import render
    n = render.push(limit)
    console.print(f"pushed {n:,} URLs to {render.vm_target()}; worker started. Later: cc render-pull")


@app.command(name="render-pull")
def render_pull():
    """Pull rendered results from the VM and merge them as rendered=1 snapshots."""
    from . import render
    console.print(render.pull())


@app.command()
def stats():
    """Corpus counts by label and snapshot coverage."""
    con = connect()
    t = Table(title="corpus")
    for c in ("label", "urls", "snapshotted", "usable", "intercepted", "sources"):
        t.add_column(c, justify="right" if c != "label" else "left")
    for label, urls, snapped, ok, inter, sources in con.execute(
        """SELECT u.label, COUNT(DISTINCT u.id),
                  COUNT(DISTINCT s.url_id),
                  COUNT(DISTINCT CASE WHEN s.ok=1 AND s.intercepted=0 THEN s.url_id END),
                  COUNT(DISTINCT CASE WHEN s.intercepted=1 THEN s.url_id END),
                  GROUP_CONCAT(DISTINCT u.source)
           FROM urls u LEFT JOIN snapshots s ON s.url_id=u.id GROUP BY u.label"""
    ):
        t.add_row(label, f"{urls:,}", f"{snapped:,}", f"{ok:,}", f"{inter:,}", sources or "")
    console.print(t)
    t3 = Table(title="latest snapshot per URL: landing_kind × label  (only 'live' rows are training positives)")
    kinds = [r[0] for r in con.execute("SELECT DISTINCT landing_kind FROM snapshots WHERE landing_kind IS NOT NULL ORDER BY 1")]
    t3.add_column("label")
    for k in kinds:
        t3.add_column(k, justify="right")
    for (label,) in con.execute("SELECT DISTINCT label FROM urls ORDER BY 1"):
        row = con.execute(
            """SELECT s.landing_kind, count(*) FROM snapshots s JOIN urls u ON u.id=s.url_id
               WHERE u.label=? AND s.id=(SELECT max(id) FROM snapshots WHERE url_id=u.id) GROUP BY 1""", (label,)
        ).fetchall()
        d = dict(row)
        t3.add_row(label, *[f"{d.get(k, 0):,}" for k in kinds])
    if kinds:
        console.print(t3)
    runs = con.execute("SELECT source, ran_at, fetched, inserted FROM ingest_runs ORDER BY ran_at DESC LIMIT 8").fetchall()
    if runs:
        t2 = Table(title="recent ingests")
        for c in ("source", "ran_at", "fetched", "new"):
            t2.add_column(c)
        for r in runs:
            t2.add_row(r[0], r[1], f"{r[2]:,}", f"{r[3]:,}")
        console.print(t2)


if __name__ == "__main__":
    app()
