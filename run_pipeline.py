"""devops-research: automated DevSecOps intelligence ingestion pipeline.

Run:
    python run_pipeline.py            # full ingest -> digest
    python run_pipeline.py --dry      # do not write files/mark seen
    python run_pipeline.py --json-out data/raw.json
"""

from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

import yaml

from ingest import digest, fetch
from ingest.classify import Classifier
from ingest.dedup import DedupStore

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
CONFIG_PATH = ROOT / "config" / "sources.yml"
STATE_PATH = DATA / "seen.json"


def main():
    ap = argparse.ArgumentParser(description="DevSecOps news ingestion pipeline")
    ap.add_argument("--config", default=str(CONFIG_PATH))
    ap.add_argument("--state", default=str(STATE_PATH))
    ap.add_argument("--dry-run", action="store_true", help="don't write files or mark items seen")
    ap.add_argument("--json-out", default=str(DATA / "raw.json"))
    ap.add_argument("--top", type=int, default=60, help="max digest items")
    args = ap.parse_args()

    conf = yaml.safe_load(Path(args.config).read_text())
    outdir = Path(args.json_out).parent

    clf = Classifier(conf.get("keywords", {}),
                     fresh_window_days=conf.get("fresh_window_days", 3))
    f = fetch.Fetcher(timeout=25)
    store = DedupStore(args.state, retention_days=conf.get("retention_days", 14))

    print(f"[pipeline] ingesting from {len(conf['sources'])} sources")
    fresh: list[dict] = []

    for src in conf["sources"]:
        name = src["name"]
        if delay := src.get("delay", 0):
            import time as _t
            print(f"  (waiting {delay}s for {name})")
            _t.sleep(delay)
        category = src.get("category", "discussion")
        weight = float(src.get("weight", 1.0))
        try:
            if src["type"] == "rss":
                raw = f.fetch_rss(src["url"], source=name, category=category,
                                  weight=weight)
            elif src["type"] == "arxiv":
                raw = f.fetch_arxiv(src["categories"], source=name,
                                    max_r=src.get("max", 40), weight=weight)
            elif src["type"] == "github":
                raw = f.fetch_github_releases(src["repos"], source=name, weight=weight)
            elif src["type"] == "cisa_kev":
                raw = f.fetch_cisa_kev(src["url"], source=name,
                                       category=category, weight=weight)
            else:
                print(f"  [warn] unknown type for {name}: {src['type']}")
                continue
        except Exception as exc:  # noqa: BLE001
            print(f"  [error] {name}: {exc}")
            continue

        print(f"  {name}: {len(raw)} items")
        max_items = src.get("max_items", 0)
        if max_items and len(raw) > max_items:
            raw = raw[:max_items]
            print(f"    (capped to {max_items})")
        for it in raw:
            tags = clf.tags(it)
            score = clf.score(it, source_weight=weight)
            it["tags"] = tags
            it["score"] = score
            min_topics = src.get("min_topics", 0)
            if (min_topics and len(tags) < min_topics):
                continue
            if score >= conf.get("min_score", 0.4) and not store.seen(it["digest"]):
                fresh.append(it)

    fresh.sort(key=lambda x: x["score"], reverse=True)
    top = fresh[: args.top]

    print(f"[2] fresh items: {len(fresh)}; showing top {len(top)}")

    if not args.dry_run:
        json_path = Path(args.json_out)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        import json as _json
        json_path.write_text(
            _json.dumps(digest.render_json(top), indent=2, ensure_ascii=False),
            encoding="utf-8")
        # Markdown
        gen = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        md = digest.render_markdown(top, gen)
        DATA.mkdir(parents=True, exist_ok=True)
        (DATA / "latest.md").write_text(md, encoding="utf-8")
        (DATA / "latest.html").write_text(digest.render_html(top, gen), encoding="utf-8")
        # commit seen state
        for it in top:
            store.mark_seen(it["digest"], it["title"], it["url"])
        store.save()
        print(f"[3] wrote data/latest.md, data/latest.html, {args.json_out}")
    else:
        print("[dry-run] no files written, nothing marked seen")

    print(f"[done] {store.stats()}")


if __name__ == "__main__":
    main()