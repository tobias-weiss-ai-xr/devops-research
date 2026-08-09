#!/usr/bin/env python3
"""Generate statistics.json and papers.json from papers.yaml (DevSecOps house).

Simple taxonomy analytics: per-category / subcategory / year counts, cell
saturation, emerging 12-month themes, top venues and top authors.

Usage:
    python3 scripts/analysis/generate_analysis.py
"""

import json
import os
import re
import yaml
from collections import Counter
from datetime import datetime

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CATEGORY_DISPLAY = {
    "security": "Security & DevSecOps",
    "cicd": "CI/CD Pipelines",
    "iac": "Infrastructure as Code",
    "containers": "Containers & Kubernetes",
    "policycode": "Policy as Code & Access Control",
    "observability": "Observability & Telemetry",
    "gitops": "GitOps & Progressive Delivery",
    "platform": "Platform Engineering",
    "ai-security": "AI / LLM Security",
}

CATEGORY_ORDER = list(CATEGORY_DISPLAY.keys())

SUBCATEGORY_ORDER = [
    "theory", "mechanism", "method", "application",
    "development", "systems", "evaluation", "review", "security",
]

# Keyword bursts: generic software-engineering terms with strong DevSecOps
# resonance, tracked for emerging-theme detection in the last 12 months.
BURST_KEYWORDS = [
    "supply chain", "sbom", "slsa", "devsecops", "zero trust",
    "policy as code", "gitops", "platform engineering", "internal developer platform",
    "prompt injection", "llm", "ai agent", "agentic", "mcp",
    "infrastructure as code", "terraform", "kubernetes", "observability",
    "telemetry", "opentelemetry", "fuzzing", "sbom", "secrets",
    "continuous delivery", "continuous integration", "github actions",
    "canary", "progressive delivery", "runtime security", "threat modeling",
    "idp", "backstage", "serverless", "cloud native", "cve",
]

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def main():
    yaml_path = os.path.join(BASE, "papers.yaml")
    if not os.path.exists(yaml_path):
        print("ERROR: papers.yaml not found — run scripts/fetch/fetch_new_papers.py first")
        return 1
    with open(yaml_path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    entries = data.get("papers", [])

    total = len(entries)
    cat_counter = Counter(e.get("category", "?") for e in entries)
    subcat_counter = Counter(e.get("subcategory", "?") for e in entries)
    year_counter = Counter()
    for e in entries:
        d = str(e.get("date", ""))
        year_counter[d[:4] if len(d) >= 4 else "unknown"] += 1

    now = datetime.now()
    cur_lo = (now.year, now.month)
    # start of the rolling 12-month window: one year back from the current month
    lo_y, lo_m = cur_lo[0] - 1, cur_lo[1]

    cell_counter = Counter((e.get("category", "?"), e.get("subcategory", "?")) for e in entries)
    total_cells = len(CATEGORY_ORDER) * len(SUBCATEGORY_ORDER)
    filled_cells = len(cell_counter)
    saturation = round(100 * filled_cells / total_cells, 1) if total_cells else 0

    # recent (last 12 months) per category + burst keywords
    recent = []
    for e in entries:
        d = str(e.get("date", ""))
        if len(d) >= 7:
            try:
                y, m = int(d[:4]), int(d[5:7])
            except ValueError:
                continue
            if (y, m) >= (lo_y, lo_m) and (y, m) <= cur_lo:
                recent.append(e)
    recent_cat = Counter(e.get("category", "?") for e in recent)

    text_pool = " ".join(
        f"{e.get('title', '')} {e.get('abstract', '')}".lower() for e in recent
    )
    corpus_pool = " ".join(
        f"{e.get('title', '')} {e.get('abstract', '')}".lower() for e in entries
    )
    bursts = []
    for kw in BURST_KEYWORDS:
        r = text_pool.count(kw)
        if r:
            bursts.append({"keyword": kw, "recent": r,
                           "corpus": corpus_pool.count(kw)})
    bursts.sort(key=lambda b: (-b["recent"], -b["corpus"]))

    # top venues + authors
    venue_counter = Counter()
    author_counter = Counter()
    for e in entries:
        v = e.get("venue", "")
        if v and "arxiv" not in v.lower():
            venue_counter[v] += 1
        for a in e.get("authors", []):
            author_counter[a] += 1

    stats = {
        "metadata": {
            "total_papers": total,
            "generated": now.strftime("%Y-%m-%d"),
            "taxonomy": {
                "categories": len(CATEGORY_ORDER),
                "subcategories": len(SUBCATEGORY_ORDER),
                "total_cells": total_cells,
                "filled_cells": filled_cells,
                "saturation": saturation,
                "empty_cells": total_cells - filled_cells,
            },
        },
        "by_category": {c: cat_counter.get(c, 0) for c in CATEGORY_ORDER},
        "by_subcategory": {s: subcat_counter.get(s, 0) for s in SUBCATEGORY_ORDER},
        "by_year": {y: year_counter[y] for y in sorted(year_counter, key=lambda x: (x == "unknown", x))},
        "by_cell": {f"{c}/{s}": n for (c, s), n in sorted(cell_counter.items(), key=lambda kv: -kv[1])},
        "recent_12m": {
            "papers": len(recent),
            "by_category": {c: recent_cat.get(c, 0) for c in CATEGORY_ORDER},
            "emerging_themes": bursts[:12],
        },
        "venues": venue_counter.most_common(10),
        "top_authors": author_counter.most_common(15),
    }

    with open(os.path.join(BASE, "statistics.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    print(f"Wrote statistics.json ({total} papers, {saturation}% saturation)")

    # ---- papers.json export (newest first) ----
    export = []
    for e in entries:
        export.append({
            "title": e.get("title", ""),
            "date": e.get("date", ""),
            "url": e.get("url", ""),
            "category": e.get("category", ""),
            "subcategory": e.get("subcategory", ""),
            "authors": e.get("authors", []),
            "abstract": e.get("abstract", ""),
            "venue": e.get("venue", ""),
        })
    export.sort(key=lambda p: p.get("date", ""), reverse=True)
    with open(os.path.join(BASE, "papers.json"), "w", encoding="utf-8") as f:
        json.dump(export, f, indent=1)
    print(f"Wrote papers.json ({len(export)} papers)")

    # console summary
    print("\nPer category:")
    for c in CATEGORY_ORDER:
        n = cat_counter.get(c, 0)
        r = recent_cat.get(c, 0)
        print(f"  {CATEGORY_DISPLAY[c]:30s} {n:4d}   (last 12m: {r})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())