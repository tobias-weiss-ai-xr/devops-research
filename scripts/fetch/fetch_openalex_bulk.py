#!/usr/bin/env python3
"""Bulk-fetch devops-research papers from OpenAlex, one request per category.

Generated for the devops-research taxonomy. Uses OpenAlex cursor pagination with
a precise `title_and_abstract.search` filter (AND semantics) and relevance
sorting. Recommended for bootstrapping / refreshing the corpus.

Usage:
    python3 scripts/fetch/fetch_openalex_bulk.py --per-category 100 --months 36
"""

import argparse
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import yaml

OPENALEX_API = "https://api.openalex.org/works"
MAILTO = os.environ.get("OPENALEX_MAILTO", "business@tobias-weiss.org")

ARXIV_ID_PATTERN = re.compile(r"(\d{4}\.\d{4,5})(v\d+)?")

# One main search term per taxonomy category
CATEGORY_TERMS = [
    ('security', 'devops security cloud'),
    ('cicd', 'CI CD pipelines automation'),
    ('iac', 'infrastructure as code'),
    ('containers', 'container orchestration kubernetes docker'),
    ('policycode', 'policy as code'),
    ('observability', 'observability monitoring tracing'),
    ('gitops', 'gitops deployment'),
    ('platform', 'platform engineering'),
    ('ai-security', 'AI security large language models vulnerabilities'),
]

# Subcategory keyword rules (repo taxonomy)
SUBCAT_KEYWORDS = [
    ('application', ['application']),
]


def load_existing_papers(yaml_path):
    """Load existing papers and build lookup structures."""
    if not yaml_path.exists():
        return {}, []
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    papers = data.get("papers", [])
    by_id = {}
    titles_lower = []
    for p in papers:
        url = p.get("url", "")
        match = ARXIV_ID_PATTERN.search(url)
        if match:
            by_id[match.group(1)] = p
        else:
            by_id.setdefault(url, p)
        titles_lower.append((p.get("title") or "").lower().strip())
    return by_id, titles_lower


def classify_subcategory(title, abstract):
    """Assign a subcategory using keyword rules against title + abstract."""
    text = f"{title} {abstract}".lower()
    for subcat, keywords in SUBCAT_KEYWORDS:
        if any(k.lower() in text for k in keywords):
            return subcat
    return "application"


def sanitize_date(date_str):
    """Normalize a date to YYYY-MM, clamping future dates to today."""
    if not date_str:
        return "papers"
    y = date_str[:4]
    m = date_str[5:7] if len(date_str) >= 7 else "01"
    if not y.isdigit() or not m.isdigit():
        return "papers"
    now = datetime.now(timezone.utc)
    if (int(y), int(m)) > (now.year, now.month):
        return now.strftime("%Y-%m")
    return f"{y}-{m}"


def date_filter(months):
    cutoff = datetime.now(timezone.utc) - timedelta(days=months * 30)
    return cutoff.strftime("%Y-%m-%d")


def reconstruct_abstract(inverted):
    if not inverted:
        return "papers"
    pos = {}
    for word, positions in inverted.items():
        for p in positions:
            pos[p] = word
    return " ".join(pos[i] for i in sorted(pos))


def fetch_category(terms, months, per_category, sleep):
    """Cursor-paginated, relevance-sorted fetch for one category."""
    entries = []
    cursor = "*"
    search_filter = f"title_and_abstract.search:{terms}"
    while len(entries) < per_category and cursor:
        params = {
            "filter": (
                f"from_publication_date:{date_filter(months)},"
                f"{search_filter}"
            ),
            "per-page": 100,
            "mailto": MAILTO,
            "cursor": cursor,
        }
        data = None
        for attempt in range(4):
            try:
                resp = requests.get(OPENALEX_API, params=params, timeout=30)
                if resp.status_code == 429:
                    wait = 15 * (attempt + 1)
                    print(f"    rate-limited (429), waiting {wait}s...", flush=True)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                data = resp.json()
                break
            except Exception as e:
                print(f"  WARNING: {e}", flush=True)
                break
        if not data:
            break
        results = data.get("results", [])
        cursor = data.get("meta", {}).get("next_cursor")
        if not results:
            break
        for work in results:
            title = work.get("title") or ""
            if not title:
                continue
            url = ""
            for loc in work.get("locations", []):
                src = (loc.get("source") or {}).get("id", "")
                lurl = loc.get("landing_page_url") or ""
                if "arxiv" in src or "arxiv" in lurl:
                    url = lurl.replace("http://", "https://").replace("https://arxiv.org/abs/", "https://arxiv.org/abs/")
                    url = re.sub(r"(arxiv\.org/abs/\d{4}\.\d{4,5})v\d+", r"\1", url)
                    break
            if not url:
                primary = work.get("primary_location") or {}
                url = (primary.get("landing_page_url") or "").replace("http://", "https://")
            if not url:
                url = work.get("doi") or ""
            if not url:
                continue
            mdoi = re.match(r"https?://doi\.org/10\.48550/arxiv\.(\d{4}\.\d{4,5})", url)
            if mdoi:
                url = "https://arxiv.org/abs/" + mdoi.group(1)
            date = sanitize_date(work.get("publication_date") or "")
            if not date:
                date = sanitize_date(str(work.get("publication_year") or ""))
            abstract = reconstruct_abstract(work.get("abstract_inverted_index"))
            entries.append(
                {
                    "title": title,
                    "date": date,
                    "url": url,
                    "category": None,
                    "subcategory": classify_subcategory(title, abstract),
                    "authors": [a.get("author", {}).get("display_name", "") for a in work.get("authorships", [])][:3],
                    "abstract": abstract[:200],
                    "venue": ((work.get("primary_location") or {}).get("source") or {}).get("display_name") or "",
                }
            )
        print(f"    page: {len(results)} results ({len(entries)} total)", flush=True)
        time.sleep(sleep)
    return entries


def append_papers(yaml_path, new_papers):
    if yaml_path.exists():
        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f) or {}
    else:
        data = {}
    papers = data.get("papers", [])
    for entry in new_papers:
        papers.append(entry)
    data["papers"] = papers
    with open(yaml_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


def main():
    parser = argparse.ArgumentParser(description="Bulk-fetch devops-research papers from OpenAlex per category")
    parser.add_argument("--months", type=int, default=36)
    parser.add_argument("--per-category", type=int, default=100)
    parser.add_argument("--sleep", type=float, default=5.0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--categories", default=None, help="Comma-separated subset of category keys")
    args = parser.parse_args()

    yaml_path = Path(__file__).resolve().parent.parent.parent / "papers.yaml"
    by_id, titles_lower = load_existing_papers(yaml_path)
    print(f"Loaded {len(by_id)} existing papers", flush=True)

    if args.categories:
        wanted = {c.strip() for c in args.categories.split(",") if c.strip()}
        terms_list = [(c, t) for c, t in CATEGORY_TERMS if c in wanted]
    else:
        terms_list = CATEGORY_TERMS

    for cat, terms in terms_list:
        print(f"\n=== [{cat}] {terms} ===", flush=True)
        entries = fetch_category(terms, args.months, args.per_category, args.sleep)
        new = []
        for e in entries:
            m = ARXIV_ID_PATTERN.search(e["url"])
            key = m.group(1) if m else e["url"]
            if key and key in by_id:
                continue
            if any(e["url"] == x["url"] for x in new):
                continue
            t_lower = e["title"].lower().strip()
            if any(t_lower == t for t in titles_lower):
                continue
            e["category"] = cat
            new.append(e)
            by_id[key] = e
            titles_lower.append(t_lower)

        print(f"  {len(new)} new for {cat}", flush=True)
        if args.dry_run:
            continue
        append_papers(yaml_path, new)
        print(f"  saved ({len(by_id)} total)", flush=True)
        time.sleep(args.sleep * 2)

    print("\nDone.", flush=True)


if __name__ == "__main__":
    main()
