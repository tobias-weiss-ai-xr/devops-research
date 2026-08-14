#!/usr/bin/env python3
"""Discover DevSecOps-relevant projects from the CNCF Cloud Native Landscape.

The CNCF Landscape is the canonical, curated map of the cloud-native ecosystem.
This fetcher extracts the categories most relevant to DevSecOps:
  - Provisioning > Security & Compliance (124 items)
  - Provisioning > Key Management (9 items)
  - Observability and Analysis > Observability (167 items)
  - Obs. and Analysis > Continuous Optimization, Chaos Engineering, Feature Flagging
  - Runtime > Cloud Native Storage, Container Runtime, etc.

Source: https://raw.githubusercontent.com/cncf/landscape/master/landscape.yml

Entries carry name, description, and repo/homepage URLs.  Write to the shared
repos.yaml (dedup by repo URL / name).

Usage:
    python3 scripts/fetch/fetch_cncf_landscape.py --dry-run
    python3 scripts/fetch/fetch_cncf_landscape.py
"""

import argparse
import sys
from collections import Counter
from pathlib import Path

import requests
import yaml

from repos_common import (
    REPOS_YAML,
    load_existing_repos,
    append_repos,
    classify_subcategory,
    enrich_github,
    repo_slug_from_url,
)

LANDSCAPE_URL = ("https://raw.githubusercontent.com/cncf/landscape/"
                 "master/landscape.yml")
USER_AGENT = "Research-Corpus/1.0 (mailto:research@tobias-weiss-ai-xr.de)"

# Subcategories worth including from any category (broad net)
# Focus on the genuinely DevSecOps-relevant parts of the landscape.
SELECTED = [
    ("Provisioning", {"Security & Compliance"}, "security"),
    ("Provisioning", {"Key Management"}, "security"),
    ("Observability and Analysis", {"Observability"}, "observability"),
    ("AI Native Infra", {"Observability"}, "observability"),
]

# Only include entries that reference a public repo (skip pure-commercial
# vendor pages that add no corpus value).
REQUIRE_REPO = True


def _matches_top(cat_name, sub_name):
    for top, subs, _ in SELECTED:
        if cat_name == top and sub_name in subs:
            return True
    return False


def extract_category(cat_name, sub_name):
    for top, subs, repo_cat in SELECTED:
        if cat_name == top and sub_name in subs:
            return repo_cat
    return "platform"


def main():
    parser = argparse.ArgumentParser(
        description="Discover DevSecOps projects from CNCF Landscape")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview without writing files")
    parser.add_argument("--url", default=LANDSCAPE_URL,
                        help="landscape.yml source URL")
    args = parser.parse_args()

    existing_names, existing_count = load_existing_repos(REPOS_YAML)
    print(f"Loaded {existing_count} existing repos from repos.yaml", flush=True)

    try:
        resp = requests.get(args.url, timeout=60,
                            headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
    except Exception as exc:
        print(f"ERROR: could not fetch landscape: {exc}", file=sys.stderr)
        sys.exit(1)

    data = yaml.safe_load(resp.text)
    landscape = data.get("landscape", [])

    collected = {}       # dedup by name (lower) -> entry
    seen_ids = set()
    total_scanned = 0
    for cat in landscape:
        cat_name = cat.get("name", "")
        for sub in cat.get("subcategories", []):
            sub_name = sub.get("name", "")
            if not _matches_top(cat_name, sub_name):
                continue
            for item in sub.get("items", []):
                total_scanned += 1
                name = item.get("name", "").strip()
                if not name:
                    continue
                key = name.lower()
                # description
                desc = item.get("description") or ""
                # repo/homepage url
                url = (item.get("repo_url") or item.get("homepage_url")
                       or item.get("github_data", {}).get("web_url", "") or "")
                if REQUIRE_REPO and not item.get("repo_url"):
                    # skip commercial/vendor entries with no public repo
                    continue
                if not url:
                    url = f"https://github.com/search?q={name.replace(' ', '+')}&type=repositories"

                # Dedup by canonical repo slug when available, else display name.
                slug = repo_slug_from_url(url)
                dedup_key = (slug if slug and "/" in slug else key).lower()
                if dedup_key in collected or dedup_key in existing_names:
                    continue

                repo_cat = extract_category(cat_name, sub_name)

                entry = normalize_cncf_entry(name, desc, url, repo_cat, sub_name)
                if entry:
                    collected[dedup_key] = entry

    print(f"Scanned {total_scanned} items; selected {len(collected)} new "
          f"relevant projects", flush=True)

    # Normalise dedup by repo slug to avoid duplicates across landscape/repos.yaml
    final = []
    for key in sorted(collected):
        e = collected[key]
        existing_names.add(e["name"].lower())
        final.append(e)

    if args.dry_run:
        print(f"\n--- Candidate projects (first 30) ---", flush=True)
        for e in final[:30]:
            print(f"  [{e['category']}/{e['subcategory']}] {e['name']}", flush=True)
            if e.get("description"):
                print(f"    {e['description'][:90]}", flush=True)
        remaining = max(0, len(final) - 30)
        if remaining:
            print(f"... and {remaining} more", flush=True)
        print("\nDry run complete — no files modified.", flush=True)
        return

    enrich_github(final)

    if not final:
        print("No new projects to add.", flush=True)
        return

    final.sort(key=lambda x: x.get("stars", 0), reverse=True)

    append_repos(REPOS_YAML, final)
    print(f"\nAppended {len(final)} CNCF Landscape projects to repos.yaml",
          flush=True)

    cats = Counter(e["category"] for e in final)
    print("\nCategory breakdown:", flush=True)
    for cat, count in cats.most_common():
        print(f"  {cat:15} {count:4}")


def normalize_cncf_entry(name, desc, url, repo_cat, sub_name):
    """Build a repos.yaml entry from a CNCF landscape item."""
    # Prefer the GitHub owner/repo slug as the canonical name for consistency
    # with the rest of the corpus (which uses owner/repo names).
    slug = repo_slug_from_url(url)
    canonical = slug if slug and "/" in slug else name
    subcategory = classify_subcategory(name, desc, [repo_cat])
    # Stub GitHub-ish fields not present in landscape
    return {
        "name": canonical,
        "url": url,
        "description": (desc or "")[:200],
        "category": repo_cat,
        "subcategory": subcategory,
        "stars": 0,
        "forks": 0,
        "language": "",
        "topics": [repo_cat, sub_name.lower().replace(" ", "-")],
        "pushed_at": "",
        "created_at": "",
        "open_issues": 0,
        "license": "",
        "source": f"cncf-landscape:{sub_name}",
    }


if __name__ == "__main__":
    main()
