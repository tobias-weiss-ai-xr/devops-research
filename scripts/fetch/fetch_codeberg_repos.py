#!/usr/bin/env python3
"""Discover DevSecOps-relevant Codeberg repositories and append to repos.yaml.

Uses the **Codeberg Gitea-compatible API** (no CLI needed).  Queries are
hardcoded for the DevSecOps taxonomy, mirroring fetch_github_repos.py's
coverage.

Codeberg API docs (Gitea-flavoured):
  https://codeberg.org/api/swagger

Usage:
    python3 scripts/fetch/fetch_codeberg_repos.py --dry-run
    python3 scripts/fetch/fetch_codeberg_repos.py --min-stars 5
    python3 scripts/fetch/fetch_codeberg_repos.py --host https://codeberg.org

Output: repos.yaml in the repo root (shared with GitHub + GitLab fetchers).
"""

import argparse
import os
import sys
import time
from collections import Counter
from pathlib import Path

import requests
import yaml

from repos_common import (
    REPOS_YAML,
    is_devops_repo,
    normalize_entry,
    load_existing_repos,
    append_repos,
)

CODEBERG_HOST = os.environ.get("CODEBERG_HOST", "https://codeberg.org")
USER_AGENT = "Research-Corpus/1.0 (mailto:business@tobias-weiss.org)"

# ── DevSecOps Codeberg queries ────────────────────────────────────────────
# (search_string, category, subcategory_hint)
# Codeberg/Gitea search supports plain text + topic:TAG and language:LANG.
CODEBERG_QUERIES = [
    # --- security ---
    ("devsecops", "security", "systems"),
    ("vulnerability scanner", "security", "systems"),
    ("sast", "security", "method"),
    ("secret detection", "security", "method"),
    ("sbom", "security", "systems"),
    ("container security", "security", "systems"),
    ("fuzzing", "security", "method"),
    ("zero trust", "security", "theory"),

    # --- CI/CD ---
    ("ci cd", "cicd", "systems"),
    ("continuous integration", "cicd", "systems"),
    ("drone ci", "cicd", "systems"),
    ("woodpecker ci", "cicd", "systems"),
    ("forgejo actions", "cicd", "systems"),

    # --- IaC ---
    ("terraform", "iac", "application"),
    ("ansible", "iac", "application"),
    ("nix flake", "iac", "application"),
    ("infrastructure as code", "iac", "application"),

    # --- Containers / Kubernetes ---
    ("kubernetes", "containers", "systems"),
    ("docker", "containers", "systems"),
    ("podman", "containers", "systems"),
    ("helm", "containers", "systems"),

    # --- Policy as code ---
    ("open policy agent", "policycode", "systems"),
    ("kyverno", "policycode", "systems"),

    # --- Observability ---
    ("opentelemetry", "observability", "systems"),
    ("prometheus", "observability", "systems"),
    ("grafana", "observability", "systems"),

    # --- GitOps ---
    ("gitops", "gitops", "systems"),
    ("argo cd", "gitops", "systems"),

    # --- Platform engineering ---
    ("platform engineering", "platform", "systems"),

    # --- Self-hosting / DevOps adjacent (strong on Codeberg) ---
    ("forgejo", "cicd", "systems"),
    ("gitea", "cicd", "systems"),
    ("self hosting", "platform", "systems"),
    ("homelab", "platform", "systems"),
]


# ── Codeberg / Gitea API helpers ──────────────────────────────────────────

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})


def codeberg_search_repos(query, host, per_page=20, page=1):
    """Search Codeberg repos via Gitea-compatible API.

    Returns (items, total_count).  Max per_page is 50.
    """
    params = {
        "q": query,
        "sort": "stars",
        "order": "desc",
        "limit": min(per_page, 50),
        "page": page,
    }
    try:
        resp = session.get(
            f"{host}/api/v1/repos/search",
            params=params,
            timeout=30,
        )
        if resp.status_code == 429:
            print("  WARNING: Codeberg rate limit (429), waiting 60s", flush=True)
            time.sleep(60)
            return [], 0

        if resp.status_code >= 400:
            print(f"  WARNING: Codeberg API {resp.status_code}: "
                  f"{resp.text[:100]}", flush=True)
            return [], 0

        data = resp.json()
        if not isinstance(data, dict):
            return [], 0

        items = data.get("data", [])
        ok = data.get("ok", False)
        total = data.get("total_count", len(items))
        return (items if ok else []), total
    except requests.Timeout:
        print("  WARNING: Codeberg API timeout", flush=True)
        return [], 0
    except requests.ConnectionError:
        print("  WARNING: Codeberg connection error", flush=True)
        return [], 0


def codeberg_to_raw(item):
    """Map a Codeberg/Gitea repo to a normalised raw dict."""
    license_info = item.get("license", {}) or {}
    license_name = ""
    if isinstance(license_info, dict):
        license_name = license_info.get("spdx_id", license_info.get("name", ""))

    topics = item.get("topics", []) or []

    return {
        "name": item.get("full_name", ""),
        "url": item.get("html_url", ""),
        "description": item.get("description") or "",
        "stars": item.get("stargazers_count", 0) or 0,
        "forks": item.get("forks_count", 0),
        "language": item.get("language") or "",
        "topics": topics,
        "pushed_at": (item.get("updated_at", "") or "")[:10],
        "created_at": (item.get("created_at", "") or "")[:10],
        "open_issues": item.get("open_issues_count", 0),
        "license": license_name,
    }


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Discover DevSecOps Codeberg repos"
    )
    parser.add_argument("--min-stars", type=int, default=5,
                        help="Minimum star threshold (default: 5; Codeberg "
                             "repos have fewer stars)")
    parser.add_argument("--per-page", type=int, default=20,
                        help="Results per page (max 50)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview without writing files")
    parser.add_argument("--sleep", type=float, default=2.0,
                        help="Seconds between queries (default: 2)")
    parser.add_argument("--max-pages", type=int, default=5,
                        help="Max pages per query (default: 5)")
    parser.add_argument("--from", dest="from_idx", type=int, default=0,
                        help="Start at query index")
    parser.add_argument("--to", dest="to_idx", type=int, default=None,
                        help="Stop at query index (inclusive)")
    parser.add_argument("--host", type=str, default=CODEBERG_HOST,
                        help="Codeberg host URL (default: https://codeberg.org)")
    args = parser.parse_args()

    to_idx = args.to_idx if args.to_idx is not None else len(CODEBERG_QUERIES) - 1
    active = CODEBERG_QUERIES[args.from_idx:to_idx + 1]

    existing_names, existing_count = load_existing_repos(REPOS_YAML)
    print(f"Loaded {existing_count} existing repos from repos.yaml", flush=True)
    print(f"Running {len(active)}/{len(CODEBERG_QUERIES)} queries on {args.host} "
          f"(min-stars {args.min_stars})...", flush=True)

    all_new = []
    total_results = 0
    filtered_out = 0

    for qi, (query_text, category, hint) in enumerate(active, start=args.from_idx):
        print(f"\nQuery {qi + 1}/{len(CODEBERG_QUERIES)} [{category}] "
              f"{query_text[:70]}", flush=True)

        for page in range(1, args.max_pages + 1):
            items, total = codeberg_search_repos(
                query_text, args.host,
                per_page=args.per_page, page=page,
            )
            if qi == args.from_idx and page == 1:
                total_results += total
                print(f"  {total} total results", flush=True)

            if not items:
                break

            page_new = 0
            for item in items:
                name = item.get("full_name", "")
                if name.lower().strip() in existing_names:
                    continue

                # Client-side star filtering (API doesn't support min_stars)
                if (item.get("stargazers_count") or 0) < args.min_stars:
                    continue

                desc = item.get("description") or ""
                topics = item.get("topics", []) or []

                if not is_devops_repo(name, desc, topics):
                    filtered_out += 1
                    continue

                existing_names.add(name.lower().strip())
                raw = codeberg_to_raw(item)
                entry = normalize_entry(raw, category, hint)
                all_new.append(entry)
                page_new += 1

            print(f"  page {page}: {len(items)} results, {page_new} new, "
                  f"{len(items) - page_new} dup/filtered", flush=True)

            if len(items) < args.per_page:
                break

        time.sleep(args.sleep)

    print(f"\n{'='*60}", flush=True)
    print(f"Total results scanned: {total_results}", flush=True)
    print(f"Filtered out (irrelevant): {filtered_out}", flush=True)
    print(f"New relevant repos: {len(all_new)}", flush=True)

    if not all_new:
        print("No new repos to add.", flush=True)
        return

    if args.dry_run:
        print(f"\n--- Candidate repos (first 20) ---", flush=True)
        for e in sorted(all_new, key=lambda x: x["stars"], reverse=True)[:20]:
            print(f"  [{e['category']}/{e['subcategory']}] "
                  f"⭐{e['stars']:>5} {e['name']}", flush=True)
            if e.get("description"):
                print(f"    {e['description'][:100]}", flush=True)
        remaining = max(0, len(all_new) - 20)
        if remaining:
            print(f"... and {remaining} more", flush=True)
        print("\nDry run complete — no files modified.", flush=True)
        return

    append_repos(REPOS_YAML, all_new)
    print(f"\nAppended {len(all_new)} repos to repos.yaml", flush=True)

    cats = Counter(e["category"] for e in all_new)
    total_stars = sum(e["stars"] for e in all_new)

    print("\nCategory breakdown:", flush=True)
    for cat, count in cats.most_common():
        print(f"  {cat:15} {count:4}", flush=True)

    print(f"\nTotal new stars: {total_stars:,}", flush=True)


if __name__ == "__main__":
    main()
