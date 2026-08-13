#!/usr/bin/env python3
"""Discover DevSecOps-relevant GitLab projects and append to repos.yaml.

Uses the **GitLab public REST API** (no ``glab`` CLI required).  Queries are
hardcoded for the DevSecOps taxonomy, mirroring fetch_github_repos.py's
coverage across security, cicd, iac, containers, policycode, observability,
gitops, platform, and ai-security categories.

Note: GitLab's /projects endpoint does not support ``order_by=stars`` for
search queries.  Results are sorted by last activity and star filtering
is applied client-side.

Usage:
    python3 scripts/fetch/fetch_gitlab_repos.py --dry-run
    python3 scripts/fetch/fetch_gitlab_repos.py --min-stars 5
    python3 scripts/fetch/fetch_gitlab_repos.py --host https://gitlab.gwdg.de

Output: repos.yaml in the repo root (shared with GitHub fetcher).
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

GITLAB_HOST = os.environ.get("GITLAB_HOST", "https://gitlab.com")
USER_AGENT = "Research-Corpus/1.0 (mailto:business@tobias-weiss.org)"

# ── DevSecOps GitLab queries ──────────────────────────────────────────────
# (search_string, category, subcategory_hint)
# GitLab search is substring-based across project name + description.
# No boolean operators; each query is one search string.
GITLAB_QUERIES = [
    # --- security ---
    ("devsecops", "security", "systems"),
    ("vulnerability scanner", "security", "systems"),
    ("sast tool", "security", "method"),
    ("secret detection", "security", "method"),
    ("sbom software", "security", "systems"),
    ("container security", "security", "systems"),
    ("threat modeling", "security", "method"),
    ("fuzzing", "security", "method"),
    ("zero trust", "security", "theory"),

    # --- CI/CD ---
    ("ci cd pipeline", "cicd", "systems"),
    ("gitlab ci template", "cicd", "method"),
    ("jenkins shared library", "cicd", "systems"),
    ("build tool", "cicd", "systems"),

    # --- IaC ---
    ("terraform module", "iac", "application"),
    ("ansible role", "iac", "application"),
    ("infrastructure as code", "iac", "application"),
    ("crossplane", "iac", "systems"),

    # --- Containers / Kubernetes ---
    ("kubernetes operator", "containers", "systems"),
    ("helm chart", "containers", "systems"),
    ("service mesh", "containers", "systems"),
    ("container runtime", "containers", "systems"),

    # --- Policy as code ---
    ("open policy agent", "policycode", "systems"),
    ("kyverno policy", "policycode", "systems"),
    ("gatekeeper", "policycode", "systems"),

    # --- Observability ---
    ("opentelemetry", "observability", "systems"),
    ("prometheus", "observability", "systems"),
    ("grafana dashboard", "observability", "systems"),
    ("distributed tracing", "observability", "systems"),
    ("log analysis", "observability", "method"),

    # --- GitOps ---
    ("gitops", "gitops", "systems"),
    ("argo cd", "gitops", "systems"),
    ("flux cd", "gitops", "systems"),

    # --- Platform engineering ---
    ("backstage developer portal", "platform", "systems"),
    ("platform engineering", "platform", "systems"),

    # --- AI security (DevOps-anchored) ---
    ("llm security", "ai-security", "method"),
    ("ai agent security", "ai-security", "systems"),
    ("model context protocol", "ai-security", "systems"),
]


# ── GitLab API helpers ───────────────────────────────────────────────────

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})


def gitlab_search_projects(query, host, min_stars=5, per_page=20, page=1):
    """Search GitLab projects via REST API.  Returns (items, total_count).

    GitLab doesn't support ``order_by=stars`` for search; uses
    ``last_activity_at`` and filters stars client-side.
    """
    params = {
        "search": query,
        "order_by": "last_activity_at",
        "sort": "desc",
        "per_page": per_page,
        "page": page,
        "simple": "true",
        "membership": "false",
    }
    try:
        resp = session.get(
            f"{host}/api/v4/projects",
            params=params,
            timeout=30,
        )
        if resp.status_code == 429:
            reset = int(resp.headers.get("RateLimit-Reset", 0))
            wait = max(60, reset - int(time.time()) + 1)
            print(f"  WARNING: GitLab rate limit (429), waiting {wait}s", flush=True)
            time.sleep(wait)
            return [], 0

        if resp.status_code >= 400:
            print(f"  WARNING: GitLab API {resp.status_code}: {resp.text[:100]}",
                  flush=True)
            return [], 0

        data = resp.json()
        if not isinstance(data, list):
            return [], 0

        # Client-side star filtering
        items = [p for p in data if (p.get("star_count") or 0) >= min_stars]
        total = int(resp.headers.get("X-Total", len(items)))
        return items, total
    except requests.Timeout:
        print("  WARNING: GitLab API timeout", flush=True)
        return [], 0
    except requests.ConnectionError:
        print("  WARNING: GitLab connection error", flush=True)
        return [], 0


def gitlab_to_raw(item):
    """Map a GitLab project to a normalised raw dict."""
    license_info = item.get("license", {}) or {}
    license_name = ""
    if isinstance(license_info, dict):
        license_name = license_info.get("spdx_id", license_info.get("name", ""))
    elif isinstance(license_info, str):
        license_name = license_info

    topics_raw = item.get("topics", []) or []
    if isinstance(topics_raw, str):
        topics = [t.strip() for t in topics_raw.split(",") if t.strip()]
    else:
        topics = topics_raw

    return {
        "name": item.get("path_with_namespace", item.get("path", "")),
        "url": item.get("web_url", item.get("http_url_to_repo", "")),
        "description": item.get("description") or "",
        "stars": item.get("star_count", 0),
        "forks": item.get("forks_count", 0),
        "language": "",  # GitLab project search doesn't return primary language
        "topics": topics,
        "pushed_at": (item.get("last_activity_at", "") or "")[:10],
        "created_at": (item.get("created_at", "") or "")[:10],
        "open_issues": item.get("open_issues_count", 0),
        "license": license_name,
    }


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Discover DevSecOps GitLab projects"
    )
    parser.add_argument("--min-stars", type=int, default=5,
                        help="Minimum star threshold (default: 5; GitLab repos "
                             "typically have fewer stars)")
    parser.add_argument("--per-page", type=int, default=20,
                        help="Results per page (max 100)")
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
    parser.add_argument("--host", type=str, default=GITLAB_HOST,
                        help="GitLab host URL (default: https://gitlab.com)")
    args = parser.parse_args()

    to_idx = args.to_idx if args.to_idx is not None else len(GITLAB_QUERIES) - 1
    active = GITLAB_QUERIES[args.from_idx:to_idx + 1]

    existing_names, existing_count = load_existing_repos(REPOS_YAML)
    print(f"Loaded {existing_count} existing repos from repos.yaml", flush=True)
    print(f"Running {len(active)}/{len(GITLAB_QUERIES)} queries on {args.host} "
          f"(min-stars {args.min_stars})...", flush=True)

    all_new = []
    total_results = 0
    filtered_out = 0

    for qi, (query_text, category, hint) in enumerate(active, start=args.from_idx):
        print(f"\nQuery {qi + 1}/{len(GITLAB_QUERIES)} [{category}] "
              f"{query_text[:70]}", flush=True)

        for page in range(1, args.max_pages + 1):
            items, total = gitlab_search_projects(
                query_text, args.host,
                min_stars=args.min_stars,
                per_page=args.per_page, page=page,
            )
            if qi == args.from_idx and page == 1:
                total_results += total
                print(f"  {total} total results", flush=True)

            if not items:
                break

            page_new = 0
            for item in items:
                name = item.get("path_with_namespace", item.get("path", ""))
                if name.lower().strip() in existing_names:
                    continue

                desc = item.get("description") or ""
                topics = item.get("topics", []) or []

                if not is_devops_repo(name, desc, topics):
                    filtered_out += 1
                    continue

                existing_names.add(name.lower().strip())
                raw = gitlab_to_raw(item)
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
