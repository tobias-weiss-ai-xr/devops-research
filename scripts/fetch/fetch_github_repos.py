#!/usr/bin/env python3
"""Discover DevSecOps-relevant GitHub repositories and store as repos.yaml.

Searches GitHub by topic and keyword, classifying repos into the DevSecOps
taxonomy (security, cicd, iac, containers, etc.). Each repo entry captures
stars, forks, activity, language, topics, and a description — providing a
complementary "tool/project" dimension alongside the paper corpus.

Usage:
    python3 scripts/fetch/fetch_github_repos.py --min-stars 50 --dry-run
    python3 scripts/fetch/fetch_github_repos.py --min-stars 200
    python3 scripts/fetch/fetch_github_repos.py --min-stars 500 --per-page 30

Output: repos.yaml in the repo root (sibling to papers.yaml).
"""

import argparse
import json
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

from repos_common import (
    REPOS_YAML,
    is_devops_repo,
    normalize_entry,
    load_existing_repos,
    append_repos,
)

# ── Taxonomy queries ──────────────────────────────────────────────────────
# Each query: (search_string, category, subcategory_hint)
# GitHub search syntax: https://docs.github.com/en/search-github/searching-on-github/searching-for-repositories
GITHUB_QUERIES = [
    # --- security ---
    ("topic:devsecops+stars:>100", "security", "systems"),
    ("topic:supply-chain-security+stars:>50", "security", "systems"),
    ("vulnerability-scanner+stars:>200", "security", "systems"),
    ("sast+security-tool+stars:>100", "security", "method"),
    ("secret-detection+stars:>200", "security", "method"),
    ("sbom+stars:>50", "security", "systems"),
    ("dependency-checking+security+stars:>100", "security", "application"),
    ("container-security+stars:>100", "security", "systems"),
    ("kubernetes-security+stars:>100", "security", "systems"),
    ("threat-modeling+stars:>30", "security", "method"),
    ("runtime-security+stars:>100", "security", "systems"),
    ("malware-analysis-tool+stars:>100", "security", "mechanism"),
    ("fuzzing-tool+stars:>200", "security", "method"),
    ("zero-trust+stars:>50", "security", "theory"),

    # --- CI/CD ---
    ("topic:cicd+stars:>100", "cicd", "systems"),
    ("ci-cd-pipeline+stars:>100", "cicd", "systems"),
    ("github-actions+stars:>200", "cicd", "systems"),
    ("gitlab-ci+stars:>100", "cicd", "systems"),
    ("jenkins-plugin+stars:>100", "cicd", "systems"),
    ("build-tool+stars:>200", "cicd", "systems"),

    # --- IaC ---
    ("topic:infrastructure-as-code+stars:>100", "iac", "application"),
    ("terraform-provider+stars:>100", "iac", "application"),
    ("ansible-role+stars:>100", "iac", "application"),
    ("pulumi-provider+stars:>50", "iac", "application"),
    ("opentofu+stars:>50", "iac", "application"),
    ("crossplane+stars:>100", "iac", "systems"),

    # --- Containers / Kubernetes ---
    ("topic:kubernetes+stars:>500", "containers", "systems"),
    ("container-orchestration+stars:>100", "containers", "systems"),
    ("helm-chart+stars:>100", "containers", "systems"),
    ("kubernetes-operator+stars:>100", "containers", "systems"),
    ("service-mesh+stars:>100", "containers", "systems"),
    ("container-runtime+stars:>100", "containers", "systems"),

    # --- Policy as code ---
    ("topic:policy-as-code+stars:>50", "policycode", "systems"),
    ("open-policy-agent+stars:>50", "policycode", "systems"),
    ("opa-policy+stars:>30", "policycode", "method"),
    ("kyverno+stars:>50", "policycode", "systems"),
    ("gatekeeper+stars:>50", "policycode", "systems"),

    # --- Observability ---
    ("topic:observability+stars:>200", "observability", "systems"),
    ("opentelemetry+stars:>100", "observability", "systems"),
    ("prometheus+stars:>500", "observability", "systems"),
    ("grafana+stars:>500", "observability", "systems"),
    ("distributed-tracing+stars:>100", "observability", "systems"),
    ("log-analysis+stars:>100", "observability", "method"),

    # --- GitOps ---
    ("topic:gitops+stars:>100", "gitops", "systems"),
    ("argo-cd+stars:>100", "gitops", "systems"),
    ("flux-cd+stars:>100", "gitops", "systems"),
    ("progressive-delivery+stars:>50", "gitops", "method"),

    # --- Platform engineering ---
    ("topic:platform-engineering+stars:>50", "platform", "systems"),
    ("backstage+stars:>100", "platform", "systems"),
    ("internal-developer-platform+stars:>30", "platform", "systems"),
    ("developer-portal+stars:>50", "platform", "systems"),

    # --- AI security (DevOps-anchored) ---
    ("ai-security-tool+stars:>50", "ai-security", "systems"),
    ("llm-security+stars:>50", "ai-security", "method"),
    ("prompt-injection+stars:>50", "ai-security", "method"),
    ("ai-agent-security+stars:>30", "ai-security", "systems"),
    ("model-context-protocol+stars:>30", "ai-security", "systems"),
]


# ── GitHub API helpers ────────────────────────────────────────────────────

def gh_search_repos(query, sort="stars", order="desc", per_page=30, page=1):
    """Search GitHub repos using `gh api`. Returns (items, total_count)."""
    cmd = [
        "gh", "api", "--method", "GET",
        f"search/repositories?q={query}&sort={sort}&order={order}"
        f"&per_page={per_page}&page={page}",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            err = result.stderr.strip()
            if "422" in err or "rate limit" in err.lower():
                return [], 0
            print(f"  WARNING: gh api error: {err[:120]}", flush=True)
            return [], 0
        data = json.loads(result.stdout)
        return data.get("items", []), data.get("total_count", 0)
    except subprocess.TimeoutExpired:
        print("  WARNING: gh api timeout", flush=True)
        return [], 0
    except json.JSONDecodeError:
        return [], 0


def github_to_raw(item):
    """Map a GitHub API search result to a normalised raw dict."""
    return {
        "name": item.get("full_name", ""),
        "url": item.get("html_url", ""),
        "description": item.get("description") or "",
        "stars": item.get("stargazers_count", 0),
        "forks": item.get("forks_count", 0),
        "language": item.get("language") or "",
        "topics": item.get("topics", []),
        "pushed_at": item.get("pushed_at", "")[:10],
        "created_at": item.get("created_at", "")[:10],
        "open_issues": item.get("open_issues_count", 0),
        "license": (item.get("license") or {}).get("spdx_id", ""),
    }


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Discover DevSecOps GitHub repos")
    parser.add_argument("--min-stars", type=int, default=50,
                        help="Minimum star threshold for queries (default: 50)")
    parser.add_argument("--per-page", type=int, default=30,
                        help="Results per GitHub query (max 100)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview without writing files")
    parser.add_argument("--sleep", type=float, default=3.0,
                        help="Seconds between queries (default: 3)")
    parser.add_argument("--max-pages", type=int, default=3,
                        help="Max pages per query (default: 3 = 90 repos/query)")
    parser.add_argument("--from", dest="from_idx", type=int, default=0,
                        help="Start at query index")
    parser.add_argument("--to", dest="to_idx", type=int, default=None,
                        help="Stop at query index (inclusive)")
    args = parser.parse_args()

    # Adjust star thresholds in queries
    queries = []
    for q_str, cat, hint in GITHUB_QUERIES:
        q = re.sub(r'stars:>\d+', f'stars:>{args.min_stars}', q_str)
        queries.append((q, cat, hint))

    to_idx = args.to_idx if args.to_idx is not None else len(queries) - 1

    existing_names, existing_count = load_existing_repos(REPOS_YAML)
    print(f"Loaded {existing_count} existing repos from repos.yaml", flush=True)
    print(f"Running {to_idx - args.from_idx + 1}/{len(queries)} queries "
          f"(min-stars {args.min_stars})...", flush=True)

    all_new = []
    total_results = 0
    filtered_out = 0

    for qi, (query, category, hint) in enumerate(queries[args.from_idx:to_idx + 1], start=args.from_idx):
        print(f"\nQuery {qi + 1}/{len(queries)} [{category}] {query[:80]}", flush=True)

        for page in range(1, args.max_pages + 1):
            items, total = gh_search_repos(query, per_page=args.per_page, page=page)
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

                desc = item.get("description") or ""
                topics = item.get("topics", [])

                # Relevance gate
                if not is_devops_repo(name, desc, topics):
                    filtered_out += 1
                    continue

                existing_names.add(name.lower().strip())
                raw = github_to_raw(item)
                entry = normalize_entry(raw, category, hint)
                all_new.append(entry)
                page_new += 1

            print(f"  page {page}: {len(items)} results, {page_new} new, "
                  f"{len(items) - page_new - (0 if name in existing_names else 0)}"
                  f" dup/filtered", flush=True)

            if len(items) < args.per_page:
                break

        time.sleep(args.sleep)

    print(f"\n{'='*60}", flush=True)
    print(f"Found {len(all_new)} new DevSecOps repos "
          f"(across {total_results} total search results)", flush=True)
    if filtered_out:
        print(f"Filtered out (irrelevant): {filtered_out}", flush=True)

    if not all_new:
        print("No new repos to add.", flush=True)
        return

    if args.dry_run:
        print(f"\n--- Candidate repos (first 15) ---", flush=True)
        for e in all_new[:15]:
            print(f"  [{e['category']}/{e['subcategory']}] "
                  f"⭐{e['stars']} {e['name']}", flush=True)
            print(f"    {e['description'][:100]}", flush=True)
        print(f"... and {max(0, len(all_new) - 15)} more", flush=True)
        print("\nDry run complete — no files modified.", flush=True)
        return

    append_repos(REPOS_YAML, all_new)
    print(f"\nAppended {len(all_new)} repos to repos.yaml", flush=True)

    cats = Counter(e["category"] for e in all_new)
    langs = Counter(e["language"] for e in all_new if e["language"])
    total_stars = sum(e["stars"] for e in all_new)

    print("\nCategory breakdown:", flush=True)
    for cat, count in cats.most_common():
        print(f"  {cat:15} {count:4}", flush=True)

    if langs:
        print("\nTop languages:", flush=True)
        for lang, count in langs.most_common(5):
            print(f"  {lang:15} {count:4}", flush=True)

    print(f"\nTotal new stars: {total_stars:,}", flush=True)


if __name__ == "__main__":
    main()
