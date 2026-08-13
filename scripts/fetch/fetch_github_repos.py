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
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

BASE = Path(__file__).resolve().parent.parent.parent
REPOS_YAML = BASE / "repos.yaml"

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


# ── Subcategory classification ─────────────────────────────────────────────

SUBCATEGORY_RULES = [
    ("review", ["survey", "benchmark", "comparison", "awesome", "collection", "curated"], True),
    ("theory", ["framework", "specification", "standard", "rfc", "architecture", "model"], False),
    ("security", ["vulnerability", "cve", "exploit", "malware", "threat", "attack", "hardening"], False),
    ("application", ["cli", "tool", "scanner", "analyzer", "detector", "checker", "linter"], False),
    ("development", ["sdk", "library", "api", "client", "wrapper", "binding"], False),
    ("method", ["template", "boilerplate", "starter", "example", "demo", "playground"], False),
    ("systems", ["platform", "engine", "orchestrator", "operator", "controller", "runtime", "daemon"], False),
    ("evaluation", ["benchmark", "test-suite", "testbed", "evaluation", "metrics"], False),
]
SUBCATEGORY_FALLBACK = "application"


def classify_subcategory(name, description, topics):
    """Assign subcategory from repo name, description, and GitHub topics."""
    text = f"{name} {description} {' '.join(topics)}".lower()
    name_lower = name.lower()
    for subcat, keywords, title_only in SUBCATEGORY_RULES:
        haystack = name_lower if title_only else text
        for kw in keywords:
            if kw in haystack:
                return subcat
    return SUBCATEGORY_FALLBACK


# ── GitHub API helpers ────────────────────────────────────────────────────

def gh_search_repos(query, sort="stars", order="desc", per_page=30, page=1):
    """Search GitHub repos using `gh api`. Returns (items, total_count)."""
    cmd = [
        "gh", "api", "--method", "GET",
        f"search/repositories?q={query}&sort={sort}&order={order}&per_page={per_page}&page={page}"
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


def to_entry(item, category, subcategory_hint):
    """Map a GitHub search result to a repos.yaml entry."""
    name = item.get("full_name", "")
    desc = (item.get("description") or "")[:200]
    topics = item.get("topics", [])
    return {
        "name": name,
        "url": item.get("html_url", ""),
        "description": desc,
        "category": category,
        "subcategory": classify_subcategory(name, desc, topics),
        "stars": item.get("stargazers_count", 0),
        "forks": item.get("forks_count", 0),
        "language": item.get("language") or "",
        "topics": sorted(topics),
        "pushed_at": item.get("pushed_at", "")[:10],
        "created_at": item.get("created_at", "")[:10],
        "open_issues": item.get("open_issues_count", 0),
        "license": (item.get("license") or {}).get("spdx_id", ""),
    }


# ── YAML I/O ─────────────────────────────────────────────────────────────

def _yaml_str(s):
    """Escape a string for a double-quoted YAML scalar."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def format_yaml_entry(entry):
    """Format a single repo entry as YAML lines."""
    lines = [f'  - name: "{_yaml_str(entry["name"])}"']
    lines.append(f'    url: {entry["url"]}')
    if entry.get("description"):
        lines.append(f'    description: "{_yaml_str(entry["description"])}"')
    lines.append(f'    category: {entry["category"]}')
    lines.append(f'    subcategory: {entry["subcategory"]}')
    lines.append(f'    stars: {entry["stars"]}')
    lines.append(f'    forks: {entry["forks"]}')
    if entry.get("language"):
        lines.append(f'    language: {entry["language"]}')
    if entry.get("topics"):
        lines.append(f'    topics:')
        for t in entry["topics"]:
            lines.append(f'      - {_yaml_str(t)}')
    if entry.get("pushed_at"):
        lines.append(f'    pushed_at: "{entry["pushed_at"]}"')
    if entry.get("created_at"):
        lines.append(f'    created_at: "{entry["created_at"]}"')
    if entry.get("open_issues"):
        lines.append(f'    open_issues: {entry["open_issues"]}')
    if entry.get("license") and entry["license"] != "NOASSERTION":
        lines.append(f'    license: {entry["license"]}')
    return "\n".join(lines)


def load_existing_repos(path):
    """Load repos.yaml, return (names_set, entries_count)."""
    if not path.exists():
        return set(), 0
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    repos = data.get("repos", [])
    names = {r.get("name", "").lower().strip() for r in repos}
    return names, len(repos)


def append_repos(path, entries):
    """Append entries to repos.yaml, creating the file if needed."""
    lines = []
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        lines = content.rstrip("\n").split("\n")
        # Remove trailing "repos:" if it's the only line
        if lines == ["repos:"]:
            lines = ["repos:"]
        else:
            lines.append("")  # blank separator
    else:
        lines = [
            "# GitHub repositories relevant to DevSecOps research.",
            "# Generated by scripts/fetch/fetch_github_repos.py",
            f"# Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            "",
            "repos:",
        ]

    for entry in entries:
        lines.append(format_yaml_entry(entry))

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ── DevOps relevance check (reuse signals) ──────────────────────────────

def _norm(text):
    import re
    return re.sub(r"[\s-]+", " ", re.sub(r"[-/]", " ", text.lower()))

# Minimal strong signals for repo classification (subset of fetch_new_papers)
REPO_STRONG = [
    "ci cd", "continuous integration", "continuous delivery", "github actions",
    "gitlab ci", "jenkins", "devsecops", "devops", "sre",
    "infrastructure as code", "terraform", "ansible", "pulumi",
    "policy as code", "kubernetes", "k8s", "docker", "container",
    "orchestration", "serverless", "microservice", "cloud native",
    "observability", "opentelemetry", "prometheus", "grafana",
    "distributed tracing", "gitops", "argo cd", "flux cd",
    "progressive delivery", "backstage", "platform engineering",
    "software supply chain", "sbom", "sast", "dast", "vulnerability",
    "secret detection", "zero trust", "fuzzing", "open policy agent",
    "kyverno", "gatekeeper", "helm", "istio", "crossplane",
    "llm security", "ai agent security", "model context protocol",
]

def _word_re(tokens):
    import re
    normed = [_norm(t) for t in tokens]
    parts = []
    for s in normed:
        words = s.split(" ")
        escaped = [re.escape(w) for w in words]
        if len(escaped) == 1:
            parts.append(r"\b" + escaped[0] + r"\b")
        else:
            parts.append(r"\b" + " ".join(escaped))
    return re.compile(r"|".join(parts), re.I)

_re = _word_re(REPO_STRONG)

def is_devops_repo(name, description, topics):
    """Quick relevance check — gate out obviously irrelevant repos."""
    text = _norm(f"{name} {description} {' '.join(topics)}")
    return bool(_re.search(text))


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
        # Replace stars:>N with the user's min-stars if it's lower
        import re
        q = re.sub(r'stars:>\d+', f'stars:>{args.min_stars}', q_str)
        queries.append((q, cat, hint))

    to_idx = args.to_idx if args.to_idx is not None else len(queries) - 1

    existing_names, existing_count = load_existing_repos(REPOS_YAML)
    print(f"Loaded {existing_count} existing repos from repos.yaml", flush=True)
    print(f"Running {to_idx - args.from_idx + 1}/{len(queries)} queries (min-stars {args.min_stars})...", flush=True)

    all_new = []
    total_results = 0

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
                existing_names.add(name.lower().strip())

                desc = item.get("description") or ""
                topics = item.get("topics", [])

                # Relevance gate
                if not is_devops_repo(name, desc, topics):
                    continue

                entry = to_entry(item, category, hint)
                all_new.append(entry)
                page_new += 1

            print(f"  page {page}: {len(items)} results, {page_new} new repos", flush=True)

            if len(items) < args.per_page:
                break  # no more pages

        time.sleep(args.sleep)

    print(f"\n{'='*60}", flush=True)
    print(f"Found {len(all_new)} new DevSecOps repos (across {total_results} total search results)", flush=True)

    if not all_new:
        print("No new repos to add.", flush=True)
        return

    if args.dry_run:
        print(f"\n--- Candidate repos (first 15) ---", flush=True)
        for e in all_new[:15]:
            print(f"  [{e['category']}/{e['subcategory']}] ⭐{e['stars']} {e['name']}", flush=True)
            print(f"    {e['description'][:100]}", flush=True)
        print(f"... and {max(0, len(all_new) - 15)} more", flush=True)
        print("\nDry run complete — no files modified.", flush=True)
        return

    append_repos(REPOS_YAML, all_new)
    print(f"\nAppended {len(all_new)} repos to {REPOS_YAML.name}", flush=True)

    # Show category breakdown
    from collections import Counter
    cats = Counter(e["category"] for e in all_new)
    print("\nCategory breakdown:", flush=True)
    for cat, count in cats.most_common():
        print(f"  {cat:15} {count:4}", flush=True)


if __name__ == "__main__":
    main()
