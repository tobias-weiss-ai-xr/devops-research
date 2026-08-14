#!/usr/bin/env python3
"""Discover DevSecOps-relevant Python libraries/tools on PyPI.

PyPI hosts ~870k packages and has no public classifier/keyword *search*
endpoint, so this fetcher uses a curated seed list of well-known DevSecOps
Python packages (security scanners, SBOM tooling, policy/compliance, IAM,
observability agents, CICD helpers) and enriches each via the PyPI JSON API
(``https://pypi.org/pypi/{pkg}/json``).

This keeps the number of API calls strictly bounded (one per seed package),
avoiding the 870k-package full-scan problem.

Usage:
    python3 scripts/fetch/fetch_pypi_repos.py --dry-run
    python3 scripts/fetch/fetch_pypi_repos.py [--seed file]
"""

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

import requests
import yaml

from repos_common import (
    REPOS_YAML,
    load_existing_repos,
    append_repos,
    classify_subcategory,
    normalize_entry,
    enrich_github,
    repo_slug_from_url,
)

PyPI_URL = "https://pypi.org/pypi/{pkg}/json"
USER_AGENT = "Research-Corpus/1.0 (mailto:research@tobias-weiss-ai-xr.de)"

# Curated seed list of well-known DevSecOps Python packages: (pypi_name, category)
SEED = {
    # --- secret scanning / SAST / SCA ---------------------------------
    "bandit": "security",
    "semgrep": "security",
    "ruff": "security",
    "safety": "security",
    "pip-audit": "security",
    "pip-licenses": "security",
    "guarddog": "security",
    "scancode-toolkit": "security",
    "gitleaks": "security",
    "trufflehog": "security",
    "detect-secrets": "security",
    "secret-shield": "security",
    "yor": "security",
    "kics": "security",
    "checkov": "security",
    "tfsec": "security",
    "cve-bin-tool": "security",
    "osv-scanner": "security",
    "dependency-check-py": "security",
    "cyclonedx-python-lib": "security",
    "cyclonedx-bom": "security",
    "spdx-tools": "security",
    "pipdeptree": "security",
    # --- policy / compliance / cloud posture --------------------------
    "prowler": "security",
    "cloudsplaining": "security",
    "pacbot": "security",
    "scoutsuite": "security",
    "cs-suite": "security",
    "policy-sentry": "security",
    "parliament": "security",
    "cloud-custodian": "security",
    "pytest-helm-charts-sandbox": "security",
    "regula": "security",
    "conftest": "security",
    "opa-python": "security",
    "falco-client": "security",
    # --- IAM / identity ------------------------------------------------
    "aws-iam-policy-generator": "security",
    "iamzero": "security",
    "keycloak-api-client": "security",
    "keycloak": "security",
    "authlib": "security",
    "jose": "security",
    "msal": "security",
    "cryptography": "security",
    "pyjwt": "security",
    # --- SBOM / supply chain ------------------------------------------
    "sbom-tool": "security",
    "osv": "security",
    "pip-conflict-checker": "security",
    "pip-check-updates": "security",
    # --- observability / monitoring ------------------------------------
    "prometheus-client": "observability",
    "prometheus-api-client": "observability",
    "opentelemetry-api": "observability",
    "opentelemetry-sdk": "observability",
    "opentelemetry-instrumentation": "observability",
    "grafana-api-client": "observability",
    "grafanalib": "observability",
    "datadog": "observability",
    "python-logstash": "observability",
    "structlog": "observability",
    "watchtower": "observability",
    "statsd": "observability",
    "pyroscope-io": "observability",
    "sentry-sdk": "observability",
    "pytest-html": "observability",
    "coverage": "observability",
    "pytest-cov": "observability",
    # --- CICD / automation --------------------------------------------
    "invoke": "cicd",
    "nox": "cicd",
    "hatch": "cicd",
    "pdm": "cicd",
    "poetry": "cicd",
    "pip-tools": "cicd",
    "tox": "cicd",
    "pre-commit": "cicd",
    "ansible": "cicd",
    "ansible-lint": "cicd",
    "molecule": "cicd",
    "ansible-runner": "cicd",
    "python-gitlab": "cicd",
    "pygithub": "cicd",
    "dulwich": "cicd",
    "gitpython": "cicd",
    "celery": "platform",
    "redis": "platform",
    "kubernetes": "platform",
    "docker": "platform",
    "python-terraform": "platform",
    "kubernetes-asyncio": "platform",
    "hvac": "platform",
    "boto3": "platform",
    "botocore": "platform",
    "google-cloud-*": "platform",
    "openstacksdk": "platform",
    "libvirt-python": "platform",
    "pulumi": "platform",
}

# Skip the wildcard placeholders above (kept as documentation only). These are
# handled by explicit entries already, so we drop them from enrichment.
_SKIP_WILDCARDS = {p for p in SEED if "*" in p}


def fetch_pkg(session, pkg):
    """Fetch PyPI JSON for a package. Returns dict or None."""
    try:
        resp = session.get(PyPI_URL.format(pkg=pkg), timeout=25)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except Exception:  # noqa: BLE001
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Discover DevSecOps Python packages on PyPI")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview without writing files")
    parser.add_argument("--sleep", type=float, default=0.2,
                        help="Seconds between API calls (rate limiting)")
    args = parser.parse_args()

    existing_names, existing_count = load_existing_repos(REPOS_YAML)
    print(f"Loaded {existing_count} existing repos from repos.yaml", flush=True)

    # Drop wildcard placeholders
    seed = sorted(p for p in SEED if p not in _SKIP_WILDCARDS)

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    collected = {}
    for i, pkg in enumerate(seed):
        if pkg.lower() in existing_names:
            continue
        data = fetch_pkg(session, pkg)
        if not data or not data.get("info"):
            # try the common name variation (e.g. underscore vs dash) later
            continue
        info = data["info"]
        name = info.get("name") or pkg
        if name.lower() in existing_names:
            continue

        summary = info.get("summary") or ""
        description = summary or (info.get("description") or "")[:200]
        classifiers = info.get("classifiers") or []
        # topic check (Topic :: Security is strong signal)
        topics = [c.split(":: ")[-1] for c in classifiers if c.startswith("Topic ::")]
        home = (info.get("home_page") or info.get("project_url") or
                f"https://pypi.org/project/{name}/")
        # prefer github repo url in project_urls
        purls = info.get("project_urls") or {}
        github_url = ""
        for v in purls.values():
            if v and any(h in v for h in ("github.com", "gitlab.com", "codeberg.org")):
                github_url = v
                break

        category = SEED[pkg]
        raw = {
            "name": name,
            "url": _canonical_repo_url(github_url or home),
            "description": (description or summary)[:200],
            "topics": [t for t in topics if t][:6],
            "license": _license_from(info),
            "version": info.get("version", ""),
        }
        entry = normalize_entry(raw, category, subcategory_hint=None)
        entry["source"] = "pypi"
        collected[name.lower()] = entry

        if (i + 1) % 20 == 0:
            print(f"  ... processed {i + 1}/{len(seed)}", flush=True)
        time.sleep(args.sleep)

    final = sorted(collected.values(), key=lambda x: x.get("stars", 0),
                   reverse=True)
    print(f"Found {len(final)} new PyPI packages (after dedup)", flush=True)

    if args.dry_run:
        print("\n--- Candidate packages (first 30) ---", flush=True)
        for e in final[:30]:
            print(f"  [{e['category']}] {e['name']} — {e['description'][:60]}",
                  flush=True)
        remaining = max(0, len(final) - 30)
        if remaining:
            print(f"... and {remaining} more", flush=True)
        print("\nDry run complete — no files modified.", flush=True)
        return

    if not final:
        print("No new packages to add.", flush=True)
        return

    enrich_github(final)

    append_repos(REPOS_YAML, final)
    print(f"\nAppended {len(final)} PyPI packages to repos.yaml", flush=True)
    cats = Counter(e["category"] for e in final)
    print("\nCategory breakdown:", flush=True)
    for cat, count in cats.most_common():
        print(f"  {cat:15} {count:4}")


def _canonical_repo_url(url):
    """Clean a repo URL to its canonical owner/repo base."""
    slug = repo_slug_from_url(url)
    if not slug:
        return url
    if "gitlab" in url:
        return f"https://gitlab.com/{slug}"
    if "codeberg" in url:
        return f"https://codeberg.org/{slug}"
    return f"https://github.com/{slug}"


def _license_from(info):
    lic = info.get("license")
    if lic and lic != "UNKNOWN":
        return lic[:60]
    # classifiers: License :: OSI Approved :: Apache Software License
    for c in info.get("classifiers") or []:
        if c.startswith("License ::"):
            return c.split("::")[-1].strip()
    return ""


if __name__ == "__main__":
    main()
