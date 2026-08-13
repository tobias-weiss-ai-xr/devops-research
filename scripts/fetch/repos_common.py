#!/usr/bin/env python3
"""Shared utilities for repo discovery fetchers in devops-research.

Every ``fetch_*_repos.py`` script imports from this module so that relevance
filtering, subcategory classification, YAML I/O, and text helpers live in
one place.  Signals and subcategory rules are DevSecOps-specific (hardcoded,
matching fetch_new_papers.py).

Usage (import only — not runnable directly):
    from repos_common import is_devops_repo, format_yaml_entry, ...
"""

import re
import yaml
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "REPOS_YAML",
    "_norm",
    "_tokenize",
    "_word_re",
    "is_devops_repo",
    "classify_subcategory",
    "SUBCATEGORY_FALLBACK",
    "_yaml_str",
    "format_yaml_entry",
    "load_existing_repos",
    "append_repos",
    "normalize_entry",
]

BASE = Path(__file__).resolve().parent.parent.parent
REPOS_YAML = BASE / "repos.yaml"


# ── Text helpers ─────────────────────────────────────────────────────────

def _norm(text):
    """Lowercase and collapse whitespace/hyphens/slashes."""
    return re.sub(r"[\s\-/]+", " ", re.sub(r"[-/]", " ", text.lower()))


def _tokenize(text):
    """Split text into individual normalized tokens."""
    return _norm(text).split()


def _word_re(tokens):
    """Build a regex that matches tokens at word boundaries.

    Multi-word tokens (containing spaces) match with a leading ``\\b`` only,
    following the _word_re fix: ``re.escape`` in Python 3.11+ escapes internal
    spaces, so we escape each word individually and join with a literal space.
    No trailing ``\\b`` for multi-word tokens to allow plural/fuzzy matches
    (e.g. "supply chains" matches "supply chain").
    """
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


# ── DevSecOps relevance signals ──────────────────────────────────────────

# Minimal strong signals for repo classification (subset of fetch_new_papers.py)
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

# Pre-compiled for fast matching — loaded on import
_re = _word_re(REPO_STRONG)


def is_devops_repo(name, description, topics):
    """Quick relevance check — gate out obviously irrelevant repos."""
    text = _norm(f"{name} {description} {' '.join(topics)}")
    return bool(_re.search(text))


# ── Subcategory classification ────────────────────────────────────────────

SUBCATEGORY_RULES = [
    ("review", ["survey", "benchmark", "comparison", "awesome", "collection",
                "curated", "list", "catalogue", "directory"], True),
    ("theory", ["framework", "specification", "standard", "rfc", "architecture",
                "model", "ontology", "taxonomy"], False),
    ("security", ["vulnerability", "cve", "exploit", "malware", "threat",
                  "attack", "hardening"], False),
    ("application", ["cli", "tool", "scanner", "analyzer", "detector",
                     "checker", "linter", "parser", "processor", "converter",
                     "engine"], False),
    ("development", ["sdk", "library", "api", "client", "wrapper",
                      "binding", "plugin", "extension", "module", "package"], False),
    ("method", ["template", "boilerplate", "starter", "example", "demo",
                "playground", "tutorial", "cookbook", "guide", "examples"], False),
    ("systems", ["platform", "engine", "orchestrator", "operator",
                 "controller", "runtime", "daemon", "service", "server",
                 "broker", "gateway"], False),
    ("evaluation", ["benchmark", "test-suite", "testbed", "evaluation",
                    "metrics", "dataset", "corpus", "baseline"], False),
]
SUBCATEGORY_FALLBACK = "application"


def classify_subcategory(name, description, topics):
    """Assign subcategory from repo name, description, and topics."""
    text = f"{name} {description} {' '.join(topics)}".lower()
    name_lower = name.lower()
    for subcat, keywords, title_only in SUBCATEGORY_RULES:
        haystack = name_lower if title_only else text
        for kw in keywords:
            if kw in haystack:
                return subcat
    return SUBCATEGORY_FALLBACK


# ── YAML I/O ─────────────────────────────────────────────────────────────

def _yaml_str(s):
    """Escape a string for a double-quoted YAML scalar."""
    if not s:
        return ""
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
    if entry.get("license") and entry["license"] not in ("NOASSERTION", ""):
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
        if lines == ["repos:"]:
            lines = ["repos:"]
        else:
            lines.append("")
    else:
        lines = [
            "# Repositories relevant to DevSecOps research.",
            "# Generated by scripts/fetch/fetch_*_repos.py",
            f"# Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            "",
            "repos:",
        ]

    for entry in entries:
        lines.append(format_yaml_entry(entry))

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ── Entry normalisation ─────────────────────────────────────────────────

def normalize_entry(raw, category, subcategory_hint=None):
    """Convert a source-agnostic dict into a standard repos.yaml entry.

    ``raw`` must contain at least ``name`` and ``url``.  Recognised fields:
      name, url, description, stars, forks, language, topics (list of str),
      pushed_at, created_at, open_issues, license.

    Dates are truncated to YYYY-MM-DD if longer strings are provided.
    """
    subcat = subcategory_hint or classify_subcategory(
        raw.get("name", ""), raw.get("description", ""), raw.get("topics", [])
    )
    return {
        "name": raw.get("name", ""),
        "url": raw.get("url", ""),
        "description": (raw.get("description") or "")[:200],
        "category": category,
        "subcategory": subcat,
        "stars": int(raw.get("stars", 0) or 0),
        "forks": int(raw.get("forks", 0) or 0),
        "language": raw.get("language") or "",
        "topics": sorted(raw.get("topics") or []),
        "pushed_at": str(raw.get("pushed_at", ""))[:10],
        "created_at": str(raw.get("created_at", ""))[:10],
        "open_issues": int(raw.get("open_issues", 0) or 0),
        "license": raw.get("license") or "",
    }
