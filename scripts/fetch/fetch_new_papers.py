#!/usr/bin/env python3
"""Discover DevSecOps research papers from the arXiv API across the DevSecOps taxonomy.

Runs ~90 queries spanning CI/CD, infrastructure-as-code, containers/Kubernetes,
application/software security, AI security, policy-as-code, observability,
GitOps and platform engineering. Each query carries a category (and a
subcategory hint) so new papers are auto-classified into the taxonomy on
discovery. Deduplicates against papers.yaml by arXiv ID / URL / title and
checkpoints every 10 queries so interrupted runs never lose progress.

Usage:
    python3 scripts/fetch/fetch_new_papers.py --months 12 --dry-run
    python3 scripts/fetch/fetch_new_papers.py --months 6 --sleep 1
    python3 scripts/fetch/fetch_new_papers.py --months 3 --create-pr
"""

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
import yaml

ARXIV_ID_PATTERN = re.compile(r"(\d{4}\.\d{4,5})")
ARXIV_SEARCH_API = (
    "https://export.arxiv.org/api/query?search_query={}&start={}&max_results={}"
)

# (query, category, subcategory-hint). Subcategory is refined by keyword scoring
# on title/abstract; the hint is used as a fallback when nothing matches.
QUERIES = [
    # --- security / DevSecOps core ---
    ('cat:cs.CR AND abs:"software supply chain"', "security", "review"),
    ('cat:cs.CR AND abs:"supply chain" AND abs:"software"', "security", "method"),
    ('cat:cs.CR AND abs:"SBOM"', "security", "systems"),
    ('cat:cs.CR AND abs:"software bill of materials"', "security", "systems"),
    ('cat:cs.CR AND abs:"DevSecOps"', "security", "method"),
    ('cat:cs.CR AND abs:"container security"', "security", "systems"),
    ('cat:cs.CR AND abs:"Kubernetes" AND abs:"security"', "security", "systems"),
    ('cat:cs.CR AND abs:"cloud security"', "security", "application"),
    ('cat:cs.CR AND abs:"zero trust"', "security", "theory"),
    ('cat:cs.CR AND abs:"threat modeling"', "security", "method"),
    ('cat:cs.CR AND abs:"vulnerability detection"', "security", "method"),
    ('cat:cs.CR AND abs:"vulnerability prediction"', "security", "method"),
    ('cat:cs.CR AND abs:"static analysis" AND abs:"security"', "security", "method"),
    ('cat:cs.CR AND abs:"fuzzing"', "security", "method"),
    ('cat:cs.CR AND abs:"secret detection"', "security", "method"),
    ('cat:cs.CR AND abs:"security testing"', "security", "method"),
    ('cat:cs.CR AND abs:"penetration testing" AND abs:"automation"', "security", "method"),
    ('cat:cs.CR AND abs:"runtime security"', "security", "systems"),
    ('cat:cs.CR AND abs:"CVE"', "security", "application"),
    ('cat:cs.CR AND abs:"dependency" AND abs:"vulnerability"', "security", "application"),
    ('cat:cs.CR AND abs:"open source" AND abs:"vulnerability"', "security", "application"),
    ('cat:cs.CR AND abs:"detection engineering"', "security", "method"),
    ('cat:cs.CR AND abs:"incident response" AND abs:"automation"', "security", "systems"),
    ('cat:cs.CR AND abs:"cyber" AND abs:"automation"', "security", "systems"),
    ('cat:cs.CR AND abs:"access control" AND abs:"cloud"', "security", "theory"),
    ('cat:cs.CR AND abs:"software signing"', "security", "method"),
    ('cat:cs.CR AND abs:"reproducible builds"', "security", "method"),
    ('cat:cs.CR AND abs:"SLSA"', "security", "systems"),
    ('cat:cs.CR AND abs:"provenance" AND abs:"software"', "security", "systems"),
    ('cat:cs.SE AND abs:"secure software development"', "security", "method"),
    ('cat:cs.SE AND abs:"software security"', "security", "method"),
    ('cat:cs.SE AND abs:"security" AND abs:"agile"', "security", "method"),
    ('cat:cs.SE AND abs:"security champions"', "security", "application"),
    # --- CI/CD ---
    ('cat:cs.SE AND abs:"continuous integration"', "cicd", "method"),
    ('cat:cs.SE AND abs:"continuous delivery"', "cicd", "method"),
    ('cat:cs.SE AND all:"CI/CD"', "cicd", "method"),
    ('cat:cs.SE AND abs:"GitHub Actions"', "cicd", "systems"),
    ('cat:cs.SE AND abs:"build pipeline"', "cicd", "systems"),
    ('cat:cs.SE AND abs:"release engineering"', "cicd", "method"),
    ('cat:cs.SE AND abs:"deployment pipeline"', "cicd", "systems"),
    ('cat:cs.SE AND abs:"build automation"', "cicd", "systems"),
    # --- Infrastructure as code ---
    ('cat:cs.SE AND abs:"infrastructure as code"', "iac", "method"),
    ('cat:cs.SE AND all:"Terraform"', "iac", "application"),
    ('cat:cs.SE AND abs:"Ansible"', "iac", "application"),
    ('cat:cs.SE AND abs:"Pulumi"', "iac", "application"),
    ('cat:cs.SE AND abs:"configuration management" AND abs:"cloud"', "iac", "systems"),
    ('cat:cs.SE AND abs:"declarative" AND abs:"infrastructure"', "iac", "method"),
    ('cat:cs.CR AND abs:"infrastructure as code" AND abs:"security"', "iac", "security"),
    # --- Containers / Kubernetes ---
    ('cat:cs.DC AND abs:"Kubernetes"', "containers", "systems"),
    ('cat:cs.DC AND abs:"container orchestration"', "containers", "systems"),
    ('cat:cs.DC AND abs:"container scheduling"', "containers", "systems"),
    ('cat:cs.DC AND abs:"serverless" AND abs:"container"', "containers", "systems"),
    ('cat:cs.SE AND abs:"microservice"', "containers", "method"),
    ('cat:cs.SE AND abs:"microservices" AND abs:"security"', "containers", "security"),
    ('cat:cs.DC AND abs:"container image"', "containers", "systems"),
    # --- Policy as code / access control ---
    ('cat:cs.CR AND abs:"policy as code"', "policycode", "method"),
    ('cat:cs.SE AND abs:"policy as code"', "policycode", "method"),
    ('cat:cs.CR AND all:"Open Policy Agent"', "policycode", "systems"),
    ('cat:cs.DC AND abs:"Kubernetes" AND abs:"policy"', "policycode", "systems"),
    ('cat:cs.CR AND abs:"attribute-based access control"', "policycode", "theory"),
    ('cat:cs.SE AND abs:"authorization" AND abs:"microservice"', "policycode", "systems"),
    ('cat:cs.CR AND abs:"policy enforcement" AND abs:"cloud"', "policycode", "systems"),
    ('cat:cs.SE AND abs:"RBAC"', "policycode", "systems"),
    # --- Observability ---
    ('cat:cs.SE AND abs:"observability"', "observability", "systems"),
    ('cat:cs.DC AND abs:"telemetry" AND abs:"distributed"', "observability", "systems"),
    ('cat:cs.NI AND abs:"distributed tracing"', "observability", "systems"),
    ('cat:cs.SE AND abs:"OpenTelemetry"', "observability", "systems"),
    ('cat:cs.SE AND abs:"service level objective"', "observability", "evaluation"),
    ('cat:cs.SE AND abs:"monitoring" AND abs:"microservice"', "observability", "systems"),
    ('cat:cs.SE AND abs:"anomaly detection" AND abs:"log"', "observability", "method"),
    # --- GitOps / progressive delivery ---
    ('cat:cs.SE AND all:"GitOps"', "gitops", "method"),
    ('cat:cs.DC AND abs:"GitOps"', "gitops", "systems"),
    ('cat:cs.SE AND abs:"progressive delivery"', "gitops", "method"),
    ('cat:cs.SE AND abs:"canary deployment"', "gitops", "method"),
    ('cat:cs.SE AND abs:"continuous deployment"', "gitops", "method"),
    # --- Platform engineering ---
    ('cat:cs.SE AND abs:"platform engineering"', "platform", "method"),
    ('cat:cs.SE AND abs:"internal developer platform"', "platform", "systems"),
    ('cat:cs.SE AND abs:"developer portal"', "platform", "systems"),
    ('cat:cs.SE AND abs:"developer experience"', "platform", "application"),
    ('cat:cs.SE AND abs:"platform team"', "platform", "application"),
    # --- AI / LLM security (DevOps-anchored: LLM/AI papers are only kept
    # when they touch code, pipelines, infra, supply chains or agent tooling) ---
    ('cat:cs.CR AND abs:"prompt injection" AND (abs:"code" OR abs:"software" OR abs:"tool")', "ai-security", "method"),
    ('cat:cs.CR AND abs:"prompt injection" AND abs:"agent" AND (abs:"workflow" OR abs:"automation" OR abs:"deployment")', "ai-security", "method"),
    ('cat:cs.CR AND abs:"LLM" AND abs:"software supply chain"', "ai-security", "systems"),
    ('cat:cs.CR AND abs:"LLM" AND abs:"vulnerability" AND (abs:"code" OR abs:"software" OR abs:"repository")', "ai-security", "method"),
    ('cat:cs.CR AND abs:"large language model" AND abs:"vulnerability" AND (abs:"code" OR abs:"software")', "ai-security", "method"),
    ('cat:cs.SE AND (abs:"AI coding assistant" OR abs:"coding assistant") AND abs:"security"', "ai-security", "application"),
    ('cat:cs.SE AND abs:"LLM" AND abs:"code review"', "ai-security", "application"),
    ('cat:cs.CR AND all:"Model Context Protocol" AND (abs:"security" OR abs:"attack" OR abs:"integration" OR abs:"tool")', "ai-security", "systems"),
    ('cat:cs.SE AND abs:"AI" AND (abs:"pipeline" OR abs:"continuous integration" OR all:"CI/CD")', "ai-security", "method"),
    ('cat:cs.CR AND abs:"AI agent" AND abs:"security" AND (abs:"tool" OR abs:"automation" OR abs:"deployment" OR abs:"platform")', "ai-security", "method"),
    ('cat:cs.CR AND abs:"agent" AND abs:"supply chain"', "ai-security", "systems"),
    ('cat:cs.CR AND abs:"LLM" AND (abs:"deployment" OR abs:"runtime" OR abs:"cloud") AND abs:"security"', "ai-security", "systems"),
    ('cat:cs.SE AND abs:"LLM" AND abs:"DevSecOps"', "ai-security", "method"),
    ('cat:cs.SE AND (abs:"AIOps" OR abs:"agentic operations")', "ai-security", "application"),
    # --- DevOps practices / empirical ---
    ('cat:cs.SE AND abs:"DevOps" AND abs:"security"', "security", "method"),
    ('cat:cs.SE AND abs:"DevOps" AND abs:"survey"', "security", "review"),
    ('cat:cs.SE AND abs:"DevOps" AND abs:"practices"', "security", "review"),
    ('cat:cs.SE AND abs:"software maintenance" AND abs:"security"', "security", "method"),
]

# Subcategory keyword rules, applied in order. First match wins.
# Each rule: (subcategory, keywords, title_only?) — title_only restricts
# matching to the paper title (for strong signals like "survey").
SUBCATEGORY_RULES = [
    ("review", ["survey", "systematic review", "state-of-the-art", "sota", "overview of"], True),
    ("review", ["a survey of", "review of", "bibliographic review", "mapping study"], False),
    ("theory", ["threat model", "formal", "theoretical", "complexity", "bounds", "fundamental limits", "axiomat", "formal verification", "security properties"], False),
    ("security", ["vulnerability", "cve", "exploit", "attack", "malware", "threat", "compromise", "intrusion", "anomaly", "penetration"], False),
    ("application", ["case study", "real-world", "in practice", "production", "industrial", "empirical study", "deployment", "adoption", "practitioners"], False),
    ("development", ["open-source", "library", "toolkit", "implementation of", "software package", "python library", "framework"], False),
    ("mechanism", ["interpretab", "explainab", "analysis of", "inner workings", "probing", "mechanism", "root cause", "taxonomy of"], False),
    ("systems", ["system", "engine", "platform", "pipeline", "architecture", "distributed", "scalable", "orchestration", "runtime", "agent"], False),
    ("evaluation", ["benchmark", "empirical comparison", "experimental evaluation", "evaluating", "comparative analysis", "dataset", "measurement"], False),
]

SUBCATEGORY_FALLBACK = "method"

CATEGORIES = {
    "security", "cicd", "iac", "containers", "policycode",
    "observability", "gitops", "platform", "ai-security",
}

# ---- DevOps-relevance filter (shared with scripts/reclassify_papers.py) ----
# LLM/AI-agent papers are only allowed into the corpus when they carry
# DevOps context. Kept here (the house pattern) so both the fetch scripts
# and the reclassification pass use identical rules.

LLM_SIGNALS = [
    "llm", "large language model", "gpt-", "gpt4", "gpt 4", "chatgpt", "copilot",
    "prompt injection", "jailbreak", "model context protocol", "mcp",
    "ai agent", "ai agents", "agentic", "autonomous agent", "multi-agent",
    "multi agent", "ai assistant", "ai coding", "code assistant",
    "foundation model", "foundation models", "ai-generated", "ai generated",
    "ai-powered", "ai powered", "ai-driven", "ai driven", "llm-based",
    "llm based", "llm-powered", "llm powered", "aiops", "ai-ops",
    "ai-assisted", "ai assisted",]

DEVOPS_STRONG = [
    "ci/cd", "continuous integration", "continuous delivery", "continuous deployment",
    "github actions", "gitlab", "jenkins", "devsecops", "devops", "sre",
    "site reliability", "infrastructure as code", "terraform", "ansible",
    "policy as code",
    "kubernetes", "k8s", "docker", "container", "containerization",
    "orchestration", "serverless", "microservice", "cloud", "cloud-native",
    "cloud native", "observability", "telemetry", "opentelemetry",
    "distributed tracing", "gitops", "progressive delivery", "canary",
    "deployment", "deploy", "release engineering", "software supply chain",
    "supply chain", "sbom", "software bill of materials", "dependency",
    "package manager", "package registry", "software signing", "provenance",
    "code review", "code generation", "code completion", "coding assistant",
    "code assistant", "static analysis", "secure coding", "software composition",
    "runtime security", "sandbox", "plugin", "extension", "ide",
    "developer tool", "platform engineering", "internal developer platform",
    "idp", "backstage", "incident response", "security operations", "soc",
    "workflow automation", "build pipeline", "build system", "release process",
    "aops", "agentic operations", "software engineering", "software development",
    "open source software", "open-source software", "code repository",
    "source code", "software deployment", "model deployment", "mlops",
    "slsa", "reproducible builds", "threat modeling", "detection engineering",
    "secure software development", "secret detection",
]

# Medium: DevOps-adjacent context — specific enough to imply a DevSecOps
# domain when ≥2 are present. Generic CS terms (software, code, tool, api,
# vulnerability, program, developer) are intentionally EXCLUDED because they
# match nearly every paper and made the threshold trivially satisfiable.
DEVOPS_MEDIUM = [
    "repository", "maintainer", "commit", "pull request",
    "runtime", "build", "release", "automation", "workflow",
    "cve", "attack surface", "malware", "security testing",
    "penetration testing", "fuzzing", "secrets",
    "application security", "secure development", "software quality",
    "open source", "logging", "log analysis", "log anomaly", "log parsing",
]


def _norm(text: str) -> str:
    """Lowercase and normalize - and / to spaces so 'policy-as-code' matches
    'policy as code', 'ci/cd' matches 'ci cd', etc."""
    return re.sub(r"[\s-]+", " ", re.sub(r"[-/]", " ", text.lower()))


def _word_re(tokens: list[str]) -> re.Pattern:
    """Case-insensitive regex with word boundaries.

    Single-word tokens get \b on both sides (prevents 'ide' matching 'idea',
    'build' matching 'rebuilding', 'soc' matching 'society').
    Multi-word tokens get \b only at the start so 'supply chain' matches
    'supply chains' and 'software supply chain' (plural trailing s).
    Tokens are normalized (hyphens/slashes -> spaces) so 'gpt-4' matches
    'gpt 4'.
    """
    normed = [_norm(t) for t in tokens]
    parts = []
    for s in normed:
        words = s.split(" ")
        escaped = [re.escape(w) for w in words]
        if len(escaped) == 1:
            parts.append(r"\b" + escaped[0] + r"\b")
        else:
            # No trailing \b so plurals like 'supply chains' still match
            parts.append(r"\b" + " ".join(escaped))
    return re.compile(r"|".join(parts), re.I)


llm_re = _word_re(LLM_SIGNALS)
strong_re = _word_re(DEVOPS_STRONG)
medium_re = _word_re(DEVOPS_MEDIUM)


def is_llm_paper(p) -> bool:
    text = _norm(f"{p.get('title','')} {p.get('abstract','')}")
    return bool(llm_re.search(text))


def devops_relevance(p) -> tuple[bool, int, int]:
    """Return (relevant, n_strong, n_medium) for LLM papers."""
    text = _norm(f"{p.get('title','')} {p.get('abstract','')}")
    strong = len(set(strong_re.findall(text)))
    medium = len(set(medium_re.findall(text)))
    relevant = strong >= 1 or medium >= 2
    return relevant, strong, medium


def devops_filter(entry) -> bool:
    """True when the entry may enter the corpus: either not an LLM/AI paper,
    or an LLM/AI paper with DevOps context."""
    return not is_llm_paper(entry) or devops_relevance(entry)[0]


def is_devops_paper(entry) -> bool:
    """True when the entry carries DevOps context (regardless of LLM status).

    Used by broad-semantic fetchers (OpenAlex) where search results are not
    category-restricted. Unlike devops_filter (which lets non-LLM papers
    through unconditionally), this gates ALL papers through the DevOps
    relevance check.
    """
    return devops_relevance(entry)[0]


def classify_subcategory(title, abstract):
    """Assign a subcategory using keyword rules against title + abstract."""
    t_lower = title.lower()
    text = f"{title} {abstract}".lower()
    for subcat, keywords, title_only in SUBCATEGORY_RULES:
        haystack = t_lower if title_only else text
        for kw in keywords:
            if kw in haystack:
                return subcat
    return SUBCATEGORY_FALLBACK


def load_existing_papers(yaml_path):
    if not yaml_path.exists():
        return {}, []
    with open(yaml_path, "r") as f:
        data = yaml.safe_load(f) or {}
    papers = data.get("papers", [])
    by_id = {}
    titles_lower = []
    for p in papers:
        url = p.get("url", "")
        match = ARXIV_ID_PATTERN.search(url)
        if match:
            by_id[match.group(1)] = p
        titles_lower.append(p.get("title", "").lower().strip())
    return by_id, titles_lower


def search_arxiv(query, months, start=0, max_results=100, max_retries=4):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(days=months * 30)
    date_start = cutoff.strftime("%Y%m%d0000")
    date_end = now.strftime("%Y%m%d") + "2359"

    full_query = f"({query}) AND submittedDate:[{date_start} TO {date_end}]"
    try:
        resp = None
        for attempt in range(max_retries):
            resp = requests.get(
                ARXIV_SEARCH_API.format(
                    requests.utils.quote(full_query), start, max_results
                ),
                timeout=30,
            )
            if resp.status_code == 429:
                wait = 8 * (attempt + 1)
                print(f"    rate-limited (429), waiting {wait}s...", flush=True)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            break
        if resp is None:
            return []
        if resp.status_code != 200:
            print(f"  WARNING: arXiv returned HTTP {resp.status_code}", flush=True)
            return []
        entries = []
        root = resp.text
        for match in re.finditer(r"<entry>(.*?)</entry>", root, re.DOTALL):
            entry_xml = match.group(1)
            entry = {}
            title_m = re.search(r"<title>(.*?)</title>", entry_xml, re.DOTALL)
            if title_m:
                entry["title"] = re.sub(r"\s+", " ", title_m.group(1).strip())
            id_m = re.search(r"<id>(.*?)</id>", entry_xml)
            if id_m:
                entry["url"] = id_m.group(1).strip().replace("http://", "https://")
            published_m = re.search(r"<published>(.*?)</published>", entry_xml)
            if published_m:
                entry["date"] = published_m.group(1).strip()[:7]
            summary_m = re.search(r"<summary>(.*?)</summary>", entry_xml, re.DOTALL)
            if summary_m:
                entry["abstract"] = re.sub(r"\s+", " ", summary_m.group(1).strip())
            authors_m = re.findall(r"<name>(.*?)</name>", entry_xml)
            if authors_m:
                entry["authors"] = [a.strip() for a in authors_m][:3]
            if entry.get("title") and entry.get("url"):
                entries.append(entry)
        return entries
    except Exception as e:
        print(f"  WARNING: arXiv search error: {e}", flush=True)
        return []


def _yaml_str(s: str) -> str:
    """Escape a string for a double-quoted YAML scalar."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def format_yaml_entry(entry, category, subcategory):
    title = _yaml_str(entry["title"])
    # Quote every author: names may start with YAML flow indicators
    # (*, &, @, !, ...) which are alias/anchor/tag syntax inside [...]
    authors = ", ".join(_yaml_str(a) for a in entry.get("authors", [])[:3])
    lines = [
        f'  - title: "{title}"',
        f'    date: "{entry.get("date", "")}"',
        f'    url: "{entry.get("url", "")}"',
        f"    category: {category}",
        f"    subcategory: {subcategory}",
        f"    authors: [{authors}]",
    ]
    if entry.get("abstract"):
        abstract = _yaml_str(entry["abstract"][:200])
        lines.append(f'    abstract: "{abstract}..."')
    if entry.get("venue"):
        lines.append(f'    venue: "{_yaml_str(entry["venue"])}"')
    return "\n".join(lines)


def append_papers(yaml_path, entries):
    """Append entries to papers.yaml (creating it if needed)."""
    # Seed file may be `papers: []` — convert to a block list before appending
    if yaml_path.exists():
        text = yaml_path.read_text(encoding="utf-8").rstrip()
        if text.endswith("papers: []"):
            text = text[: -len("papers: []")].rstrip() + "\npapers:"
        if not text.endswith("\n"):
            text += "\n"
    else:
        text = (
            "# DevSecOps research paper corpus (auto-discovered from arXiv/OpenAlex).\n"
            "# Categories: security | cicd | iac | containers | policycode |\n"
            "#             observability | gitops | platform | ai-security\n"
            "papers:"
        )
    entries_text = "\n".join(format_yaml_entry(e, e["category"], e["subcategory"])
                             for e in entries)
    with open(yaml_path, "w", encoding="utf-8") as f:
        f.write(text + "\n" + entries_text + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Discover DevSecOps research papers from arXiv"
    )
    parser.add_argument(
        "--months",
        type=int,
        default=12,
        help="Search papers from the last N months (default: 12)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview without creating anything"
    )
    parser.add_argument(
        "--create-pr", action="store_true", help="Create a GitHub PR with new papers"
    )
    parser.add_argument(
        "--sleep", type=float, default=1.5, help="Seconds between queries"
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=100,
        help="Max results per arXiv query (default: 100)",
    )
    parser.add_argument(
        "--from",
        dest="from_idx",
        type=int,
        default=0,
        help="Start at query index (0-based, inclusive)",
    )
    parser.add_argument(
        "--to",
        dest="to_idx",
        type=int,
        default=None,
        help="Stop at query index (0-based, inclusive)",
    )
    args = parser.parse_args()

    yaml_path = Path(__file__).resolve().parent.parent.parent / "papers.yaml"
    by_id, titles_lower = load_existing_papers(yaml_path)

    print(f"Loaded {len(by_id)} existing papers from papers.yaml", flush=True)
    print(
        f"Searching arXiv ({len(QUERIES)} queries) for papers from the last {args.months} month(s)...",
        flush=True,
    )

    all_new = []
    CHECKPOINT_EVERY = 10
    to_idx = args.to_idx if args.to_idx is not None else len(QUERIES) - 1
    for qi, qdef in enumerate(QUERIES[args.from_idx:to_idx + 1], start=args.from_idx):
        if len(qdef) == 4:
            query, category, hint, force_sub = qdef
        else:
            query, category, hint = qdef
            force_sub = None
        print(f"Query {qi + 1}/{len(QUERIES)} [{category}] {query[:70]}", flush=True)
        entries = search_arxiv(query, args.months, max_results=args.max_results)
        for entry in entries:
            arxiv_id_match = ARXIV_ID_PATTERN.search(entry.get("url", ""))
            arxiv_id = arxiv_id_match.group(1) if arxiv_id_match else None

            if arxiv_id and arxiv_id in by_id:
                continue

            title_lower = entry.get("title", "").lower().strip()
            if any(title_lower == t for t in titles_lower):
                continue

            if arxiv_id and any(e.get("url", "") == entry["url"] for e in all_new):
                continue

            entry["category"] = category
            entry["subcategory"] = force_sub or classify_subcategory(
                entry.get("title", ""), entry.get("abstract", "")
            )
            # DevOps-relevance gate: LLM/AI papers without DevOps context
            # never enter the corpus (same rule as scripts/reclassify_papers.py)
            if not devops_filter(entry):
                continue
            all_new.append(entry)
            by_id[arxiv_id] = entry
            titles_lower.append(title_lower)

        # Incremental checkpoint so partial runs are never lost
        if not args.dry_run and all_new and (qi + 1) % CHECKPOINT_EVERY == 0:
            append_papers(yaml_path, all_new)
            print(f"  [checkpoint] saved {len(all_new)} papers so far", flush=True)
            all_new = []
            by_id, titles_lower = load_existing_papers(yaml_path)

        time.sleep(args.sleep)

    print(
        f"\nFound {len(all_new)} new papers ({len(by_id)} already in list)", flush=True
    )

    if not all_new:
        print("No new papers to add.", flush=True)
        return

    print("\n--- New Papers (first 10) ---", flush=True)
    for entry in all_new[:10]:
        print(format_yaml_entry(entry, entry["category"], entry["subcategory"]), flush=True)
        print(flush=True)
    print(f"... and {max(0, len(all_new) - 10)} more", flush=True)

    if args.dry_run:
        print("\nDry run complete — no files modified", flush=True)
        return

    if args.create_pr:
        branch_name = f"add-new-papers-{datetime.now().strftime('%Y%m%d')}"
        print(f"\nCreating branch '{branch_name}' and PR...", flush=True)
        try:
            subprocess.run(
                ["git", "checkout", "-b", branch_name], check=True, cwd=yaml_path.parent
            )
            append_papers(yaml_path, all_new)
            subprocess.run(["git", "add", "papers.yaml"], check=True, cwd=yaml_path.parent)
            subprocess.run(
                ["git", "commit", "-m", f"Add {len(all_new)} new papers from arXiv discovery"],
                check=True,
                cwd=yaml_path.parent,
            )
            subprocess.run(
                ["git", "push", "origin", branch_name], check=True, cwd=yaml_path.parent
            )
            subprocess.run(
                [
                    "gh", "pr", "create",
                    "--title", f"Add {len(all_new)} new papers from arXiv discovery",
                    "--body", "Automatically discovered papers.\n\n**Please review taxonomy assignments.**",
                ],
                check=True,
                cwd=yaml_path.parent,
            )
            print("PR created successfully!", flush=True)
        except subprocess.CalledProcessError as e:
            print(f"ERROR: PR creation failed: {e}", flush=True)
            sys.exit(1)
    else:
        append_papers(yaml_path, all_new)
        print(f"\nAppended {len(all_new)} papers to {yaml_path.name}", flush=True)


if __name__ == "__main__":
    main()