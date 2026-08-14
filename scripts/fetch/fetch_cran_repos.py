#!/usr/bin/env python3
"""Discover DevSecOps-relevant CRAN (R) packages and append to repos.yaml.

Uses a two-phase approach:

Phase 1 (Task Views — primary, curated):
  Scrapes CRAN Task Views known to contain DevSecOps-relevant packages.
  Each Task View is curated by domain experts. Packages are enriched
  via crandb.r-pkg.org for full Title/Description metadata.

Phase 2 (Full CRAN scan — secondary, broader):
  Scans the PACKAGES index with a strict name/dependency pre-filter,
  then enriches matching candidates via crandb for relevance scoring.

Usage:
    python3 scripts/fetch/fetch_cran_repos.py --dry-run
    python3 scripts/fetch/fetch_cran_repos.py --task-views-only --dry-run
    python3 scripts/fetch/fetch_cran_repos.py --skip-task-views --dry-run
    python3 scripts/fetch/fetch_cran_repos.py --from 0 --to 3
"""

import argparse
import re
import sys
import time
from collections import Counter
from pathlib import Path

import requests
import yaml

from repos_common import (
    REPOS_YAML,
    _norm,
    _word_re,
    load_existing_repos,
    append_repos,
)

CRAN_MIRROR = "https://cran.r-project.org"
CRANDB_API = "https://crandb.r-pkg.org"
USER_AGENT = "Research-Corpus/1.0 (mailto:research@tobias-weiss-ai-xr.de)"

# ── CRAN-relevant Task Views for DevSecOps ────────────────────────────────
CRAN_TASK_VIEWS = [
    ("AnomalyDetection",       "observability", "Outlier/anomaly detection for monitoring"),
    ("NetworkAnalysis",        "security",      "Graph/network analysis for security"),
    ("MachineLearning",       "ai-security",   "ML models used in security/AIOps"),
    ("ModelDeployment",        "cicd",          "Model CI/CD and deployment pipelines"),
    ("ReproducibleResearch",  "cicd",          "Reproducible builds, CI/CD in R"),
    ("NaturalLanguageProcessing", "observability", "NLP for log/text analysis"),
    ("HighPerformanceComputing", "platform",    "HPC/parallel infrastructure"),
    ("TimeSeries",             "observability", "Time series analysis for monitoring"),
    ("Bayesian",               "security",      "Bayesian risk/threat analysis"),
    ("Distributions",          "security",      "Statistical distributions for risk modeling"),
    ("Databases",              "platform",      "Database tools, data engineering"),
    ("Optimization",           "platform",      "Resource optimization for infrastructure"),
    ("Robust",                 "security",      "Robust statistical methods"),
    ("ExtremeValue",           "observability", "Extreme value theory for anomaly detection"),
    ("Survival",               "security",      "Survival/failure analysis for reliability"),
    ("WebTechnologies",       "platform",      "Web technologies, APIs, HTTP services"),
    ("Finance",                "security",      "Risk modeling, compliance, fraud detection"),
    ("Cluster",                "platform",      "Clustering, distributed computing"),
    ("GraphicalModels",        "security",      "Graphical models for security analysis"),
    ("Tracking",               "observability", "Object/state tracking for monitoring"),
]

# ── Strict name pre-filter patterns for full CRAN scan ────────────────────
# Must match known DevSecOps-relevant R packages by name.
# Kept intentionally tight to limit crandb API calls.

STRICT_NAME_PATTERNS = [
    r"^openssl$", r"^sodium$", r"^jose$", r"^digest$",
    r"^bcrypt$", r"^argon2i$",
    r"^pki$", r"^x509$", r"^certifi$",
    r"^keyring$", r"^secret$",
    r"^jwt$", r"^jwtio$", r"^jose4j$",
    r"^oauth$",
    r"^password$",
    r"^encryptr$", r"^decryptr$",
    r"^git2r$", r"^gert$", r"^gh$",
    r"^gitlabr$",
    r"^renv$", r"^pak$",
    r"^httr$", r"^httr2$", r"^curl$", r"^crul$",
    r"^prometheus$", r"^grafana$",
    r"^docker$", r"^containerit$", r"^harbor$",
    r"^plumber$", r"^swagger$", r"^openapi$",
    r"^opencpu$",
    r"^vetiver$", r"^mlflow$",
    r"^testthat$", r"^covr$", r"^lintr$",
    r"^rcmdcheck$", r"^pkgbuild$", r"^desc$",
    r"^styler$", r"^goodpractices$",
    r"^devtools$", r"^remotes$", r"^usethis$",
    r"^roxygen2$", r"^roxygen$",
    r"^assertthat$", r"^checkmate$", r"^attach$",
    r"^dbi$", r"^pool$", r"^odbc$",
    r"^logger$", r"^futile.logger$",
    r"^anomalize$", r"^tsoutliers$",
    r"^strchange$", r"^breakfast$",
    r"^drift$",
    r"^rlimiter$", r"^ratelimitry$",
    r"^htmlwidgets$",
    r"^shiny$", r"^golem$",
    r"^igraph$",
    r"^network$", r"^sna$",
    r"^aws$", r"^paws$",
    r"^azure$",
    r"^googlecloud$",
    r"^sparklyr$",
    r"^arrow$",
    r"^rmarkdown$", r"^knitr$",
    r"^quarto$",
    r"^targets$", r"^drake$",
    r"^here$", r"^fs$",
    r"^cron$", r"^taskschedule$",
    r"^processx$",
    r"^later$", r"^callr$",
    r"^httr$", r"^webutils$",
    r"^httpcode$",
    r"^trycatchlog$",
    r"^errorhandle$",
    r"^conditionmessage$",
    r"^lifecycle$",
]

# DevSecOps imports that strongly signal relevance (only for the
# full-scan pre-filter; used when the package name alone doesn't match)
SECURITY_IMPORTS = [
    "openssl", "sodium", "jose",
    "bcrypt", "argon2i", "encryptr",
    "pki", "keyring", "secret",
    "jwt",
    "prometheus", "docker", "containerit",
    "plumber", "swagger", "openapi",
    "renv", "vetiver", "mlflow",
]

# ── Relevance signals for enriched data ───────────────────────────────────
CRAN_STRONG = [
    # --- Core DevSecOps ---
    "ci cd", "continuous integration", "continuous delivery",
    "devsecops", "devops", "sre", "site reliability",
    "infrastructure as code", "policy as code", "gitops",
    "platform engineering",
    "software supply chain", "sbom", "software bill of materials",
    "sast", "static analysis", "dast", "dynamic analysis",
    "sca", "software composition analysis",
    "vulnerability", "vulnerability assessment",
    "secret detection", "secrets scanning", "zero trust",
    # --- Security / Crypto ---
    "cryptography", "encryption", "decryption", "cipher",
    "hash", "hashing", "digest",
    "certificate", "ssl", "tls", "https", "pki",
    "authentication", "authorization", "oauth", "jwt",
    "public key", "private key", "rsa", "aes", "gpg", "pgp",
    "ssh", "secure shell",
    "firewall", "intrusion", "malware", "exploit",
    "penetration", "pentest", "security audit",
    "compliance", "risk assessment", "threat modeling",
    "owasp", "cve",
    "role based access", "rbac", "access control",
    "digital signature", "code signing",
    # --- Observability ---
    "anomaly detection", "outlier detection", "novelty detection",
    "monitoring", "alert", "telemetry", "observability",
    "time series", "log analysis",
    "prometheus", "grafana", "opentelemetry",
    "distributed tracing", "profiling",
    "change point", "change detection", "fault detection",
    # --- Containers ---
    "docker", "container", "kubernetes",
    # --- CI/CD ---
    "reproducible research", "reproducible analysis",
    "unit test", "coverage", "code quality", "linting",
    "continuous deployment", "model deployment", "mlops",
    # --- Network ---
    "network analysis", "network security", "network monitoring",
    "distributed computing", "parallel computing",
    # --- Data ---
    "data pipeline", "etl", "database", "data validation",
    "api", "rest api", "web api",
    # --- AI/ML Security ---
    "adversarial", "robustness", "model security",
    "explainability", "privacy preserving", "federated learning",
]

_re_cran = _word_re(CRAN_STRONG)

# ── crandb cache ──────────────────────────────────────────────────────────
_crandb_cache: dict[str, dict | None] = {}


def enrich_from_crandb(pkg_name: str,
                        session: requests.Session | None = None) -> dict | None:
    """Fetch full DESCRIPTION metadata from crandb.r-pkg.org."""
    if pkg_name in _crandb_cache:
        return _crandb_cache[pkg_name]
    s = session or requests.Session()
    url = f"{CRANDB_API}/{pkg_name}"
    try:
        resp = s.get(url, timeout=15, headers={"User-Agent": USER_AGENT})
        if resp.status_code != 200:
            _crandb_cache[pkg_name] = None
            return None
        data = resp.json()
    except Exception:
        _crandb_cache[pkg_name] = None
        return None

    result = {
        "name": pkg_name,
        "title": data.get("Title", "").replace("\n", " "),
        "description": data.get("Description", "").replace("\n", " "),
        "license": _clean_license(data.get("License", "")),
        "published": (data.get("Date/Publication", "") or "")[:10],
        "reverse_depends_count": 0,
    }
    _crandb_cache[pkg_name] = result
    return result


def enrich_bulk_from_crandb(packages: list[dict],
                            delay: float = 0.3) -> list[dict]:
    """Enrich packages with crandb data."""
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    enriched = []
    for i, pkg in enumerate(packages):
        name = pkg["name"]
        data = enrich_from_crandb(name, s)
        if data:
            pkg["title"] = data["title"]
            pkg["description"] = data["description"]
            pkg["published"] = data["published"] or pkg["published"]
            pkg["license"] = data["license"] or pkg["license"]
        enriched.append(pkg)
        if (i + 1) % 25 == 0:
            print(f"    enriched {i+1}/{len(packages)}...", flush=True)
        if delay > 0 and i < len(packages) - 1:
            time.sleep(delay)
    return enriched


# ── PACKAGES file parser ──────────────────────────────────────────────────

def parse_packages_index(text: str) -> list[dict]:
    """Parse the CRAN PACKAGES file (Debian-style DESCRIPTION blocks).

    NOTE: No Title/Description — populated via crandb enrichment.
    """
    packages = []
    blocks = re.split(r"\n\n+", text.strip())
    for block in blocks:
        if not block.strip():
            continue
        fields = {}
        current_key = None
        current_val = []
        for line in block.split("\n"):
            if line.startswith(" ") and current_key:
                current_val.append(line.strip())
            elif ":" in line:
                if current_key:
                    fields[current_key] = " ".join(current_val)
                key, _, val = line.partition(":")
                current_key = key.strip()
                current_val = [val.strip()]
        if current_key:
            fields[current_key] = " ".join(current_val)
        pkg_name = fields.get("Package", "").strip()
        if not pkg_name:
            continue
        published = fields.get("Published", "")
        packages.append({
            "name": pkg_name,
            "version": fields.get("Version", ""),
            "title": "",
            "description": "",
            "depends": fields.get("Depends", ""),
            "imports": fields.get("Imports", ""),
            "suggests": fields.get("Suggests", ""),
            "license": _clean_license(fields.get("License", "")),
            "published": published[:10] if len(published) >= 10 else "",
            "reverse_depends_count": 0,
        })
    return packages


def _clean_license(license_str: str) -> str:
    if not license_str:
        return ""
    s = license_str.strip()
    for pattern, replacement in [
        (r"GPL\s*\(\s*>=\s*\d+[\.\d]*\s*\)", "GPL"),
        (r"GPL\s*\(\s*\d+[\.\d]*\s*\)", "GPL"),
        (r"LGPL\s*\(\s*>=\s*\d+[\.\d]*\s*\)", "LGPL"),
        (r"LGPL\s*\(\s*\d+[\.\d]*\s*\)", "LGPL"),
        (r"MIT \+ file LICENSE", "MIT"),
        (r"Apache License\s*\(.*?\)", "Apache-2.0"),
        (r"BSD[_ ]?2[_ -]?Clause", "BSD-2-Clause"),
        (r"BSD[_ ]?3[_ -]?Clause", "BSD-3-Clause"),
    ]:
        s = re.sub(pattern, replacement, s, flags=re.I)
    if "|" in s:
        s = s.split("|")[0].strip()
    if "+" in s:
        s = s.split("+")[0].strip()
    return s.strip() or s


# ── Task View scraper ────────────────────────────────────────────────────

def scrape_task_view_packages(view_name: str) -> list[str]:
    """Extract CRAN package names from a Task View HTML page."""
    url = f"{CRAN_MIRROR}/web/views/{view_name}.html"
    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
    except Exception as exc:
        print(f"  WARNING: Could not fetch Task View '{view_name}': {exc}")
        return []

    html = resp.text
    pattern = r'class="CRAN"[^>]*>\s*([A-Za-z0-9][\w.-]*)\s*<'
    matches = re.findall(pattern, html)
    if not matches:
        href_pattern = r'href="[^"]*packages/([A-Za-z0-9][\w.-]*)/'
        matches = sorted(set(re.findall(href_pattern, html)))
    return sorted(set(matches))


# ── Classification helpers ────────────────────────────────────────────────

def is_devsecops_package(name, title, description, imports=None):
    """Check relevance using keyword signals."""
    parts = [name, title, description]
    if imports:
        parts.append(imports)
    text = _norm(" ".join(parts))
    return bool(_re_cran.search(text))


def _classify_category(name: str, title: str, description: str,
                       imports: str) -> str:
    """Determine primary DevSecOps category from strongest signal."""
    text = _norm(f"{name} {title} {description} {imports}")
    category_signals = [
        ("security",     [r"\bsecurity\b", r"\bvulnerabilit", r"\bcryptograph",
                         r"\bencrypt", r"\bauthenticat", r"\bauthoriz",
                         r"\bcipher", r"\bssl\b", r"\btls\b",
                         r"\bpenetrat", r"\bexploit", r"\bmalware",
                         r"\bthreat\b", r"\bcompliance", r"\baudit\b",
                         r"\brisk\b", r"\bcertificate", r"\bsignature",
                         r"\boauth", r"\btokeni"]),
        ("ai-security",  [r"\badversarial", r"\brobustness", r"\bexplainab",
                         r"\bfederated.learn", r"\bdifferential.privacy"]),
        ("observability",[r"\banomaly", r"\boutlier", r"\bnovelty.detect",
                         r"\bmonitoring", r"\balert", r"\btelemetry",
                         r"\bobservab", r"\btime.seri", r"\blog.analys",
                         r"\bchange.point", r"\bfault.detect"]),
        ("cicd",         [r"\bci.cd", r"\bcontinuous.integrat",
                         r"\bcontinuous.deliver", r"\breproducible",
                         r"\bcoverage", r"\bunit.test", r"\bmodel.deploy",
                         r"\bmlops", r"\bdeployment", r"\blint"]),
        ("containers",   [r"\bdocker", r"\bcontainer", r"\bkubernetes",
                         r"\borchestrat", r"\bmicroservice", r"\bservice.mesh"]),
        ("platform",     [r"\bplatform.engineer", r"\bcluster",
                         r"\bdistributed.comput", r"\bparallel.comput",
                         r"\bhigh.performance", r"\bscalab"]),
    ]
    best_cat = "security"
    best_score = 0
    for cat, patterns in category_signals:
        score = sum(1 for p in patterns if re.search(p, text, re.I))
        if score > best_score:
            best_score = score
            best_cat = cat
    return best_cat


def _classify_cran_subcategory(name: str, title: str,
                               description: str) -> str:
    text = f"{name} {title} {description}".lower()
    rules = [
        ("review",      ["survey", "benchmark", "comparison", "collection",
                         "curated", "overview"]),
        ("theory",      ["framework", "specification", "standard", "model",
                         "theory", "methodology"]),
        ("security",    ["vulnerability", "cve", "exploit", "malware",
                         "threat", "attack", "hardening", "cryptography",
                         "encryption", "cipher", "hash"]),
        ("application", ["cli", "tool", "scanner", "analyzer", "detector",
                         "checker", "linter", "parser", "processor",
                         "converter", "engine", "package", "library"]),
        ("development", ["sdk", "api", "client", "wrapper", "binding",
                         "plugin", "extension", "module"]),
        ("method",      ["template", "starter", "example", "demo",
                         "tutorial", "cookbook", "guide"]),
        ("systems",     ["platform", "orchestrator", "operator",
                         "controller", "runtime", "daemon", "service",
                         "server", "broker", "gateway"]),
        ("evaluation",  ["benchmark", "test", "evaluation", "metrics",
                         "dataset", "corpus", "baseline"]),
    ]
    for subcat, keywords in rules:
        for kw in keywords:
            if kw in text:
                return subcat
    return "application"


def _extract_topics(text: str) -> list[str]:
    text_lower = text.lower()
    topics = []
    topic_map = {
        "cryptography": ["cryptography", "encryption", "cipher", "hash"],
        "authentication": ["authentication", "authorization", "oauth"],
        "anomaly-detection": ["anomaly detection", "outlier detection"],
        "network-analysis": ["network analysis", "graph analysis"],
        "time-series": ["time series"],
        "monitoring": ["monitoring", "alert"],
        "machine-learning": ["machine learning", "deep learning"],
        "model-deployment": ["model deployment", "mlops"],
        "docker": ["docker", "container"],
        "database": ["database", "sql"],
        "api": ["rest", "web service", "api"],
        "testing": ["unit test", "test", "coverage"],
        "reproducible": ["reproducible"],
        "security": ["security", "vulnerability", "exploit"],
        "privacy": ["privacy", "differential privacy", "federated"],
    }
    for topic, keywords in topic_map.items():
        if any(kw in text_lower for kw in keywords):
            topics.append(topic)
    return sorted(topics)


def cran_to_yaml_entry(pkg: dict, category: str,
                       source: str = "cran") -> dict:
    url = f"{CRAN_MIRROR}/web/packages/{pkg['name']}"
    title = pkg.get("title", "")
    description = pkg.get("description", "")
    desc_text = f"{title}. {description}" if title and description else title or description

    entry = {
        "name": pkg["name"],
        "url": url,
        "description": desc_text[:200],
        "category": category,
        "subcategory": _classify_cran_subcategory(pkg["name"], title, description),
        "stars": pkg.get("reverse_depends_count", 0),
        "forks": 0,
        "language": "R",
        "topics": _extract_topics(f"{title} {description}"),
        "pushed_at": pkg.get("published", ""),
        "created_at": pkg.get("published", ""),
        "open_issues": 0,
        "license": pkg.get("license", ""),
    }
    entry["source"] = source
    return entry


def fetch_package_description(pkg_name: str, mirror: str) -> dict | None:
    data = enrich_from_crandb(pkg_name)
    if data:
        return data
    url = f"{mirror}/web/packages/{pkg_name}/DESCRIPTION"
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": USER_AGENT})
        if resp.status_code != 200:
            return None
        text = resp.text
        fields = {}
        current_key = None
        current_val = []
        for line in text.split("\n"):
            if line.startswith(" ") and current_key:
                current_val.append(line.strip())
            elif ":" in line:
                if current_key:
                    fields[current_key] = " ".join(current_val)
                key, _, val = line.partition(":")
                current_key = key.strip()
                current_val = [val.strip()]
        if current_key:
            fields[current_key] = " ".join(current_val)
        return {
            "name": fields.get("Package", pkg_name),
            "title": fields.get("Title", ""),
            "description": fields.get("Description", ""),
            "published": (fields.get("Date/Publication", "") or "")[:10],
            "license": _clean_license(fields.get("License", "")),
            "reverse_depends_count": 0,
        }
    except Exception:
        return None


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Discover DevSecOps-relevant CRAN packages"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview without writing files")
    parser.add_argument("--task-views-only", action="store_true",
                        help="Only fetch from curated Task Views")
    parser.add_argument("--skip-task-views", action="store_true",
                        help="Skip Task View enrichment")
    parser.add_argument("--sleep", type=float, default=3.0,
                        help="Seconds between Task View requests")
    parser.add_argument("--from", dest="from_idx", type=int, default=0,
                        help="Start at Task View index")
    parser.add_argument("--to", dest="to_idx", type=int, default=None,
                        help="Stop at Task View index (inclusive)")
    parser.add_argument("--mirror", type=str, default=CRAN_MIRROR,
                        help=f"CRAN mirror URL (default: {CRAN_MIRROR})")
    args = parser.parse_args()

    existing_names, existing_count = load_existing_repos(REPOS_YAML)
    print(f"Loaded {existing_count} existing repos from repos.yaml", flush=True)

    all_new = []

    # ── Phase 1: Task Views (primary, curated) ────────────────────────
    if not args.skip_task_views:
        to_idx = args.to_idx if args.to_idx is not None else len(CRAN_TASK_VIEWS) - 1
        active_views = CRAN_TASK_VIEWS[args.from_idx:to_idx + 1]

        print(f"\n{'='*60}", flush=True)
        print(f"Phase 1: Scraping {len(active_views)} Task Views", flush=True)

        s = requests.Session()
        s.headers.update({"User-Agent": USER_AGENT})

        for vi, (view_name, category, desc) in enumerate(active_views,
                                                          start=args.from_idx):
            print(f"\n  [{vi+1}/{len(CRAN_TASK_VIEWS)}] {view_name} ({desc})",
                  flush=True)

            pkg_names = scrape_task_view_packages(view_name)
            print(f"    Found {len(pkg_names)} packages in Task View",
                  flush=True)

            new_from_view = 0
            for pkg_name in pkg_names:
                if pkg_name.lower() in existing_names:
                    continue

                pkg_data = fetch_package_description(pkg_name, args.mirror)
                if not pkg_data:
                    pkg_data = {
                        "name": pkg_name,
                        "title": f"[{view_name} Task View package]",
                        "description": f"Curated in CRAN Task View: {view_name}",
                        "published": "",
                        "license": "",
                        "reverse_depends_count": 0,
                    }

                entry = cran_to_yaml_entry(pkg_data, category,
                                            source=f"cran-tv:{view_name}")
                all_new.append(entry)
                existing_names.add(pkg_name.lower())
                new_from_view += 1

                if new_from_view % 20 == 0:
                    print(f"    enriched {new_from_view}...", flush=True)

            print(f"    {new_from_view} new packages added", flush=True)
            time.sleep(args.sleep)

    # ── Phase 2: Full CRAN PACKAGES scan (secondary) ────────────────
    if not args.task_views_only:
        print(f"\n{'='*60}", flush=True)
        print("Phase 2: Scanning full CRAN PACKAGES index", flush=True)

        try:
            resp = requests.get(
                f"{args.mirror}/src/contrib/PACKAGES",
                timeout=60,
                headers={"User-Agent": USER_AGENT},
            )
            resp.raise_for_status()
            text = resp.text
        except Exception as exc:
            print(f"  ERROR: Could not fetch PACKAGES index: {exc}",
                  file=sys.stderr)
            sys.exit(1)

        packages = parse_packages_index(text)
        print(f"  Parsed {len(packages)} packages from index", flush=True)

        # Strict pre-filter: name + security imports
        candidates = []
        for pkg in packages:
            name = pkg["name"]
            if name.lower() in existing_names:
                continue

            name_lower = name.lower()
            deps_text = _norm(
                f"{pkg.get('depends','')} {pkg.get('imports','')} "
                f"{pkg.get('suggests','')}"
            )

            # Check strict name patterns
            name_match = any(
                re.search(pat, name_lower) for pat in STRICT_NAME_PATTERNS
            )

            # Check security imports
            import_match = any(
                re.search(rf"\b{re.escape(imp)}\b", deps_text)
                for imp in SECURITY_IMPORTS
            )

            if not (name_match or import_match):
                continue

            candidates.append(pkg)

        print(f"  Pre-filter candidates: {len(candidates)}", flush=True)

        if candidates:
            print(f"  Enriching {len(candidates)} candidates via crandb "
                  f"(~{len(candidates) * 0.3:.0f}s)...", flush=True)
            candidates = enrich_bulk_from_crandb(candidates, delay=0.25)

        relevant = []
        for pkg in candidates:
            name = pkg["name"]
            title = pkg.get("title", "")
            description = pkg.get("description", "")
            imports_str = pkg.get("imports", "")

            if not is_devsecops_package(name, title, description, imports_str):
                continue

            category = _classify_category(name, title, description, imports_str)
            entry = cran_to_yaml_entry(pkg, category, source="cran")
            relevant.append(entry)
            existing_names.add(name.lower())

        print(f"  Relevant packages: {len(relevant)} "
              f"(from {len(candidates)} candidates)", flush=True)
        all_new.extend(relevant)

    # ── Summary ────────────────────────────────────────────────────────
    print(f"\n{'='*60}", flush=True)
    print(f"Total new packages: {len(all_new)}", flush=True)

    if not all_new:
        print("No new packages to add.", flush=True)
        return

    all_new.sort(key=lambda x: x["stars"], reverse=True)

    if args.dry_run:
        print(f"\n--- Candidate packages (top 30) ---", flush=True)
        for e in all_new[:30]:
            print(f"  [{e['category']}/{e['subcategory']}] "
                  f"↩{e['stars']:>4} {e['name']}", flush=True)
            if e.get("description"):
                print(f"    {e['description'][:100]}", flush=True)
        remaining = max(0, len(all_new) - 30)
        if remaining:
            print(f"... and {remaining} more", flush=True)
        print("\nDry run complete — no files modified.", flush=True)
        return

    append_repos(REPOS_YAML, all_new)
    print(f"\nAppended {len(all_new)} CRAN packages to repos.yaml", flush=True)

    cats = Counter(e["category"] for e in all_new)
    sources = Counter(e.get("source", "unknown") for e in all_new)

    print("\nCategory breakdown:", flush=True)
    for cat, count in cats.most_common():
        print(f"  {cat:15} {count:4}", flush=True)

    print("\nSource breakdown:", flush=True)
    for src, count in sources.most_common():
        print(f"  {src:30} {count:4}", flush=True)


if __name__ == "__main__":
    main()
