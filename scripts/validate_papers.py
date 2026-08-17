#!/usr/bin/env python3
"""Validate papers.yaml structure, taxonomy values and URL/date formats.

Usage:
    python3 scripts/validate_papers.py
    python3 scripts/validate_papers.py --strict
"""

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

import yaml

TODAY = datetime.now()

BASE = Path(__file__).resolve().parent.parent

CATEGORIES = {
    "security", "cicd", "iac", "containers", "policycode",
    "observability", "gitops", "platform", "ai-security",
}

SUBCATEGORIES = {
    "theory", "mechanism", "method", "application",
    "development", "systems", "evaluation", "review", "security",
}

ARXIV_RE = re.compile(r"https?://arxiv\.org/abs/(\d{4}\.\d{4,5})")
DATE_RE = re.compile(r"^\d{4}-\d{2}$")
# YAML flow-sequence indicator chars: an unquoted author token starting
# with one of these breaks the authors: [...] list.
INDICATORS = set("*&@!|>%`")
TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|[^,"]+')


def main():
    parser = argparse.ArgumentParser(description="Validate papers.yaml")
    parser.add_argument("--strict", action="store_true", help="Fail on any warning")
    args = parser.parse_args()

    yaml_path = BASE / "papers.yaml"
    if not yaml_path.exists():
        print("ERROR: papers.yaml not found")
        sys.exit(1)

    with open(yaml_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    papers = data.get("papers", []) if data else []

    errors = []
    warnings = []

    if not papers:
        errors.append("papers list is empty")

    titles = set()
    for i, p in enumerate(papers):
        prefix = f"paper[{i}]"
        if not p.get("title"):
            errors.append(f"{prefix}: missing title")
        else:
            t = p["title"].lower().strip()
            if t in titles:
                errors.append(f"{prefix}: duplicate title '{p['title'][:60]}'")
            titles.add(t)
        if not p.get("url"):
            errors.append(f"{prefix}: missing url")
        else:
            if not (p["url"].startswith("http://") or p["url"].startswith("https://")):
                errors.append(f"{prefix}: url not http(s): {p['url']}")
            if not p.get("date"):
                warnings.append(f"{prefix}: no date for {p.get('title', '')[:60]}")
        if p.get("date") and not DATE_RE.match(str(p["date"])):
            errors.append(f"{prefix}: bad date '{p.get('date')}' (want YYYY-MM)")
        else:
            # QUALITY GATE: no future dates
            _d = str(p.get("date", ""))
            if len(_d) >= 7:
                _y, _m = int(_d[:4]), int(_d[5:7])
                if (_y, _m) > (TODAY.year, TODAY.month):
                    errors.append(f"{prefix}: future date '{_d}' (cannot be after today {TODAY:%Y-%m})")
        cat = p.get("category")
        if cat not in CATEGORIES:
            errors.append(f"{prefix}: bad category '{cat}' (want one of {sorted(CATEGORIES)})")
        sub = p.get("subcategory")
        if sub not in SUBCATEGORIES:
            errors.append(f"{prefix}: bad subcategory '{sub}' (want one of {sorted(SUBCATEGORIES)})")
        if not p.get("abstract"):
            warnings.append(f"{prefix}: missing abstract")

        # authors: [...] must not contain unquoted YAML-indicator tokens
        for a in p.get("authors", []) or []:
            if a and a.strip() and a.strip()[0] in INDICATORS:
                errors.append(f"{prefix}: unquoted YAML indicator in author '{a[:40]}'")

    for err in errors:
        print(f"  ERROR: {err}")
    for w in warnings:
        print(f"  WARN:  {w}")

    if errors:
        print(f"\nValidation FAILED: {len(errors)} error(s), {len(warnings)} warning(s)")
        sys.exit(1)
    if warnings and args.strict:
        print(f"\nValidation FAILED (strict): {len(warnings)} warning(s)")
        sys.exit(1)

    print(f"\nValidation OK: {len(papers)} papers, no errors, {len(warnings)} warning(s)")

    # quick taxonomy summary
    from collections import Counter
    by_cat = Counter(p.get("category") for p in papers)
    print("Coverage:")
    for cat in sorted(CATEGORIES):
        print(f"  {cat:14s} {by_cat.get(cat, 0):4d}")


if __name__ == "__main__":
    main()