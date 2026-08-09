#!/usr/bin/env python3
"""DevOps-relevance pass over the paper corpus.

The corpus must stay DevOps / DevSecOps-focused. LLM & AI-agent papers are the
most prone to drift into general AI-security research (jailbreaks, alignment,
chatbot privacy, ...), so this tool:

  1. detects LLM/AI-agent papers across all categories (title+abstract signals)
  2. scores DevOps context (CI/CD, pipelines, IaC, Kubernetes, containers,
     supply chain, code review, coding assistants, MCP tooling, AIOps, ...)
  3. moves LLM papers WITHOUT DevOps context out of papers.yaml into an
     archive file (papers-general.yaml) — nothing is deleted, the corpus stays
     clean, and future iterations only fetch DevOps-anchored queries.

Line-based surgery keeps papers.yaml byte-identical apart from removed blocks,
so git diffs stay reviewable.

Usage:
    python3 scripts/reclassify_papers.py --dry-run
    python3 scripts/reclassify_papers.py
"""

import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent / "fetch"))
from fetch_new_papers import (  # noqa: E402
    DEVOPS_MEDIUM,
    DEVOPS_STRONG,
    LLM_SIGNALS,
    devops_relevance,
    is_llm_paper,
)

BASE = Path(__file__).resolve().parent.parent


def entry_blocks(lines):
    """Split file lines into (header_lines, [blocks]) where each block starts
    with a '  - title:' line (2-space indent, list item)."""
    starts = [i for i, ln in enumerate(lines) if ln.startswith("  - title:")]
    blocks = []
    for k, s in enumerate(starts):
        e = starts[k + 1] if k + 1 < len(starts) else len(lines)
        blocks.append((s, e))
    return blocks


def main():
    parser = argparse.ArgumentParser(
        description="Move non-DevOps LLM/AI-agent papers out of the corpus"
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview only")
    parser.add_argument(
        "--archive", default=str(BASE / "papers-general.yaml"),
        help="target archive file for purged papers",
    )
    args = parser.parse_args()

    yaml_path = BASE / "papers.yaml"
    with open(yaml_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    papers = data.get("papers", [])

    lines = yaml_path.read_text(encoding="utf-8").split("\n")
    blocks = entry_blocks(lines)
    if len(blocks) != len(papers):
        print(f"ERROR: parsed {len(papers)} entries but found {len(blocks)} blocks in file")
        sys.exit(1)

    moved = []
    stays = []
    per_cat = Counter()
    per_sub = Counter()
    for p, (s, e) in zip(papers, blocks):
        if not is_llm_paper(p):
            stays.append(p)
            continue
        relevant, n_strong, n_med = devops_relevance(p)
        if relevant:
            stays.append(p)
            note = f"keep ({n_strong} strong, {n_med} med)"
        else:
            moved.append(p)
            per_cat[p.get("category", "?")] += 1
            per_sub[p.get("subcategory", "?")] += 1
            note = "MOVE"
        # per_cat counting for summary:
        if note == "keep":
            per_cat[f"{p.get('category','?')}/keep"] += 1

    llm_total = len(moved) + (len(papers) - len([p for p in papers if not is_llm_paper(p)]) - len(stays))
    # simpler: llm_total = sum(is_llm) over papers BEFORE filtering
    llm_total = sum(1 for p in papers if is_llm_paper(p))

    print(f"Corpus: {len(papers)} papers, {llm_total} LLM/AI-related")
    print(f"LLM papers WITH DevOps context (keep): {llm_total - len(moved)}")
    print(f"LLM papers WITHOUT DevOps context (move): {len(moved)}")
    print("\nMoved by category:", dict(per_cat))
    print("Moved by subcategory:", dict(per_sub))

    if moved:
        print("\n--- Example purged papers (up to 12) ---")
        for p in moved[:12]:
            print(f"  [{p.get('category')}/{p.get('subcategory')}] {p.get('title','')[:90]}")

    if args.dry_run:
        print("\nDry run — nothing changed")
        return 0

    if not moved:
        print("\nNo papers to move — corpus unchanged")
        return 0

    # ---- line surgery: keep only non-moved blocks ----------------
    moved_ids = {id(p) for p in moved}
    kept_ids = {id(p) for p in papers if id(p) not in moved_ids}
    first_start = blocks[0][0] if blocks else len(lines)
    new_lines = lines[:first_start]  # header/comments before first entry
    for p, (s, e) in zip(papers, blocks):
        if id(p) in kept_ids:
            new_lines.extend(lines[s:e])
    while new_lines and new_lines[-1] == "":
        new_lines.pop()
    yaml_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    # ---- archive: merge with existing (dedup by url), never clobber ----
    archive_path = Path(args.archive)
    existing = []
    if archive_path.exists():
        existing = (yaml.safe_load(archive_path.read_text()) or {}).get("papers", [])
    seen_urls = {e.get("url", "") for e in existing}
    for p in moved:
        if p.get("url") not in seen_urls:
            existing.append(p)
            seen_urls.add(p.get("url", ""))
    with open(archive_path, "w", encoding="utf-8") as f:
        f.write(
            "# Non-DevOps LLM/AI-agent papers purged from papers.yaml by\n"
            "# scripts/reclassify_papers.py (kept for reference, not part of\n"
            "# the DevOps corpus). Same schema as papers.yaml.\n"
        )
        yaml.dump({"papers": existing}, f, default_flow_style=False,
                  allow_unicode=True, sort_keys=False)

    # re-validate the resulting file
    import subprocess
    r = subprocess.run([sys.executable, str(BASE / "scripts" / "validate_papers.py")],
                       capture_output=True, text=True)
    print("\n" + r.stdout.strip().split("\n")[-1])
    print(f"Moved {len(moved)} papers to {archive_path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())