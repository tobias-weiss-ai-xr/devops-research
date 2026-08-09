#!/usr/bin/env python3
"""Recover the papers-general.yaml archive after the reclassify overwrite.

History: purge #1 moved 530 papers out of papers.yaml (archive written),
purge #2 moved 465 more and OVERWROTE the archive file with only those.
Also, fetches ran before the ingest filter existed and re-added some purged
papers. This script reconstructs the exact union of all purged papers from
set algebra (git HEAD papers.yaml ∪ current archive − current corpus) and:

  - papers now considered DevOps-relevant (current rules) are APPENDED BACK
    into papers.yaml (house format via fetch_new_papers.append_papers)
  - the rest form the complete archive

One-off repair — kept in scripts/ for provenance.
"""

import re
import subprocess
import sys
from pathlib import Path

import yaml

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "scripts" / "fetch"))
from fetch_new_papers import append_papers, devops_filter  # noqa: E402

ARXIV_ID_RE = re.compile(r"(?:arxiv\.org/abs/|arxiv.org/pdf/)(\d{4}\.\d{4,5})")
DOI_RE = re.compile(r"10\.\d{4,9}/[^\s]+")


def key(p):
    url = p.get("url", "")
    m = ARXIV_ID_RE.search(url)
    if m:
        return ("arxiv", m.group(1))
    m = DOI_RE.search(url)
    if m:
        return ("doi", m.group(0).rstrip("."))
    return ("title", p.get("title", "").lower().strip())


def main():
    # A = committed corpus (git HEAD), C = current corpus, P = current archive
    a_raw = subprocess.run(
        ["git", "show", "HEAD:papers.yaml"], capture_output=True, text=True,
        cwd=BASE).stdout
    A = yaml.safe_load(a_raw)["papers"]
    C = yaml.safe_load((BASE / "papers.yaml").read_text())["papers"]
    P = yaml.safe_load((BASE / "papers-general.yaml").read_text())["papers"]

    c_keys = {key(p) for p in C}
    pool = {}
    for p in A + P:
        k = key(p)
        if k not in c_keys and k not in pool:
            pool[k] = p

    re_add = []
    keep_archived = []
    for k, p in pool.items():
        if devops_filter(p):
            re_add.append(p)      # now relevant under current rules
        else:
            keep_archived.append(p)

    # append back into corpus (house format, dedup-safe by id/url in fetchers)
    if re_add:
        append_papers(BASE / "papers.yaml", re_add)
        print(f"Re-added {len(re_add)} papers to papers.yaml (now DevOps-relevant)")

    # rebuild complete archive
    with open(BASE / "papers-general.yaml", "w", encoding="utf-8") as f:
        f.write(
            "# Non-DevOps LLM/AI-agent papers purged from papers.yaml by\n"
            "# scripts/reclassify_papers.py (kept for reference, not part of\n"
            "# the DevOps corpus). Same schema as papers.yaml.\n"
        )
        yaml.dump({"papers": keep_archived}, f, default_flow_style=False,
                  allow_unicode=True, sort_keys=False)
    print(f"Archive now holds {len(keep_archived)} papers ({len(pool)} purged total, "
          f"{len(re_add)} re-added)")


if __name__ == "__main__":
    main()