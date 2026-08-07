# Contributing to DevSecOps Research

Thanks for your interest! This repository is part of a consistent set of
`*-research` corpora, so contributions should stay within the shared
house style (standard pipeline, `papers.yaml` as source of truth).

## Workflow
1. Fork and branch off `main`.
2. Keep `papers.yaml` valid (`python3 scripts/validate_papers.py`).
3. Regenerate derived artifacts when you change taxonomy/data:
   - `python3 scripts/standard_stats.py`
   - `python3 scripts/analysis/generate_reports.py`
4. Open a PR describing the change and your validation output.
