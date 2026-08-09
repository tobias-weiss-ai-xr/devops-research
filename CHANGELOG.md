# Changelog

All notable changes to DevSecOps Research are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]
- Standardized repository: research-pipeline house (validate, stats, reports,
  BibTeX, tools) aligned with the sibling `*-research` repos.

## [0.1.0] - 2026-08-09
- Added DevSecOps paper-search house aligned with sibling `*-research` repos
  (arXiv 12-month pass + OpenAlex 36-month pass — 3180 papers, 95.1% taxonomy
  saturation):
  - `papers.yaml` corpus + `papers.json` / `statistics.json` exports
  - `scripts/fetch/fetch_new_papers.py` — arXiv discovery, 94 taxonomy queries
    (security | cicd | iac | containers | policycode | observability | gitops |
    platform | ai-security), dedup by arXiv ID/title, checkpoint every 10 queries
  - `scripts/fetch/fetch_openalex.py` — OpenAlex discovery pass
  - `scripts/validate_papers.py` — structure/taxonomy/URL checks
  - `scripts/analysis/generate_analysis.py` — saturation, per-category counts,
    rolling 12-month emerging themes
