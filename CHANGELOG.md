# Changelog

All notable changes to DevSecOps Research are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]
- Standardized repository: research-pipeline house (validate, stats, reports,
  BibTeX, tools) aligned with the sibling `*-research` repos.

## [0.2.1] - 2026-08-09
- Second fetch iteration (arXiv all queries + OpenAlex 36-month) added ~686
  candidate papers; post-fetch reclassify purged 465 non-DevOps LLM papers
  (corpus 2650 → 3336 → 2871).
- **Ingest-level DevOps-relevance gate**: `devops_filter()` moved into
  `fetch_new_papers.py` (house pattern: reclassify imports from fetch).
  Both `fetch_new_papers.py` and `fetch_openalex.py` now reject LLM/AI
  papers without DevOps context *at fetch time* — no more post-hoc purging
  needed.
- Archive recovery: `scripts/recover_archive.py` rebuilt `papers-general.yaml`
  as the exact union of all purged papers (HEAD ∪ archive − corpus) after a
  purge overwrite clobbered the first 530 entries.  `reclassify_papers.py`
  now merges into the archive (dedup by URL) instead of overwriting.
- Added `ai-assisted` / `ai assisted` to LLM signals; 3rd purge caught 9
  remaining edge cases.  Final corpus: **2862 papers**, archive: **670**.
- `generate_analysis.py` updated: all papers fall within the 12-month
  rolling window so `recent_12m` equals total counts (saturation 95.1%).

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

## [0.2.0] - 2026-08-09
- DevOps-relevance pass over the corpus (`scripts/reclassify_papers.py`):
  LLM/AI-agent papers are now only kept with DevOps context (code, pipelines,
  CI/CD, IaC, Kubernetes, supply chain, agent tooling, AIOps). 530 general
  AI papers moved to `papers-general.yaml` (corpus 3180 → 2650, ai-security
  557 → 266).
- ai-security fetch queries are now DevOps-anchored (prompt injection + code/
  software/tool, LLM vuln + repository, MCP + tool/integration, AI + CI/CD,
  agent supply chain, …) so new discoveries cannot re-pollute.
- Fixed YAML robustness: word-boundary + hyphen/slash normalization in the
  relevance pass; validator now flags unquoted YAML-indicator author tokens.
