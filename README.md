# devops-research — automated DevSecOps intelligence ingestion pipeline

A small, dependency-light pipeline that pulls the latest **DevSecOps / DevOps tools,
research papers, release-changelogs, and community discussions** from a mix of RSS/Atom
feeds and APIs, filters + tags + scores them, and renders a daily digest
(Markdown + standalone HTML + JSON).

## Why

Staying on top of DevSecOps tooling and security research across GitHub releases, arXiv,
Hacker News, Reddit, and vendor blogs is manual and noisy. This pipeline automates
ingestion, de-duplication, relevance scoring, and digest rendering so you get one
curated list instead of N feeds.

## Pipeline stages

```
config/sources.yml  ──▶  fetch.py      normalize entries from each source
                            │
                            ▼
                        classify.py   keyword-tag topics + relevance score
                            │
                            ▼
                        dedup.py       JSON state store (only NEW items pass)
                            │
                            ▼
                        digest.py      render MD + HTML + JSON
                            │
                            ▼
                      data/latest
```

### Components (`ingest/`)
| Module | Responsibility |
|--------|----------------|
| `fetch.py`   | Adapters for RSS/Atom (`feedparser`), arXiv API, GitHub releases. Normalizes to one item schema. Auto-retries once on empty (handles Reddit/CDN 429 flakiness). |
| `classify.py` | Topic tagging from keyword groups in config + weighted relevance score (source weight + topic matches + recency). Security/policy topics weighted higher. |
| `dedup.py`   | JSON-backed "seen" store; only emits items not seen within the retention window. |
| `digest.py`  | Renders grouped, score-sorted Markdown / standalone HTML / JSON. |

### Entrypoint
```bash
python run_pipeline.py                # full ingest → write digest + mark seen
python run_pipeline.py --dry-run     # ingest + score, write nothing
python run_pipeline.py --top 40      # cap digest size
python run_pipeline.py --json-out data/raw.json
```

## Configuration
Add/edit feeds and keywords in **`config/sources.yml`** — no code changes needed:
- `sources[].type`: `rss` (URL feed), `arxiv` (category query), `github` (repo releases).
- `sources[].weight`: trust boost for scoring.
- `sources[].min_topics`: drop items with fewer topic hits (great for arXiv to cut noise).
- `sources[].delay`: seconds to wait before fetching (script friendly to Reddit rate limits).
- `keywords`: topic → word list. Add/modify freely.

## Install & schedule (automation)
```bash
bash scripts/setup.sh         # create .venv, install deps, install crontab (daily 07:00)
```

## Research repo corpus (`repos.yaml`)

Complementary to the paper corpus, this tracks DevSecOps-relevant repositories
across the same taxonomy. All three fetchers share a ``repos_common.py`` module
for relevance filtering, subcategory classification, YAML I/O, and entry
normalisation.

```bash
# GitHub (gh CLI required)
python3 scripts/fetch/fetch_github_repos.py --min-stars 100 --dry-run
python3 scripts/fetch/fetch_github_repos.py --min-stars 100

# GitLab (no CLI — pure REST API)
python3 scripts/fetch/fetch_gitlab_repos.py --dry-run
python3 scripts/fetch/fetch_gitlab_repos.py --min-stars 5
python3 scripts/fetch/fetch_gitlab_repos.py --host https://gitlab.gwdg.de   # self-hosted

# Codeberg (Gitea-compatible API)
python3 scripts/fetch/fetch_codeberg_repos.py --dry-run
python3 scripts/fetch/fetch_codeberg_repos.py --min-stars 5
```

All fetchers write to the shared ``repos.yaml`` (dedup by repo name, append-only).

# CRAN (R packages)

```bash
# CRAN Task Views (primary — curated, enriched via crandb API)
python3 scripts/fetch/fetch_cran_repos.py --task-views-only --dry-run
python3 scripts/fetch/fetch_cran_repos.py --task-views-only

# Full CRAN scan + Task Views (Phase 2 adds name/dependency filtering)
python3 scripts/fetch/fetch_cran_repos.py --dry-run
python3 scripts/fetch/fetch_cran_repos.py

# Partial Task View run (index range)
python3 scripts/fetch/fetch_cran_repos.py --from 0 --to 5 --dry-run
```

The CRAN fetcher discovers R packages from 20 DevSecOps-relevant Task Views
(AnomalyDetection, NetworkAnalysis, MachineLearning, Cryptography, etc.)
and enriches them via the crandb.r-pkg.org API for full Title/Description.
Phase 2 scans the full PACKAGES index with strict name/dependency pre-filtering.

Taxonomy mirrors `papers.yaml`: `security`, `containers`, `cicd`, `iac`,
`observability`, `ai-security`, `policycode`, `gitops`, `platform`.  Each entry
includes stars, forks, language, topics, activity date, and license.
For CRAN packages, ``stars`` proxies reverse dependency count.

# CNCF Landscape (canonical cloud-native tool map)

```bash
python3 scripts/fetch/fetch_cncf_landscape.py --dry-run
python3 scripts/fetch/fetch_cncf_landscape.py
```

Pulls the curated CNCF Cloud Native Landscape
(`landscape.yml`) and keeps the DevSecOps-relevant slices:
`Security & Compliance`, `Key Management`, and `Observability`.  Only entries
with a public repo are kept (pure-commercial vendor pages are skipped).  When
`GITHUB_TOKEN` is set, each repo is enriched with stars/forks/license/language.

# PyPI (Python packages)

```bash
python3 scripts/fetch/fetch_pypi_repos.py --dry-run
python3 scripts/fetch/fetch_pypi_repos.py   # respects GITHUB_TOKEN for stars
```

PyPI hosts ~870k packages and has no public classifier-search endpoint, so
this fetcher uses a curated seed list of well-known DevSecOps Python packages
(SAST/SCA, SBOM/supply-chain, policy/compliance, IAM, observability, CICD)
and enriches each via `https://pypi.org/pypi/{pkg}/json`.  This keeps API
calls strictly bounded (one per seed package) instead of scanning the index.

All fetchers from this section share ``scripts/fetch/repos_common.py`` for
relevance filtering, subcategory classification, YAML I/O, entry
normalisation, and GitHub star enrichment (``enrich_github``).
Entries are tagged with a ``source`` field (e.g. ``cran-tv``, ``cncf-landscape:*``,
``pypi``) for provenance.

## Paper search (research corpus)

In addition to the daily news digest, this repo maintains a curated research
corpus in `papers.yaml` (plus `papers.json` / `statistics.json` exports),
following the same house pattern as the sibling `*-research` repos.

```bash
# arXiv discovery — 94 DevSecOps taxonomy queries, last N months,
# dedup by arXiv ID/title, checkpoint every 10 queries
python3 scripts/fetch/fetch_new_papers.py --months 12 --dry-run   # preview
python3 scripts/fetch/fetch_openalex.py  --months 36            # OpenAlex pass

python3 scripts/validate_papers.py               # structure + taxonomy checks
python3 scripts/analysis/generate_analysis.py    # saturation, counts, themes
```

Taxonomy (category in `papers.yaml`): `security`, `cicd`, `iac`, `containers`,
`policycode`, `observability`, `gitops`, `platform`, `ai-security` — matching
the keyword groups in `config/sources.yml`. Subcategory refines by theme
(review / theory / method / application / systems / evaluation / …).

The corpus is DevOps-strict: LLM / AI-agent papers are only kept when they
carry DevOps context (code, pipelines, CI/CD, IaC, Kubernetes, supply chain,
agent tooling, AIOps, …). Papers without it are archived to
`papers-general.yaml` instead of polluting the corpus.

The relevance gate runs **at ingest time** in both `fetch_new_papers.py` and
`fetch_openalex.py` (shared `devops_filter()` from `fetch_new_papers.py`,
imported by `reclassify_papers.py` — house pattern).  LLM signals are matched
with word boundaries and hyphen/slash normalisation; generic CS terms
(`software`, `code`, `tool`, `api`, `vulnerability`) are excluded from the
medium-signal list to prevent false positives.

```bash
# DevOps-relevance pass (LLM/AI papers w/o DevOps context -> archive)
python3 scripts/reclassify_papers.py --dry-run   # preview
python3 scripts/reclassify_papers.py             # apply
```

Bulk refreshes: `--from Q --to Q` resume partial runs; both fetchers append
and checkpoint, so interrupted runs never lose progress.

Manual equivalent:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
(crontab -l 2>/dev/null; echo "0 7 * * * cd $PWD && .venv/bin/python run_pipeline.py >> data/run.log 2>&1") | crontab -
```

> **Note on Reddit:** Reddit sometimes returns HTTP 429 to datacenter IPs; the pipeline logs
> the empty result and continues. For reliable Reddit ingestion, use OAuth credentials or a mirror.

## Extending to an LLM summarizer
`ingest/digest.summarize()` is a dependency-free, extractive placeholder. To use an LLM,
replace the body with an API call and set the vendor env vars you have available
(`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, …).

## Output
- `data/latest.md` — primary digest
- `data/latest.html` — standalone styled web page (open file:// in any browser, it’s self-contained)
- `data/raw.json` — full structured feed for downstream consumption
- `data/seen.json` — dedup state (do not delete, or everything is re-emitted once)