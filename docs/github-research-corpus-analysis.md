# GitHub Research Corpus — Cross-Corpus Analysis

> Generated: 2026-08-13 | Corpus: 1759 repos, 4421 papers

## Overview

The `repos.yaml` corpus tracks 1,759 DevSecOps-relevant GitHub repositories
discovered via 56 topic+keyword queries across the same 9-category taxonomy
as `papers.yaml`. This provides a complementary **tool/project** dimension
alongside the **research paper** dimension.

## Category Balance

| Category       | Papers | Repos | Papers/Repo Ratio |
|---------------|--------|-------|-------------------|
| security       |   1467 |   442 | 3.3×              |
| containers     |    511 |   298 | 1.7×              |
| cicd           |    395 |   254 | 1.6×              |
| observability  |    348 |   206 | 1.7×              |
| iac            |    260 |   232 | 1.1×              |
| ai-security    |    659 |   119 | **5.5×**          |
| policycode     |    299 |    73 | 4.1×              |
| gitops         |    188 |    72 | 2.6×              |
| platform       |    294 |    63 | **4.7×**          |

**Insight**: AI-security and platform engineering have the highest paper-to-repo
ratios (5.5× and 4.7×), meaning lots of research interest but fewer open-source
projects. IaC has the lowest ratio (1.1×), reflecting its maturity with a rich
tool ecosystem (Terraform providers, Ansible roles, Pulumi providers).

## Stars Distribution

- **Total stars**: 7.1M
- **Mean**: 4,053 | **Median**: 981
- **10K+ stars**: 162 repos | **1K-10K**: 706 | **100-1K**: 891

## Top Languages

| Language    | Repos | Share |
|-------------|-------|-------|
| Go          |   564 | 32.1% |
| Python      |   265 | 15.1% |
| TypeScript  |   154 |  8.8% |
| Java        |   116 |  6.6% |
| Shell       |    88 |  5.0% |
| JavaScript  |    74 |  4.2% |
| Rust        |    61 |  3.5% |

**Insight**: Go dominates (32.1%), reflecting the Cloud Native ecosystem's
language choice. Python is the #2 but primarily for security scanning and
AI-adjacent tooling. Rust is growing in the security + observability space.

## License Distribution

| License      | Repos | Share |
|--------------|-------|-------|
| Apache-2.0   |   725 | 41.2% |
| MIT          |   440 | 25.0% |
| GPL-3.0      |    73 |  4.2% |
| AGPL-3.0     |    67 |  3.8% |
| MPL-2.0      |    57 |  3.2% |
| Unlicensed   |   311 | 17.7% |

## Activity

- **Pushed in last 30 days**: 994 repos (57%)
- **Pushed in last 90 days**: 1116 repos (63%)

## Most-Researched Tools (by paper mentions)

| Papers | Stars | Tool | Category |
|--------|-------|------|----------|
| 188 | 124K | kubernetes/kubernetes | containers |
| 95 | 2.0K | pyupio/safety | security |
| 24 | 26K | jenkinsci/jenkins | cicd |
| 21 | 4.1K | hashicorp/boundary | security |
| 18 | 22K | vectordotdev/vector | observability |
| 18 | 535 | CycloneDX/specification | security |
| 16 | 22K | jina-ai/serve | containers |
| 14 | 38K | harness/harness | cicd |
| 9 | 90K | modelcontextprotocol/servers | ai-security |

**Insight**: Kubernetes dominates research (188 papers). Jenkins has
disproportionately few papers (24) given its 26K stars — it's been
largely supplanted in the research literature by GitHub Actions and GitLab CI.

## Research Gaps: High-Star Tools with Zero Paper Mentions

These tools have significant adoption but zero academic attention in the corpus:

| Stars | Tool | Category | Why This Matters |
|-------|------|----------|-----------------|
| 38K | portainer/portainer | containers | Most popular K8s GUI — zero research |
| 37K | aquasecurity/trivy | security | Dominant container scanner — unvalidated empirically |
| 34K | backstage/backstage | platform | Leading IDP — zero adoption research |
| 33K | langfuse/langfuse | observability | LLM observability — frontier topic |
| 33K | podman/podman | containers | Docker alternative — no comparative studies |
| 32K | dokku/dokku | containers | PaaS-on-a-server — no research |
| 31K | SigNoz/signoz | cicd | OpenTelemetry-native monitoring |
| 30K | projectdiscovery/nuclei | security | Template-based vulnerability scanner |
| 29K | gitleaks/gitleaks | security | Most popular secret scanner |
| 30K | hashicorp/consul | containers | Service mesh — zero research despite Kubernetes |
| 26K | cilium/cilium | containers | eBPF networking — growing but unstudied |
| 25K | pulumi/pulumi | iac | Competitor to Terraform — no comparative work |

## Most Forked (Community Adoption Signal)

| Forks | Stars | Tool | Category |
|-------|-------|------|----------|
| 43K | 124K | kubernetes/kubernetes | containers |
| 26K | 42K | apache/dubbo | containers |
| 24K | 152K | langgenius/dify | cicd |
| 20K | 84K | bregman-arie/devops-exercises | containers |
| 19K | 10K | iam-veeramalla/Jenkins-Zero-To-Hero | cicd |
| 16K | 10K | tech-shrimp/docker_image_pusher | cicd |
| 15K | 76K | grafana/grafana | observability |

## Methodology

- **Source**: GitHub Search API via `gh api` (56 queries, 2 pages each)
- **Star threshold**: 100+ (main run), configurable via `--min-stars`
- **Dedup**: by exact repo name (case-insensitive)
- **Classification**: keyword-based subcategory assignment from repo name + description + GitHub topics
- **Relevance gate**: DevOps signal matching (shared signals with `fetch_new_papers.py`)
- **Star thresholds for research gaps**: 3K+ stars with zero paper title/abstract mentions
