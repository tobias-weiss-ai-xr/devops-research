# DevSecOps Intelligence Digest

_Generated 2026-08-07 05:05 UTC · 60 items_

## 📄 Papers

- **[Hardware Keystores for AI Agent Signing Workflows: A Zero-Trust MCP Enforcement Architecture](https://arxiv.org/abs/2608.06130v1)** · arxiv-cs-cr · score 2.5
  _tags:_ `containers`, `ai-security`
  AI agents performing cryptographic operations (signing Git commits, authenticating API calls, issuing certificates) currently store private keys in software-accessible locations: plaintext files, envi

- **[Agent Against Agent: An Agentic System for Automatic Prompt Injection Red Teaming](https://arxiv.org/abs/2608.05108v1)** · arxiv-cs-cr · score 2.5
  _tags:_ `ai-security`
  Prompt injection poses significant security risks to LLM agents. Efficient and effective red-teaming is therefore critical, both for evaluating these risks and for collecting training data to improve 

- **[On the Figures of Merit for Quantum Software Security: Toward a Benchmarking Rubric](https://arxiv.org/abs/2608.05831v1)** · arxiv-cs-cr · score 2.4
  _tags:_ `security`, `observability`
  Quantum software is increasingly provided through multi-tenant and cloud-based Quantum-as-a-Service (QaaS) stacks. A growing concern about the diverse attack vectors across the pipeline has been demon

- **[Serverless platform driven CPU loadbalancing](https://arxiv.org/abs/2608.05633v1)** · arxiv-cs-se · score 2.34
  _tags:_ `containers`
  Serverless platforms maintain a global view of function invocations and resource utilization, yet existing systems largely restrict CPU scheduling decisions to the operating system scheduler. This pap

- **[The Vulnerability With No CVE: Managing Persistent Gaps Between Mandate and Authority in AI Coding Agents](https://arxiv.org/abs/2608.05884v1)** · arxiv-cs-cr · score 1.9
  _tags:_ `security`
  Existing guidance identifies excessive agency, excessive permission, weak task-bound authorization, and inadequate agent controls as important risks. Control frameworks also describe capabilities for 

- **[RustGo: Fairly Directed Greybox Fuzzing for Enforcing Rust Memory Safety](https://arxiv.org/abs/2608.05870v1)** · arxiv-cs-cr · score 1.9
  _tags:_ `security`
  Rust is a popular systems programming language that provides strong memory safety and introduces low-performance overhead. While Rust guarantees memory safety through strict security policies, such as

## 💬 Discussions & News

- **[Runtime Supply Chain Verification using the Node Resource Interface (NRI)](https://www.cncf.io/blog/2026/07/30/runtime-supply-chain-verification-using-the-node-resource-interface-nri/)** · cncf-blog · score 6.34
  _tags:_ `containers`, `security`, `policycode`
  The widely used container supply chain verification tools today operate at the Kubernetes API layer as admission webhooks (such as Kyverno, OPA Gatekeeper, and Sigstore Policy Controller). They interc

- **[Reconciling the Past: Correcting Records for Unfixed Kubernetes CVEs](https://kubernetes.io/blog/2026/05/26/reconciling-unfixed-kubernetes-cves/)** · kubernetes-blog · score 5.0
  _tags:_ `containers`, `security`
  The Kubernetes project relies on transparency to empower cluster administrators and security researchers. One important way we do that is by publishing CVE records into the Common Vulnerabilities and 

- **[Building a Custom Metrics Exporter for Kubernetes](https://kubernetes.io/blog/2026/07/14/custom-metrics-exporter-kubernetes/)** · kubernetes-blog · score 3.8
  _tags:_ `containers`, `observability`
  Kubernetes ships with built-in awareness of CPU and memory, but most real-world scaling decisions depend on signals that live entirely outside that narrow window: how many messages are waiting in a qu

- **[Kubernetes v1.36: PSI Metrics for Kubernetes Graduates to GA](https://kubernetes.io/blog/2026/05/12/kubernetes-v1-36-psi-metrics-ga/)** · kubernetes-blog · score 3.3
  _tags:_ `containers`, `observability`
  Since its original implementation in the Linux kernel in 2018, Pressure Stall Information (PSI) has provided users with the high-fidelity signals needed to identify resource saturation before it becom

- **[Kubernetes v1.36: Tiered Memory Protection with Memory QoS](https://kubernetes.io/blog/2026/04/29/kubernetes-v1-36-memory-qos-tiered-protection/)** · kubernetes-blog · score 3.3
  _tags:_ `containers`, `observability`
  On behalf of SIG Node, we are pleased to announce updates to the Memory QoS feature (alpha) in Kubernetes v1.36. Memory QoS uses the cgroup v2 memory controller to give the kernel better guidance on h

- **[Kubernetes v1.36: Deprecation and removal of Service ExternalIPs](https://kubernetes.io/blog/2026/05/14/kubernetes-v1-36-deprecation-and-removal-of-service-externalips/)** · kubernetes-blog · score 3.2
  _tags:_ `containers`, `security`
  The .spec.externalIPs field for Service was an early attempt to provide cloud-load-balancer-like functionality for non-cloud clusters. Unfortunately, the API assumes that every user in the cluster is 

- **[Kubernetes v1.36: Staleness Mitigation and Observability for Controllers](https://kubernetes.io/blog/2026/04/28/kubernetes-v1-36-staleness-mitigation-for-controllers/)** · kubernetes-blog · score 2.8
  _tags:_ `containers`, `observability`
  Staleness in Kubernetes controllers is a problem that affects many controllers, and is something may affect controller behavior in subtle ways. It is usually not until it is too late, when a controlle

- **[Your AI agent’s next tool call may be valid but wrong. AWS’s Dogwood promises to fix that.](https://thenewstack.io/aws-dogwood-agent-policies/)** · newstack · score 2.34
  _tags:_ `ai-security`
  AWS on Thursday launched Dogwood, an open-source policy language and reference interpreter that lets developers govern sequences of AI agent The post Your AI agent’s next tool call may be valid but wr

- **[Kubernetes upgrades don’t have to break things: How EKS is making cluster lifecycle management simpler and safer](https://thenewstack.io/eks-kubernetes-upgrade-rollback/)** · newstack · score 2.34
  _tags:_ `containers`
  Kubernetes moves at a pace of three minor version releases per year, and staying current is not optional if you The post Kubernetes upgrades don’t have to break things: How EKS is making cluster lifec

- **[Gateway API v1.6: TCPRoute and UDPRoute Graduate to Standard](https://kubernetes.io/blog/2026/08/03/gateway-api-v1-6-release/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  The Kubernetes SIG Network community is thrilled to share the release of Gateway API v1.6.0 , which was released on June 30th of this year! Gateway API has become the standard for modern, role-oriente

- **[Kubernetes v1.37 Sneak Peek](https://kubernetes.io/blog/2026/07/31/kubernetes-v1-37-sneak-peek/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  As we get closer to the release date for Kubernetes v1.37, the project develops and matures, features may be deprecated, removed, or replaced with better ones for the project's overall health. This bl

- **[Operating AI/ML Workloads on Kubernetes: A Headlamp Plugin for Kubeflow](https://kubernetes.io/blog/2026/07/13/introducing-headlamp-plugin-for-kubeflow/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  Kubernetes has quietly become the default platform for AI and machine learning. Whether you run notebook servers for data scientists, schedule distributed training jobs, tune hyperparameters, or orche

- **[Kubernetes Dashboard to Headlamp: A Step-by-Step Guide](https://kubernetes.io/blog/2026/07/13/kubernetes-dashboard-to-headlamp/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  1. Before you start: know what is changing Kubernetes Dashboard and Headlamp both show what is running in a cluster, but they work differently. When Headlamp runs on the desktop, it uses your existing

- **[Announcing etcd v3.7.0](https://kubernetes.io/blog/2026/07/08/announcing-etcd-3.7/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  This article is a mirror of the original announcement Today, SIG etcd is releasing etcd v3.7.0 , the latest minor release of the popular distributed key-value store and core Kubernetes component. v3.7

- **[Introducing the Cluster API plugin for Headlamp](https://kubernetes.io/blog/2026/06/25/headlamp-cluster-api-plugin/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  Headlamp is an open-source, extensible Kubernetes SIG UI project designed to let you explore, manage, and debug cluster resources directly from a browser. Cluster API (CAPI) is a Kubernetes sub-projec

- **[Inspect Volcano workloads faster with Headlamp](https://kubernetes.io/blog/2026/06/25/visual-context-volcano-headlamp-plugin/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  Volcano is a cloud native batch scheduler for Kubernetes, built for high-performance computing, AI/ML, and other batch workloads. Headlamp is an extensible Kubernetes web UI. With its plugin system, H

- **[See your serverless: introducing the Headlamp plugin for Knative](https://kubernetes.io/blog/2026/06/25/headlamp-knative-plugin/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  Headlamp is an open-source, extensible Kubernetes SIG UI project designed to let you explore, manage, and debug cluster resources. Knative brings serverless workloads to Kubernetes, handling traffic r

- **[Spotlight on SIG Storage](https://kubernetes.io/blog/2026/06/15/sig-storage-spotlight-2026/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  In our ongoing SIG Spotlight series, we shine a light on the groups that keep the Kubernetes project moving forward. This time, we catch up with SIG Storage , the group responsible for persistent data

- **[From Kubernetes Dashboard to Headlamp: Understanding the Transition](https://kubernetes.io/blog/2026/06/01/dashboard-to-headlamp/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  For many people, Kubernetes Dashboard was their first window into Kubernetes. It offered a simple visual way to see what was running in a cluster, inspect resources, and build confidence without relyi

- **[Kubernetes v1.36: New Metric for Route Sync in the Cloud Controller Manager](https://kubernetes.io/blog/2026/05/15/ccm-new-metric-route-sync-total/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  This article was originally published with the wrong date. It was later republished, dated the 15th of May 2026. Kubernetes v1.36 introduces a new alpha counter metric route_controller_route_sync_tota

- **[Kubernetes v1.36: Mixed Version Proxy Graduates to Beta](https://kubernetes.io/blog/2026/05/15/kubernetes-1-36-feature-mixed-version-proxy-beta/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  Back in Kubernetes 1.28, we introduced the Mixed Version Proxy (MVP) as an Alpha feature (under the feature gate UnknownVersionInteroperabilityProxy ) in a previous blog post . The goal was simple but

- **[Kubernetes v1.36: Advancing Workload-Aware Scheduling](https://kubernetes.io/blog/2026/05/13/kubernetes-v1-36-advancing-workload-aware-scheduling/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  AI/ML and batch workloads introduce unique scheduling challenges that go beyond simple Pod-by-Pod scheduling. In Kubernetes v1.35, we introduced the first tranche of workload-aware scheduling improvem

- **[Kubernetes v1.36: Moving Volume Group Snapshots to GA](https://kubernetes.io/blog/2026/05/08/kubernetes-v1-36-volume-group-snapshot-ga/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  Volume group snapshots were introduced as an Alpha feature with the Kubernetes v1.27 release, moved to Beta in v1.32, and to a second Beta in v1.34. We are excited to announce that in the Kubernetes v

- **[Kubernetes v1.36: More Drivers, New Features, and the Next Era of DRA](https://kubernetes.io/blog/2026/05/07/kubernetes-v1-36-dra-136-updates/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  Dynamic Resource Allocation (DRA) has fundamentally changed how platform administrators handle hardware accelerators and specialized resources in Kubernetes. In the v1.36 release, DRA continues to mat

- **[Kubernetes v1.36: Server-Side Sharded List and Watch](https://kubernetes.io/blog/2026/05/06/kubernetes-v1-36-server-side-sharded-list-and-watch/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  As Kubernetes clusters grow to tens of thousands of nodes, controllers that watch high-cardinality resources like Pods face a scaling wall. Every replica of a horizontally scaled controller receives t

- **[Kubernetes v1.36: Declarative Validation Graduates to GA](https://kubernetes.io/blog/2026/05/05/kubernetes-v1-36-declarative-validation-ga/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  In Kubernetes v1.36, Declarative Validation for Kubernetes native types has reached General Availability (GA). For users, this means more reliable, predictable, and better-documented APIs. By moving t

- **[Kubernetes v1.36: Admission Policies That Can't Be Deleted](https://kubernetes.io/blog/2026/05/04/kubernetes-v1-36-manifest-based-admission-control/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  If you've ever tried to enforce a security policy across a fleet of Kubernetes clusters, you've probably run into a frustrating chicken-and-egg problem. Your admission policies are API objects, which 

- **[Kubernetes v1.36: Pod-Level Resource Managers (Alpha)](https://kubernetes.io/blog/2026/05/01/kubernetes-v1-36-feature-pod-level-resource-managers-alpha/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  Kubernetes v1.36 introduces Pod-Level Resource Managers as an alpha feature, bringing a more flexible and powerful resource management model to performance-sensitive workloads. This enhancement extend

- **[Kubernetes v1.36: In-Place Vertical Scaling for Pod-Level Resources Graduates to Beta](https://kubernetes.io/blog/2026/04/30/kubernetes-v1-36-inplace-pod-level-resources-beta/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  Following the graduation of Pod-Level Resources to Beta in v1.34 and the General Availability (GA) of In-Place Pod Vertical Scaling in v1.35, the Kubernetes community is thrilled to announce that In-P

- **[Kubernetes v1.36: Mutable Pod Resources for Suspended Jobs (beta)](https://kubernetes.io/blog/2026/04/27/kubernetes-v1-36-mutable-pod-resources-for-suspended-jobs/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  Kubernetes v1.36 promotes the ability to modify container resource requests and limits in the pod template of a suspended Job to beta. First introduced as alpha in v1.35, this feature allows queue con

- **[Kubernetes v1.36: Fine-Grained Kubelet API Authorization Graduates to GA](https://kubernetes.io/blog/2026/04/24/kubernetes-v1-36-fine-grained-kubelet-authorization-ga/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  On behalf of Kubernetes SIG Auth and SIG Node, we are pleased to announce the graduation of fine-grained kubelet API authorization to General Availability (GA) in Kubernetes v1.36! The KubeletFineGrai

- **[Kubernetes v1.36: User Namespaces in Kubernetes are finally GA](https://kubernetes.io/blog/2026/04/23/kubernetes-v1-36-userns-ga/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  After several years of development, User Namespaces support in Kubernetes reached General Availability (GA) with the v1.36 release. This is a Linux-only feature. For those of us working on low level c

- **[SELinux Volume Label Changes goes GA (and likely implications in v1.37)](https://kubernetes.io/blog/2026/04/22/breaking-changes-in-selinux-volume-labeling/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  If you run Kubernetes on Linux with SELinux in enforcing mode, plan ahead: a future release (anticipated to be v1.37) is expected to turn the SELinuxMount feature gate on by default. This makes volume

- **[Kubernetes v1.36: ハル (Haru)](https://kubernetes.io/blog/2026/04/22/kubernetes-v1-36-release/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  Editors: Chad M. Crowell, Kirti Goyal, Sophia Ugochukwu, Swathi Rao, Utkarsh Umre Similar to previous releases, the release of Kubernetes v1.36 introduces new stable, beta, and alpha features. The con

- **[Kubernetes v1.36 Sneak Peek](https://kubernetes.io/blog/2026/03/30/kubernetes-v1-36-sneak-peek/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  Kubernetes v1.36 is coming at the end of April 2026. This release will include removals and deprecations, and it is packed with an impressive number of enhancements. Here are some of the features we a

- **[Announcing Ingress2Gateway 1.0: Your Path to Gateway API](https://kubernetes.io/blog/2026/03/20/ingress2gateway-1-0-release/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  With the Ingress-NGINX retirement scheduled for March 2026, the Kubernetes networking landscape is at a turning point. For most organizations, the question isn't whether to migrate to Gateway API , bu

- **[Securing Production Debugging in Kubernetes](https://kubernetes.io/blog/2026/03/18/securing-production-debugging-in-kubernetes/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  During production debugging, the fastest route is often broad access such as cluster-admin (a ClusterRole that grants administrator-level access), shared bastions/jump boxes, or long-lived SSH keys. I

- **[The Invisible Rewrite: Modernizing the Kubernetes Image Promoter](https://kubernetes.io/blog/2026/03/17/image-promoter-rewrite/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  Every container image you pull from registry.k8s.io got there through kpromo , the Kubernetes image promoter. It copies images from staging registries to production, signs them with cosign , replicate

- **[Announcing the AI Gateway Working Group](https://kubernetes.io/blog/2026/03/09/announcing-ai-gateway-wg/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  The community around Kubernetes includes a number of Special Interest Groups (SIGs) and Working Groups (WGs) facilitating discussions on important topics between interested contributors. Today, we're 

- **[Introducing Node Readiness Controller](https://kubernetes.io/blog/2026/02/03/introducing-node-readiness-controller/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  In the standard Kubernetes model, a node’s suitability for workloads hinges on a single binary "Ready" condition. However, in modern Kubernetes environments, nodes require complex infrastructure depen

- **[New Conversion from cgroup v1 CPU Shares to v2 CPU Weight](https://kubernetes.io/blog/2026/01/30/new-cgroup-v1-to-v2-cpu-conversion-formula/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  I'm excited to announce the implementation of an improved conversion formula from cgroup v1 CPU shares to cgroup v2 CPU weight. This enhancement addresses critical issues with CPU priority allocation 

- **[Ingress NGINX: Statement from the Kubernetes Steering and Security Response Committees](https://kubernetes.io/blog/2026/01/29/ingress-nginx-statement/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  In March 2026, Kubernetes will retire Ingress NGINX, a piece of critical infrastructure for about half of cloud native environments. The retirement of Ingress NGINX was announced for March 2026, after

- **[Cluster API v1.12: Introducing In-place Updates and Chained Upgrades](https://kubernetes.io/blog/2026/01/27/cluster-api-v1-12-release/)** · kubernetes-blog · score 2.3
  _tags:_ `containers`
  Cluster API brings declarative management to Kubernetes cluster lifecycle, allowing users and platform teams to define the desired state of clusters and rely on controllers to continuously reconcile t

- **[Six stable kernels with a security fix](https://lwn.net/Articles/1087567/)** · lwn · score 1.9
  _tags:_ `security`
  Greg Kroah-Hartman has announced the release of the 7.1.7 , 6.18.43 , 6.6.149 , 6.1.181 , 5.15.214 , and 5.10.263 stable kernels. These kernels fix a single security vulnerability ( CVE-2026-68480 ) t

- **[You can’t debug what you can’t see — Observability for AI Agents](https://www.cncf.io/blog/2026/08/04/you-cant-debug-what-you-cant-see-observability-for-ai-agents/)** · cncf-blog · score 1.84
  _tags:_ `ai-security`, `observability`
  This article reflects practical experience building and operating production AI agent systems. Traditional APM can’t tell you why your agent spent far more than usual asking the same question three ti

- **[Cortex completes OSTIF security audit](https://www.cncf.io/blog/2026/08/03/cortex-completes-ostif-security-audit/)** · cncf-blog · score 1.84
  _tags:_ `observability`
  The Open Source Technology Improvement Fund is proud to share the results of our security audit of Cortex. Cortex functions as a long-term, multi-tenant scalable open source storage for Prometheus and

- **[Scaling Kubernetes pods with KEDA based on Amazon SQS queue depth](https://www.cncf.io/blog/2026/07/31/scaling-kubernetes-pods-with-keda-based-on-amazon-sqs-queue-depth/)** · cncf-blog · score 1.84
  _tags:_ `containers`
  In event-driven Kubernetes architectures, CPU and memory utilization often fail to reflect real system pressure. A worker pod may sit idle from a CPU perspective while thousands of messages pile up in

- **[Your Kubernetes health checks are accidentally waking your services. Here’s the fix.](https://www.cncf.io/blog/2026/07/29/your-kubernetes-health-checks-are-accidentally-waking-your-services-heres-the-fix/)** · cncf-blog · score 1.84
  _tags:_ `containers`
  Scale-to-zero breaks when health checks scale you back up. Learn how KubeElasti’s ProbeResponse lets Kubernetes services stay genuinely idle — while keeping load balancers and uptime monitors happy. S

- **[Welcome CoHDI to the CNCF: Evolving Kubernetes into composable disaggregated infrastructures](https://www.cncf.io/blog/2026/07/28/welcome-cohdi-to-the-cncf-evolving-kubernetes-into-composable-disaggregated-infrastructures/)** · cncf-blog · score 1.84
  _tags:_ `containers`
  We are thrilled to announce that CoHDI has officially been accepted as a Cloud Native Computing Foundation (CNCF) Sandbox project! This acceptance into the CNCF Sandbox marks an important milestone in

- **[Say goodbye to K8s GPU pain: How DRA changes everything](https://thenewstack.io/kubernetes-dra-gpu-scheduling/)** · newstack · score 1.84
  _tags:_ `containers`
  Consider a platform team managing a shared GPU cluster with a mix of B200s, H100s, and recently added B300s. Every The post Say goodbye to K8s GPU pain: How DRA changes everything appeared first on Th

- **[How the controller-runtime Cache Actually Works, and Why Your Controller Does Not Crash the API Server](https://kubernetes.io/blog/2026/07/29/controller-runtime-cache-explained/)** · kubernetes-blog · score 1.8
  _tags:_ `containers`
  This article has been revised since it was first published, to correct several significant technical inaccuracies in the original text. Kubernetes has long been the default platform for distributed wo

- **[Open source maintainership in the age of AI](https://kubernetes.io/blog/2026/06/26/open-source-maintainership-in-the-age-of-ai/)** · kubernetes-blog · score 1.8
  _tags:_ `containers`
  AI has really changed the game around software development. More people are leveraging AI than ever to contribute patches to projects they use. To me, this is a good thing as more folks will contribut

- **[Spotlight on WG Device Management](https://kubernetes.io/blog/2026/06/24/wg-device-management-spotlight-2026/)** · kubernetes-blog · score 1.8
  _tags:_ `containers`
  The rising popularity of AI, Edge, and Telecommunications workloads on Kubernetes has led to new requirements for hardware management. We now need hardware specification beyond CPU time and memory all

- **[Announcing etcd 3.7.0-beta.0](https://kubernetes.io/blog/2026/05/20/etcd-370-beta/)** · kubernetes-blog · score 1.8
  _tags:_ `containers`
  SIG-Etcd announces the availability of the first beta release of etcd v3.7.0 . This new version of the popular distributed database and key Kubernetes component includes the long-requested RangeStream

---
_Auto-generated by the devops-research ingestion pipeline._