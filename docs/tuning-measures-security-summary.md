# Security Summary — Tuning Measures for VMs/Containers/Pods

> Security-focused companion to `tuning-measures-vm-container-pod.md`. This document
> isolates the security-relevant knobs and configurations for hardening VMs, Docker,
> and Kubernetes workloads.

---

## 1. Attack Surface Reduction

| Mechanism | What It Does | Recommended Setting |
|-----------|--------------|---------------------|
| **`--cap-drop ALL` + selective `--cap-add`** | Starts with zero capabilities; adds only what's needed | Default for all production containers; only add `NET_BIND_SERVICE`, `IPC_LOCK` (for DPDK/DBs), `SYS_ADMIN` (only for explicit runtime like Kata) |
| **`--read-only` root filesystem** | Prevents write attacks to `/`, image tampering, rootkits | Turn on; mount writable state to tmpfs or PVCs (e.g., `/var/cache`, `/var/run`, `/tmp`) |
| **`--user 1000:1000` (non-root)** | Removes root privilege escalation paths | Never run as UID 0 in production; if image requires root, use `--security-opt uidmap` or SecurityContext `runAsUser` |
| **`--security-opt no-new-privileges`** | Blocks `setuid/setgid` escalation | Default ON in Docker daemon config |
| **`allowPrivilegeEscalation: false`** | K8s equivalent of no-new-privileges | Set on all container securityContexts |
| **`seccomp: RuntimeDefault`** | Whitelists ~254 syscalls for containers; blocks 300+ dangerous syscalls (e.g., `kexec_load`, `module_load`, `ptrace`) | Use the default profile; custom profiles only for special cases (e.g., some FUSE workloads) |
| **`--network=none` or custom network** | Removes bridge network exposure | Use for non-networked jobs; otherwise, apply CNI policies (Cilium NetworkPolicy) |
| **`--pids-limit=100`** | Fork bomb containment | Default to ~100–500 per container type (web ~100, DB ~500) |
| **`runAsNonRoot: true`** | Enforces non-root execution at admission controller level | Enforce via PodSecurityPolicy or PodSecurityStandards `restricted` profile |
| **`readOnlyRootFilesystem: true`** | Same as Docker `--read-only` | Recommended for all stateless services |

---

## 2. Kernel Hardening (Host/VM)

| Parameter | Security Purpose | Risk If Ignored |
|-----------|------------------|-----------------|
| `kernel.kexec_load_disabled=1` | Blocks kexec (rootkits can't hijack boot) | Attacker with root can load malicious kernel |
| `kernel.modules_disabled=1` | Post-boot kernel module loading | **Breaks drivers, BPF, some networking tools** — only for airgapped specialized workloads |
| `kernel.unprivileged_bpf_disabled=1` | Blocks unprivileged BPF (used by some userland eBPF-based tools) | Some tooling breaks, but prevents BPF escalation paths |
| `kernel.perf_event_paranoid=2` | Only root can use `perf` | Prevents side-channel attacks via perf |
| `kernel.yama.ptrace_scope=2` | No cross-process `ptrace` without parent | Stops attackers from attaching to other processes |
| `kernel.dmesg_restrict=1` | Only root can read kernel logs | Prevents info leaks (KASLR bypass, module listing) |
| `kernel.kptr_restrict=2` | Hides kernel pointers | Mitigates KASLR bypass |
| `net.ipv4.conf.all.rp_filter=1` | Reverse path filtering (anti-spoofing) | Prevents IP spoofing from containers |
| `net.ipv4.conf.all.accept_source_route=0` | Block source-routed packets | Less common path for spoofed traffic |
| `net.ipv4.conf.all.send_redirects=0` | Don't send ICMP redirects | Prevents ICMP redirect attacks |
| `net.ipv4.conf.all.log_martians=1` | Log spoofed/martian packets | IDS/visibility |
| `net.ipv4.tcp_syncookies=1` | SYN cookies (DDoS protection) | Keep ON; if disabled, SYN flood can exhaust `tcp_max_syn_backlog` |

```bash
# /etc/sysctl.d/99-security-hardening.conf
kernel.kexec_load_disabled=1
kernel.unprivileged_bpf_disabled=1
kernel.perf_event_paranoid=2
kernel.yama.ptrace_scope=2
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.tcp_syncookies=1
```

---

## 3. Docker Daemon Hardening

```json
{
  "cgroup-parent": "docker.slice",
  "default-ulimits": {
    "nofile": {"Name": "nofile", "Hard": 1048576, "Soft": 65535},
    "nproc": {"Name": "nproc", "Hard": 65535, "Soft": 4096}
  },
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "5"
  },
  "storage-opts": ["overlay2.override_kernel_check=true"],
  "live-restore": true,
  "userns-remap": "default",
  "no-new-privileges": true,
  "ip-forward": false,
  "iptables": false
}
```

**Critical settings:**

| Setting | Security Impact |
|---------|-----------------|
| `userns-remap: default` | Remaps container UIDs/GIDs to non-root ranges (`/etc/subuid`, `/etc/subgid`). Breakouts are confined to remapped space. |
| `no-new-privileges: true` | Prevents `setuid` escalation across the system. |
| `ip-forward: false` / `iptables: false` | Disables Docker's auto-bridge manipulation; forces managed networking (CNI). |
| `default-ulimits` | Enforces baseline resource caps per container. |
| `live-restore: true` | Prevents `dockerd` restart from killing containers. |

Apply and reload:
```bash
sudo systemctl reload docker
sudo systemctl restart docker  # for some changes
```

---

## 4. Kubernetes Admission Controls

### 4.1 Pod Security Standards (Enforce `restricted`)

| Parameter | `baseline` vs `restricted` |
|-----------|---------------------------|
| `runAsNonRoot` | `restricted` required |
| `allowPrivilegeEscalation` | `restricted`: `false` |
| `capabilities.drop` | `restricted`: `ALL` + optional adds |
| `seccomp.type` | `restricted`: `RuntimeDefault` |
| `volumes` | `restricted`: no hostPath volumes (except for pre-approved paths) |

**Enforce at namespace level:**
```yaml
# PodSecurityPolicy style (deprecated) or PodSecurityLabel (1.30+)
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
```

### 4.2 NetworkPolicy Defaults (Default-Deny, Explicit Allow)

```yaml
# Default deny all ingress/egress for namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: production
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
```

**Common patterns:**
- Internal-to-internal: allow `namespaceSelector`, `podSelector`
- Ingress from LB: allow `namespaceSelector: matchLabels: namespace.kubernetes.io/isolate=shared`
- Egress to DNS: allow rules to `kube-dns.kube-system.svc` ports 53/UDP, 53/TCP
- Egress to external: allow specific public CIDRs or `namespaceSelector: external-service`

### 4.3 ResourceQuotas / LimitRange Anti-DoS

```yaml
# LimitRange: enforce reasonable defaults + prevent ratio abuse
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: production
spec:
  limits:
  - type: Container
    default:
      cpu: "500m"
      memory: "256Mi"
    defaultRequest:
      cpu: "100m"
      memory: "128Mi"
    max:
      cpu: "4"
      memory: "8Gi"
    min:
      cpu: "50m"
      memory: "64Mi"
    maxLimitRequestRatio:
      cpu: "10"
      memory: "4"
---
# ResourceQuota: aggregate namespace caps
apiVersion: v1
kind: ResourceQuota
metadata:
  name: production-quota
  namespace: production
spec:
  hard:
    requests.cpu: "20"
    requests.memory: "40Gi"
    limits.cpu: "40"
    limits.memory: "80Gi"
    requests.storage: "500Gi"
    persistentvolumeclaims: "20"
    pods: "50"
    services: "10"
    secrets: "20"
    configmaps: "30"
  scopes: ["NotTerminating"]
```

**Anti-DoS:**
| Control | Security Benefit |
|---------|-----------------|
| `LimitRange.maxLimitRequestRatio` | Prevents a single pod from reserving 10× what it uses (resource hoarding) |
| `ResourceQuota.pods` / `services` / `secrets` | Caps namespace-wide resource abuse |
| `memory limits` | OOM-kill grants predictable resource boundaries; prevents noisy neighbor swap thrash |

---

## 5. Common Security Misconfigurations

| Misconfiguration | Risk | Fix |
|------------------|------|-----|
| **Missing `requests` on pods** | `BestEffort` QoS → first to evict; no scheduling constraints; overprovisioned pods can exhaust node | Always set `requests` (`LimitRange.defaultRequest` enforces this) |
| **`--privileged`** | Full host access; disables seccomp, AppArmor, kernel captures | Never use in production; isolate via `RuntimeClass` + VM-based runtime (Kata, gVisor) for privileged workloads |
| **HostPath volumes (R/W)** | Container writes to arbitrary host paths; host takeover if image compromised | Use strictly R/O hostPath or preferably `emptyDir` / PVCs |
| **`--pid=host`** | Container can kill/signal all host processes | Use only for debugging; never in prod |
| **`hostNetwork: true`** | Same attack surface as running on host | Use CNI-managed networks; expose via Service/Ingress |
| **`allowPrivilegeEscalation: true`** (default if not set) | If the app calls `setuid`, escalation is possible | Explicitly set to `false` |
| **`seccompProfile` unset** | Container can call 600+ syscalls | Use `RuntimeDefault`; custom profiles only when needed |
| **`securityContext.fsGroup` not set for `/dev/shm`** | PostgreSQL often sleeps at startup due to wrong ownership | Set `fsGroup` = DB user UID |
| **`sysctls: kernel.*`** | Node-level sysctls cannot be set per pod — admission controller rejects unless `sysctl-safe` annotation is placed | Stick to namespaced `net.*`, `kernel.shm_rmid_forced`; for node-level changes, use node taints/labels and `systemd-sysctl` |
| **No `podSecurityContext.seccompProfile`** | If the image is running setuid via suid binary, escapes possible in some older runtimes | Set `seccompProfile.type: RuntimeDefault` on the pod level (container-level overrides) |
| **`oom-kill-disable` + no `memory` limit** | Host OOM kills other pods instead | Never set `--oom-kill-disable`; set both reservation + limit and tune `swappiness` |

---

## 6. Seccomp & Landlock (Syscall Filtering)

### 6.1 Use `RuntimeDefault` Profile

The `RuntimeDefault` is curated (~254 syscalls allowed for containers). It blocks:

| Syscall Category | Dangerous Syscalls Blocked |
|------------------|---------------------------|
| **Kernel persistence** | `kexec_load`, `reboot`, `kexec_file_load` |
| **Modules** | `module_load`, `delete_module` |
| **Process manipulation** | `ptrace`, `process_vm_readv/writev` |
| **Filesystem remount** | `mount`, `umount`, `pivot_root`, `fsconfig` |
| **System time** | `clock_settime`, `settimeofday`, `adjtimex` |
| **Unprivileged BPF** | `bpf` (some kernels allow; set `kernel.unprivileged_bpf_disabled=1`) |
| **User-mode fault pages** | `userfaultfd` |
| **Host IPC** | `shmctl`, `msgctl` (only via namespaced sysctls) |

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

### 6.2 Custom Profile for Minimal Surface

Use only for specialized workloads (e.g., some FUSE deployments, networking agents):

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "read", "write", "close", "fstat", "mmap", "mprotect", "munmap",
        "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl",
        "pread64", "pwrite64", "readv", "writev", "access", "pipe2",
        "select", "pselect6", "poll", "ppoll", "epoll_create1",
        "epoll_ctl", "epoll_wait", "getpid", "socket", "connect",
        "sendto", "recvfrom", "bind", "listen", "accept4", "dup2",
        "restart_syscall", "exit_group", "set_tid_address", "set_robust_list"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

Apply via: `--security-opt seccomp:/path/to/profile.json` (Docker) or `seccompProfile.type: LocalProfile` (K8s).

### 6.3 Landlock (Future-Proof Inode Confinement)

Landlock provides filesystem access control via `landlock` profiles (newer kernels). Configure via AppArmor or seccomp-landlock bridge (when supported).

```bash
# Check landlock support
grep landlock /proc/self/status
# Landlock: 1 (ABI level)
```

Use `security-opt=apparmor:landlock` or set a dedicated profile. Landlock is particularly useful for:
- Restricting `/proc` `/sys` read-only (beyond cgroup)
- Granular path-based confinement (e.g., `/var/lib/data` only)
- Complementing seccomp (seccomp for syscalls, Landlock for paths)

---

## 7. Admission Controller Integration

### 7.1 Kyverno Gatekeeper / OPA Gatekeeper

**Kyverno policy to enforce restricted:**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-seccomp-profile
spec:
  validationFailureAction: enforce
  background: false
  rules:
  - name: enforce-runtime-default-seccomp
    match:
      resources:
        kinds: ["Pod"]
    validate:
      message: "seccompProfile.type must be RuntimeDefault"
      pattern:
        spec:
          securityContext:
            seccompProfile:
              type: "RuntimeDefault"
  - name: block-privileged
    match:
      resources:
        kinds: ["Pod"]
    validate:
      message: "privileged containers are not allowed"
      pattern:
        spec:
          containers:
          - =(securityContext):
              X(privileged): true
```

**OPA/Rego for no host namespaces:**

```rego
package kubernetes.restricted
import data.kubernetes

deny[msg] {
  input.kind == "Pod"
  input.spec.hostPID == true
  msg := "hostPID is not allowed"
}

deny[msg] {
  input.kind == "Pod"
  input.spec.hostNetwork == true
  msg := "hostNetwork is not allowed"
}

deny[msg] {
  input.kind == "Pod"
  some c
  input.spec.containers[c].securityContext.privileged == true
  msg := "privileged containers are not allowed"
}
```

### 7.2 Image Signing

Use `notation` or `cosign` with `kritis` or `policy-controller`:

```bash
# Sign image
cosign sign --key cosign.key docker.io/your-org/app:v1

# Verify in admission controller
kubectl create configmap kritis-config --from-file=policy.yaml
# policy.yaml:
#   signature:
#     keys:
#     - key: "cosign.pub"
#   match: ""
#   requirements:
#   - signature:
#       signed_by:
#       keys:
#       - key: "cosign.pub"
```

---

## 8. Runtime Classes for Hardened Isolation

### 8.1 Kata Containers (VM-based Isolation)

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-containers
handler: kata-qemu
overhead:
  podFixed:
    memory: "160Mi"
    cpu: "100m"
```

Use for:
- Multi-tenant isolation when VM per-tenant is too costly
- Legacy privileged workloads (without giving full host access)
- Confidential computing (AMD SEV, Intel TDX) when paired with Kata

**Trade-off:** ~160Mi memory + ~100m CPU overhead per pod; slower startup (cold boot VM).

### 8.2 gVisor (userspace kernel)

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
```

Use for:
- Untrusted workloads (CI jobs, user-submitted containers)
- Trade-off: slightly slower CPU/IO than runc, but ~1–2Mi overhead vs VM. Partial syscall compatibility (some Linux syscalls unimplemented).

### 8.3 WASM Runtimes (WASI)

| Runtime | Use Case | Isolation |
|---------|----------|-----------|
| `wasmedge` | Portable sandboxed functions (e.g., edge handlers) | Strong (no host syscalls) |
| `wasmtime` | Cloud workloads with polyglot support | Strong |
| `spin` | Fermyon Spin app model | Strong, but needs gateway |

WASM at the edge: tight resource caps; suitable for function workloads.

---

## 9. Incident Detection & Audit

### 9.1 Kubernetes Audit Logs

Enable `--audit-log-path`, `--audit-log-maxage`, `--audit-log-maxsize`, `--audit-log-maxbackup`. Filter `auditd` output for:

| Event | What to Watch | Potential Indicator |
|-------|---------------|---------------------|
| `AdmissionReview` with `privileged=true` | Privileged pod schedule | Breakout attempt or misconfiguration |
| `AdmissionReview` with `hostPID=true` or `hostNetwork=true` | Host namespace usage | Unauthorized sysadmin access |
| `AdmissionReview` with `volumes:\[{hostPath: …}]` | Host volume mount | Host takeover risk |
| `PodSecurityPolicy` / `PodSecurityLabel` violations | Restricted bypass | Admission policy drift |
| `RBAC` `create`/`delete` on `ClusterRole`/`Role` | Privilege escalation clustering | Admin account takeover |

### 9.2 Seccomp and Security Logs

Collect from container runtime (containerd, CRI-O):

```bash
# containerd seccomp logs (journalctl -u containerd)
# Look for:
#   seccomp: "ip setsockopt" failed: Operation not permitted  (blocked syscall)
```

For Linux 6.6+ (cgroup v2 landlock), monitor `dmesg` for `landlock: denied` messages.

### 9.3 Prometheus Alerts

```yaml
# OOM kill detection
- alert: ContainerOOMKilling
  expr: rate(kube_pod_container_status_restarts_total{reason="OOMKilled"}[5m]) > 0
  for: 0m
  annotations:
    summary: "Container {{ $labels.container }} in {{ $labels.pod }} was OOM-killed"

# Privileged pod schedules
- alert: PrivilegedPodScheduled
  expr: sum(kube_pod_info{privileged}) by (namespace) > 0
  for: 0m
  annotations:
    summary: "Privileged pod {{ $labels.pod }} scheduled in namespace {{ $labels.namespace }}"

# Host namespace usage
- alert: HostNetworkPodScheduled
  expr: sum(kube_pod_info{host_network}) by (namespace) > 0
  for: 0m
  annotations:
    summary: "Pod with hostNetwork: {{ $labels.pod }} in namespace {{ $labels.namespace }}"

# PID pressure
- alert: PodPidsExhausting
  expr: kube_pod_container_info{pids_limit:int}<1000 and pids_used:int>pids_limit*0.9
  for: 5m
  annotations:
    summary: "Container {{ $labels.container }} PID count nearing limit"

# File descriptor exhaustion
- alert: ContainerFDExhaustion
  expr: process_open_fds / process_max_fds > 0.85
  for: 10m
  annotations:
    summary: "High FD usage {{ $labels.container }}"

# CPU throttling>50%
- alert: ContainerCPUThrottlingHigh
  expr: rate(container_cpu_cfs_throttled_periods_total[5m]) / rate(container_cpu_cfs_periods_total[5m]) > 0.5
  for: 10m
  annotations:
    summary: "Container {{ $labels.container }} CPU throttled >50%"
```

---

## 10. Recommended Baseline Audits

### 10.1 Weekly (Automated via CronJob)

**Scan for privileged containers:**
```yaml
# CronJob: /tmp/audit-privileged.sh
kubectl get pods -A -o json |
  jq '.items[] | select(.spec.hostPID or (.spec.hostNetwork) or (.spec.containers[] | .securityContext?.privileged == true)) |
    {namespace: .metadata.namespace, pod: .metadata.name, privileged: .spec.hostPID,
     hostNetwork: .spec.hostNetwork,
     privileged_containers: [.spec.containers[] | select(.securityContext?.privileged == true) | .name]}'
```

**Scan for best-effort pods:**
```bash
kubectl get pods -A -o json | jq '.items[] |
  select(.status.qosClass == "BestEffort") |
  {namespace: .metadata.namespace, pod: .metadata.name}'
```

**Validate `seccompProfile` set:**
```bash
kubectl get pods -A -o json | jq '.items[] |
  select(.spec.securityContext?.seccompProfile?.type != "RuntimeDefault" and
         (.spec.containers[] | .securityContext?.seccompProfile?.type != "RuntimeDefault")) |
  {namespace: .metadata.namespace, pod: .metadata.name, missing: true}'
```

### 10.2 Monthly (Ops Team Review)

- Review and update `SecurityPolicy` rules (Kyverno/OPA)
- Audit `RoleBinding` / `ClusterRoleBinding` for `.subjects.kind=Group` with too admin-heavy permissions
- Recompute precision/recall: measure false positive (legitimate pods rejected) vs false negative (restricted bypasses)
- Perform pen-test on QA cluster: attempt `kubectl run --privileged= ...`

### 10.3 Per-Incident

When incident occurs:
1. Collect `kubectl logs` for the breached pod(s)
2. Run `kubectl get pod -o yaml ...` and store for post-mortem
3. Pull container image, verify manifest (cosign verify)
4. Check logs: journalctl -u kubelet, journalctl -u containerd
5. Run `ss -tuln` on host to detect unexpected listeners
6. Run `ls -lZ /var/run/docker.sock` (if Docker still present) for permission drift

---

## 11. Tightest Hardening Profile (For Air-Gapped/High-Security)

### 11.1 Docker Daemon

```json
{
  "cgroup-parent": "system.slice",
  "default-ulimits": {
    "nofile": {"Hard": 65535, "Soft": 65535},
    "nproc": {"Hard": 8192, "Soft": 4096}
  },
  "log-driver": "journald",
  "live-restore": true,
  "userns-remap": "default",
  "no-new-privileges": true,
  "ip-forward": false,
  "iptables": false,
  "default-runtime": "runc"
}
```

### 11.2 Kubelet Flags

```bash
# /etc/kubernetes/kubelet
--enforce-node-allocatable=pods,kube-reserved
--kube-reserved=cpu=500m,memory=500Mi
--system-reserved=cpu=1,memory=1Gi
--protect-kernel-defaults=true
--make-iptables-util-chains=true
--pod-manifest-path=/etc/kubernetes/manifests
--cgroup-driver=systemd
--container-runtime=remote
--container-runtime-endpoint=unix:///run/containerd/containerd.sock
```

### 11.3 Kernel Parameters

```bash
# /etc/sysctl.d/99-security-hardening.conf (applied in `99-production` order)
kernel.kexec_load_disabled=1
kernel.unprivileged_bpf_disabled=1
kernel.perf_event_paranoid=2
kernel.yama.ptrace_scope=2
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.tcp_syncookies=1
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_tw_reuse=1
```

### 11.4 Admission Controls

- Enforce `PodSecurityStandards: restricted` atkube-api-server via `--enable-admission-plugins=PodSecurity,NodeRestriction,ResourceQuota`
- Kyverno + Gatekeeper cross-checks
- `kubectl label ns production pod-security.kubernetes.io/enforce=restricted`
- `NetworkPolicy` default-deny + explicit allow rules per namespace

### 11.5 Logging

- `audit-log-path=/var/log/kubernetes/audit.log`
- `audit-log-maxage=90`
- `audit-log-maxsize=500M`
- `audit-log-maxbackup=20`
- `audit-log-format=json`

---

## 12. Quick Reference: Security Checklist

| Layer | Checklist Items |
|-------|------------------|
| **Host/VM** | `kernel.kexec_load_disabled=1`, `kernel.unprivileged_bpf_disabled=1`, `kernel.perf_event_paranoid=2`, `kernel.yama.ptrace_scope=2`, `net.ipv4.conf.all.rp_filter=1` |
| **Docker daemon** | `userns-remap=default`, `no-new-privileges=true`, `iptables=false`, `ip-forward=false`, `default-ulimits` strict |
| **Container** | `--cap-drop ALL`, `--read-only`, `--user`, `--security-opt no-new-privileges`, `--security-opt seccomp=RuntimeDefault`, `--pids-limit=100` |
| **Pod** | `securityContext.runAsNonRoot`, `allowPrivilegeEscalation=false`, `readOnlyRootFilesystem=true`, `seccompProfile.type=RuntimeDefault`, `requests`+`limits` set |
| **Namespace** | `PodSecurityStandard: restricted`, `LimitRange`, `ResourceQuota`, `NetworkPolicy` default-deny |
| **Runtime** | Use `RuntimeClass` (Kata/gVisor) for unprivileged isolation when possible |
| **Image** | Signed (`cosign`), minimal base (`alpine`, `debian:slim`), non-root entrypoint, vendored deps |

---

## 13. Out-of-Band Hardening

### 13.1 Immutable Infrastructure

- Build images once; reuse across environments.
- Tag with SHA256 digest (`docker.io/org/app@sha256:...`).
- Avoid `latest`; enforce via admission controller.

### 13.2 Secrets Management

- Use `SealedSecrets`, `ExternalSecrets`, or Vault.
- Never commit secrets to git; rotate at least quarterly.

### 13.3 Vulnerability Scanning

- Daily: `trivy image --severity HIGH,CRITICAL repo/app:tag` → block in ScanPolicy
- Hourly: CI pipeline `trivy filesystem .` (dev builds)
- Monthly: SBOM generation (`syft`), store in release artifacts

### 13.4 Backups

- Backup etcd (`etcdctl snapshot save backup.db`) every 6 hours.
- Restore test quarterly.
- Store off-site (airgapped or encrypted cloud bucket).

---

## 14. Incident Response Playbook

1. **Contain**: `kubectl label pod <pod> incident-quarantine=true` → use existing selector with `NetworkPolicy` isolate
2. **Preserve**: `kubectl cp <pod>:/var/log* /tmp/`, `kubectl logs -c <container> > /tmp/logs.txt`, kube-audit dump
3. **Investigate**: Review `journalctl -u kubelet`, `journalctl -u containerd`, `dmesg`, `syslog`
4. **Post-mortem**: Document timeline, identify misconfig or exploit, update controls
5. **Patch**: Update images, fix admission policy, add new alerts

---

## 15. Further Reading

- **CIS Docker Benchmark**: https://www.cisecurity.org/benchmark/docker
- **CIS Kubernetes Benchmark**: https://www.cisecurity.org/benchmark/kubernetes
- **NIST SP 800-190**: Container Security
- **kata-containers docs**: https://kata-containers.org/docs/
- **seccomp docs**: `man 2 seccomp`, https://www.kernel.org/doc/Documentation/userspace-api/seccomp_filter.rst
- **landlock docs**: https://docs.kernel.org/userspace-api/landlock.html
