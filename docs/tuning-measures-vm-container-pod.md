# Resource Tuning Measures for VMs, Containers, and Kubernetes Pods

> A practical compendium of kernel parameters, cgroups, ulimits, sysctls, and
> orchestration-level controls — organized by isolation layer with workload-specific
> recommendations.

---

## 1. Isolation Layers Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Bare Metal / VM                                                 │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Host Kernel: sysctl, ulimit, sysfs, /proc, cgroup v2      │ │
│  └─────────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────┐  ┌──────────────────────────────────┐ │
│  │  Docker Container   │  │  Kubernetes Pod                  │ │
│  │  ┌────────────────┐  │  │  ┌────────────────────────────┐  │ │
│  │  │ cgroup v2 slice │  │  │  │ LimitRange / ResourceQuota │  │ │
│  │  │ seccomp profile │  │  │  │ PodOverhead                 │  │ │
│  │  │ ulimit override │  │  │  │ CPU Manager / Topology Mgr  │  │ │
│  │  │ sysctls (net.*) │  │  │  │ SecurityContext              │  │ │
│  │  │ capabilities    │  │  │  │ RuntimeClass (crun/wasm)     │  │ │
│  │  └────────────────┘  │  │  └────────────────────────────┘  │ │
│  └──────────────────────┘  └──────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Host/VM Level — Kernel Parameters (`sysctl`)

### 2.1 Networking (`net.core.*`, `net.ipv4.*`)

| Parameter | Default | Tuned Value | Purpose |
|-----------|---------|-------------|---------|
| `net.core.somaxconn` | 4096 | 65535 | Max pending TCP SYN for `listen()` (high-traffic servers) |
| `net.core.netdev_max_backlog` | 1000 | 5000+ | Max queued packets before `ifconfig` drops |
| `net.core.rmem_max` | 2129920 (2MB) | 134217728 (128MB) | Max TCP receive buffer |
| `net.core.wmem_max` | 2129920 (2MB) | 134217728 (128MB) | Max TCP send buffer |
| `net.core.rmem_default` | 2129920 | 26214400 (25MB) | Default TCP receive buffer |
| `net.core.wmem_default` | 2129920 | 26214400 (25MB) | Default TCP send buffer |
| `net.ipv4.tcp_max_syn_backlog` | 128 | 8192 | Max half-open connections (SYN flood protection) |
| `net.ipv4.tcp_tw_reuse` | 0 | 1 | Allow reuse of TIME-WAIT sockets (safe for modern TCP stacks) |
| `net.ipv4.tcp_fin_timeout` | 60 | 15 | TIME-WAIT timeout (shorter = faster socket recycling) |
| `net.ipv4.tcp_keepalive_time` | 7200 | 600 | Keepalive interval (detect dead peers faster) |
| `net.ipv4.tcp_keepalive_intvl` | 75 | 30 | Interval between keepalive probes |
| `net.ipv4.tcp_keepalive_probes` | 9 | 5 | Probes before dropping connection |
| `net.ipv4.tcp_slow_start_after_idle` | 1 | 0 | Disable slow-start restart (throughput continuity) |
| `net.ipv4.tcp_no_metrics_save` | 0 | 1 | Don't cache TCP metrics per route (avoids stale congestion state) |
| `net.ipv4.tcp_rfc1337` | 0 | 1 | Protect against TIME-WAIT assassination |
| `net.ipv4.tcp_syncookies` | 1 | 1 | SYN cookies (DDoS protection — keep ON) |
| `net.ipv4.ip_local_port_range` | 32768–60999 | 1024–65535 | Ephemeral port range (wider = more outbound connections) |
| `net.ipv4.tcp_max_tw_buckets` | 262144 | 262144 | TIME-WAIT bucket limit |
| `net.ipv4.conf.all.rp_filter` | 1 | 1 | Reverse path filtering (keep ON for anti-spoofing) |
| `net.ipv4.conf.all.accept_redirects` | 1 | 0 | Disable ICMP redirects (security hardening) |
| `net.ipv4.tcp_mtu_probing` | 0 | 1 | Enable MTU path discovery (avoid PMTU black holes) |
| `net.core.optmem_max` | 20480 | 65536 | Max ancillary buffer (socket options, BPF) |

**Apply persistently:**
```bash
# /etc/sysctl.d/99-production.conf
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.ip_local_port_range = 1024 65535
```

### 2.2 Memory Management (`vm.*`)

| Parameter | Default | Database Tuned | Web Server Tuned | Purpose |
|-----------|---------|-----------------|-------------------|---------|
| `vm.swappiness` | 60 | 1–10 | 10–30 | Swappiness (0 = avoid swap, 60 = aggressive swap) |
| `vm.overcommit_memory` | 0 | 0 | 0 | 0=heuristic, 1=always allow, 2=don't overcommit |
| `vm.overcommit_ratio` | 50 | 50 | 50 | % of RAM for overcommit (mode 2 only) |
| `vm.dirty_ratio` | 20 | 10 | 20 | % of RAM before dirty pages force writeback |
| `vm.dirty_background_ratio` | 10 | 5 | 10 | % of RAM before background writeback starts |
| `vm.dirty_background_bytes` | — | 0 | 0 | Override ratio (0 = use ratio) |
| `vm.drop_caches` | 0 | — | — | 1=pagecache, 2=slab, 3=both (one-shot, not persistent) |
| `vm.min_free_kbytes` | ~67536 | 131072 (128MB) | 65536 (64MB) | Reserved free memory (emergency allocation) |
| `vm.max_map_count` | 65530 | 262144 | 262144 | Max mmap areas (Elasticsearch, Chromium need high values) |
| `vm.nr_hugepages` | 0 | 1024+ | 0 | Pre-allocated huge pages (2MB each; DBs, DPDK, VMs) |
| `vm.hugetlb_shm_group` | 0 | gid | — | Group allowed to use huge page shared memory |
| `vm.zone_reclaim_mode` | 0 | 0 | 0 | NUMA zone reclaim (keep 0; hurts performance) |
| `vm.compaction_proactiveness` | 20 | 20 | 20 | How aggressively compact memory for huge pages |

**Workload-specific:**

```bash
# === PostgreSQL / Database VM ===
vm.swappiness = 1               # Minimize swap; DB manages its own cache
vm.dirty_ratio = 10             # Start writeback earlier
vm.dirty_background_ratio = 5
vm.min_free_kbytes = 131072     # 128MB reserve
vm.nr_hugepages = 1024          # 2GB huge pages for shared buffers
vm.max_map_count = 262144

# === Redis / In-Memory Cache VM ===
vm.overcommit_memory = 1         # Always allow (Redis saves on disk async)
vm.swappiness = 1
vm.dirty_ratio = 5
vm.min_free_kbytes = 131072

# === Kafka / Event Streaming VM ===
vm.swappiness = 1
vm.dirty_ratio = 20
vm.dirty_background_ratio = 15
vm.min_free_kbytes = 131072
vm.max_map_count = 262144

# === General Web Server VM ===
vm.swappiness = 10
vm.dirty_ratio = 20
```

### 2.3 Filesystem (`fs.*`)

| Parameter | Default | Tuned Value | Purpose |
|-----------|---------|-------------|---------|
| `fs.file-max` | ~209715 (auto) | 2097152 | System-wide open file descriptor limit |
| `fs.nr_open` | 1048576 | 1048576 | Per-process hard limit on open FDs |
| `fs.inotify.max_user_watches` | 8192 | 524288 | Inotify watchers (IDEs, build tools, file sync) |
| `fs.inotify.max_user_instances` | 128 | 512 | Inotify instances per user |
| `fs.inotify.max_queued_events` | 16384 | 32768 | Inotify event queue size |
| `fs.aio-max-nr` | 65536 | 1048576 | Async I/O events (Oracle, PostgreSQL, FIO) |
| `fs.epoll.max_user_watches` | — | varies | epoll watchers (modern kernels share with inotify) |
| `fs.pipe-max-size` | 1048576 | 1048576 | Max pipe buffer size (65536 × 16 pages) |
| `fs.mqueue.msg_max` | 10 | 100 | POSIX message queue max messages |
| `fs.mqueue.msgsize_max` | 8192 | 65536 | Max message queue entry size |
| `fs.protected_regular` | 1 | 1 | Prevent O_CREAT writes to regular files with sticky bit (CVE-2022-0847 mitigation) |
| `fs.protected_fifos` | 2 | 2 | Restrict FIFO writes (sticky bit protection) |

### 2.4 Kernel (`kernel.*`)

| Parameter | Default | Tuned Value | Purpose |
|-----------|---------|-------------|---------|
| `kernel.pid_max` | 32768 (or 4194304) | 4194304 | Max PID (prevent PID exhaustion with many containers) |
| `kernel.threads-max` | auto | auto | Max threads (derived from RAM) |
| `kernel.sem` | 32000 1024000000 500 32000 | 250 32000 32 1024 | SysV IPC semaphore limits (arrays, semaphores, ops, max) |
| `kernel.shmmax` | 18446744073692774399 | 68719476736 (64GB) | Max shared memory segment size |
| `kernel.shmall` | 18446744073692774399 | 4294967296 | Total shared memory pages |
| `kernel.msgmax` | 8192 | 65536 | Max message queue message size |
| `kernel.msgmnb` | 16384 | 65536 | Max message queue byte size |
| `kernel.core_pattern` | core | `/var/core/%e.%p.%t.core` | Core dump location |
| `kernel.panic` | 0 | 30 | Reboot N seconds after panic (0 = don't reboot) |
| `kernel.watchdog` | 1 | 1 | Hardware watchdog (reboot on hard lockup) |
| `kernel.keys.maxkeys` | 200 | 1000 | Max keys in keyring |
| `kernel.keys.maxbytes` | 20000 | 100000 | Max keyring bytes |

### 2.5 Security Hardening (`kernel.*`, `net.*`)

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `kernel.kexec_load_disabled` | 1 | Disable kexec (prevent rootkit persistence) |
| `kernel.modules_disabled` | 1 | Disable module loading (post-boot hardening; breaks many things) |
| `kernel.unprivileged_bpf_disabled` | 1 | Disable unprivileged BPF |
| `kernel.perf_event_paranoid` | 2 | Restrict perf to root only |
| `kernel.yama.ptrace_scope` | 2 | Restrict ptrace (no cross-process debugging without parent) |
| `kernel.dmesg_restrict` | 1 | Restrict dmesg to root |
| `kernel.kptr_restrict` | 2 | Hide kernel pointers |
| `net.ipv4.conf.all.accept_source_route` | 0 | Reject source-routed packets |
| `net.ipv4.conf.all.send_redirects` | 0 | Don't send ICMP redirects |
| `net.ipv4.conf.all.log_martians` | 1 | Log martian packets |
| `net.ipv6.conf.all.disable_ipv6` | 0/1 | Disable IPv6 if unused (reduces attack surface) |

---

## 3. Process/User Level — `ulimit` (PAM, shells, Docker)

### 3.1 Standard `ulimit` Flags

| Flag | Name | Typical Host Default | Container Default | Production Tuning |
|------|------|---------------------|-------------------|-------------------|
| `-n` | open files (nofile) | 1048576 | 1048576 | 65535–1048576 |
| `-u` | max processes (nproc/MaxTasks) | 61125 | unlimited | 4096–65535 |
| `-l` | max locked memory (memlock) | 1983432 (~2GB) | unlimited | unlimited (DPDK, DB) |
| `-s` | stack size | 8192 KB | 8192 KB | 8192 KB (or 65536 for Java) |
| `-m` | max data segment | unlimited | unlimited | unlimited |
| `-f` | max file size | unlimited | unlimited | unlimited |
| `-c` | core file size | 0 | 0 | 0 (prod) or unlimited (debug) |
| `-e` | scheduling priority | 0 | 0 | 0 |
| `-r` | real-time priority | 0 | 0 | 0 (unless RT workload) |
| `-p` | pipe buffer size | 8 (×512B) | 8 | 8 |
| `-q` | POSIX msg queues | 819200 B | 819200 B | 819200 B |
| `-v` | virtual memory | unlimited | unlimited | unlimited |
| `-x` | file locks | unlimited | unlimited | unlimited |
| `-i` | pending signals | 61125 | unlimited | unlimited |
| `-t` | CPU time | unlimited | unlimited | unlimited |
| `-R` | real-time nanoseconds | unlimited | unlimited | unlimited |

### 3.2 Setting ulimits

```bash
# === System-wide: /etc/security/limits.conf ===
# <domain>    <type>  <item>         <value>
*             hard    nofile         1048576
*             soft    nofile         65535
*             hard    nproc          65535
*             soft    nproc          4096
root          hard    nofile         1048576
root          soft    nofile         1048576
postgres      hard    nofile         131072
postgres      soft    nofile         131072
postgres      hard    memlock        unlimited
postgres      soft    memlock        unlimited
redis         hard    nofile         65535
redis         soft    nproc          4096
www-data      hard    nproc          16384
elasticsearch hard    nofile         65535
elasticsearch soft    nofile         65535
elasticsearch hard    memlock        unlimited
elasticsearch soft    memlock        unlimited

# === Per-session: /etc/security/limits.d/ ===
# 90-nofile.conf:
*     soft    nofile   65535
*     hard    nofile   1048576

# === Systemd service override ===
# /etc/systemd/system/myservice.service.d/limits.conf
[Service]
LimitNOFILE=1048576
LimitNPROC=65535
LimitMEMLOCK=infinity
LimitSIGPENDING=61125
```

### 3.3 Docker Container ulimits

```yaml
# docker-compose.yml
services:
  web:
    ulimits:
      nofile:
        soft: 65535
        hard: 65535
      nproc:
        soft: 4096
        hard: 8192
      memlock:
        soft: -1    # unlimited
        hard: -1
```

```bash
# docker run
docker run --ulimit nofile=65535:65535 --ulimit nproc=4096:8192 ...

# Docker daemon default ulimits: /etc/docker/daemon.json
{
  "default-ulimits": {
    "nofile": {"name": "nofile", "hard": 65535, "soft": 65535},
    "nproc": {"name": "nproc", "hard": 65535, "soft": 4096}
  }
}
```

---

## 4. Container Level — Docker Resource Controls

### 4.1 CPU Controls

| Flag / File | Example | Effect |
|-------------|---------|--------|
| `--cpus=<n>` | `--cpus=2.5` | Limit to 2.5 CPU cores (equivalent to CFS quota) |
| `--cpuset-cpus` | `--cpuset-cpus=0-3` | Pin to specific CPU cores (NUMA affinity) |
| `--cpu-shares` | `--cpu-shares=512` | Relative weight (default 1024; 512 = half priority) |
| `--cpu-period` | `--cpu-period=100000` | CFS period in microseconds (default 100ms) |
| `--cpu-quota` | `--cpu-quota=50000` | CFS quota in microseconds (50000/100000 = 0.5 CPU) |
| `--cpu-rt-period` | `--cpu-rt-period=1000000` | Real-time scheduling period (requires `--cap-add SYS_ADMIN`) |
| `--cpu-rt-runtime` | `--cpu-rt-runtime=500000` | Real-time scheduling runtime |

```bash
# Examples
docker run --cpus=2 --cpuset-cpus=0-1 nginx       # 2 cores, pinned to core 0-1
docker run --cpu-shares=512 --cpu-shares=512 app   # half weight vs default
docker run --cpu-period=50000 --cpu-quota=25000 app  # 0.5 CPU
```

### 4.2 Memory Controls

| Flag / File | Example | Effect |
|-------------|---------|--------|
| `--memory` / `-m` | `--memory=2g` | Memory limit (soft+hard combined) |
| `--memory-reservation` | `--memory-reservation=1g` | Soft limit (OOM only when below this + contention) |
| `--memory-swap` | `--memory-swap=3g` | Total memory+swap; `-1` = unlimited swap |
| `--memory-swappiness` | `--memory-swappiness=0` | Container-specific swappiness (0–100) |
| `--kernel-memory` | `--kernel-memory=100m` | Kernel memory limit (deprecated cgroup v2) |
| `--oom-kill-disable` | `--oom-kill-disable` | Don't OOM-kill this container (dangerous with unlimited memory) |
| `--shm-size` | `--shm-size=256m` | /dev/shm size (default 64MB; PostgreSQL needs 256m+) |
| `--tmpfs` | `--tmpfs /tmp:rw,size=1g` | tmpfs mount with size limit |

```bash
# Examples
docker run -m 2g --memory-reservation=1g --memory-swap=2g --memory-swappiness=10 nginx
docker run -m 512m --shm-size=256m --tmpfs /tmp:rw,size=512m postgres
```

### 4.3 PID Controls

| Flag | Example | Effect |
|------|---------|--------|
| `--pids-limit` | `--pids-limit=100` | Max processes (fork bomb protection) |

```bash
docker run --pids-limit=100 nginx    # prevent fork bombs
```

### 4.4 I/O Controls

| Flag / File | Example | Effect |
|-------------|---------|--------|
| `--device-read-bps` | `--device-read-bps /dev/sda:10mb` | Read bandwidth limit |
| `--device-write-bps` | `--device-write-bps /dev/sda:10mb` | Write bandwidth limit |
| `--device-read-iops` | `--device-read-iops /dev/sda:1000` | Read IOPS limit |
| `--device-write-iops` | `--device-write-iops /dev/sda:1000` | Write IOPS limit |
| `--blkio-weight` | `--blkio-weight=500` | Block I/O weight (10–1000, default 500) |
| `--io-maxbandwidth` | `--io-maxbandwidth=20mb` | Cgroup v2 I/O bandwidth (Docker 27+) |
| `--io-maxiops` | `--io-maxiops=500` | Cgroup v2 I/O IOPS (Docker 27+) |

```bash
docker run --device-read-bps /dev/sda:100mb --device-write-bps /dev/sda:50mb db
```

### 4.5 Security / Isolation Controls

| Flag | Effect |
|------|--------|
| `--cap-drop ALL` | Drop ALL Linux capabilities (start from zero) |
| `--cap-add NET_BIND_SERVICE` | Add specific capability back |
| `--cap-add SYS_PTRACE` | Allow ptrace (debugging) |
| `--cap-add CHOWN` | Allow chown |
| `--security-opt no-new-privileges:true` | Prevent privilege escalation via setuid |
| `--security-opt seccomp=profile.json` | Custom seccomp profile |
| `--security-opt apparmor=profile` | AppArmor profile |
| `--privileged` | Full host access (NEVER in production) |
| `--read-only` | Read-only root filesystem (use tmpfs for writable dirs) |
| `--user 1000:1000` | Run as non-root user |
| `--pid=host` | Share host PID namespace (for debugging only) |
| `--network=none` | No network (minimal attack surface) |
| `--sysctl net.core.somaxconn=4096` | Per-container sysctl (network namespace only) |
| `--tmpfs /run:rw,noexec,nosuid,size=64m` | Restricted tmpfs |

```yaml
# docker-compose.yml — hardened web service
services:
  web:
    image: nginx:alpine
    read_only: true
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    security_opt:
      - no-new-privileges:true
      - seccomp:./seccomp-profile.json
    user: "101:101"
    mem_limit: 512m
    memswap_limit: 512m
    pids_limit: 100
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
      - /var/cache/nginx:rw,noexec,nosuid,size=32m
      - /var/run:rw,noexec,nosuid,size=1m
    sysctls:
      net.core.somaxconn: "4096"
```

### 4.6 Docker Daemon Global Defaults

```json
// /etc/docker/daemon.json
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

---

## 5. Kubernetes Pod Level — Resource Controls

### 5.1 Resource Requests & Limits

```yaml
# requests = guaranteed minimum (scheduling, node selection)
# limits  = hard ceiling (cgroup enforcement, OOM-kill boundary)
resources:
  requests:
    memory: "256Mi"      # must be <= limit
    cpu: "250m"           # 250 millicores = 0.25 cores
    ephemeral-storage: "1Gi"
  limits:
    memory: "512Mi"
    cpu: "500m"
    ephemeral-storage: "2Gi"
```

**QoS Classes (automatically assigned):**

| QoS | Criteria | Behavior |
|-----|-----------|----------|
| **Guaranteed** | requests == limits (all resources) | Never killed (unless node pressure) |
| **Burstable** | requests < limits, or only requests set | Can be killed after BestEffort |
| **BestEffort** | no requests, no limits | First to be killed under pressure |

### 5.2 CPU Management Policies (per-node)

```bash
# Static policy: exclusive cores for Guaranteed pods with integer CPU requests
# /etc/default/kubelet or kubelet config
--cpu-manager-policy=static
--cpu-manager-cpu-exclusive-policy=full
# Full nodes want 1+ reserved cores (system daemons + kubelet)
--system-reserved=cpu=1,memory=1Gi
--kube-reserved=cpu=500m,memory=500Mi
```

**CPU Manager interaction with QoS:**
| Pod QoS | CPU Request | Behavior under `static` policy |
|---------|-------------|--------------------------------|
| Guaranteed, integer | `cpu: "2"` (whole number) | Exclusive pinned cores |
| Guaranteed, fractional | `cpu: "500m"` | Shared pool |
| Burstable | any | Shared pool |
| BestEffort | none | Shared pool |

### 5.3 Topology Manager (NUMA awareness)

```bash
# /etc/default/kubelet
--topology-manager-policy=best-effort  # default: try NUMA, fallback
--topology-manager-policy=restricted    # require NUMA alignment, reject if not possible
--topology-manager-policy=single-numa-node  # strict: all resources on one NUMA node
```

### 5.4 LimitRange — Namespace Defaults

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: production
spec:
  limits:
  - type: Container
    default:           # default limits (applied if not specified)
      cpu: "500m"
      memory: "256Mi"
    defaultRequest:    # default requests
      cpu: "100m"
      memory: "128Mi"
    max:
      cpu: "4"
      memory: "8Gi"
    min:
      cpu: "50m"
      memory: "64Mi"
    maxLimitRequestRatio:  # prevent limit:request ratio abuse (resource hogging)
      cpu: "10"
      memory: "4"
  - type: Pod
    max:
      cpu: "8"
      memory: "16Gi"
  - type: PersistentVolumeClaim
    max:
      storage: "100Gi"
    min:
      storage: "1Gi"
```

### 5.5 ResourceQuota — Namespace Caps

```yaml
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
    replicationcontrollers: "5"
  scopes: ["NotTerminating"]  # only applies to non-preemptible pods
---
# Separate quota for long-running vs batch
apiVersion: v1
kind: ResourceQuota
metadata:
  name: terminating-quota
  namespace: production
spec:
  hard:
    pods: "10"
  scopes: ["Terminating"]
```

### 5.6 PodOverhead (RuntimeClass)

```yaml
# Pod overhead accounts for sandbox overhead (container runtime, pause container)
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-containers
handler: kata-qemu
overhead:
  podFixed:    # Always added to every pod's resource accounting
    memory: "160Mi"
    cpu: "100m"
---
# Pod using the runtime class
apiVersion: v1
kind: Pod
metadata:
  name: with-overhead
spec:
  runtimeClassName: kata-containers
  containers:
  - name: nginx
    resources:
      limits:
        memory: "200Mi"
        cpu: "100m"
  # Total node accounting: 200Mi + 160Mi overhead = 360Mi
```

### 5.7 Pod Security Context

```yaml
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
    runAsNonRoot: true
    fsGroup: 1000
    supplementalGroups: [100, 200]
    seccompProfile:
      type: RuntimeDefault       # or type: LocalProfile, profile: ...
    sysctls:                      # Namespaced sysctls only (net.*, kernel.shm*)
    - name: net.core.somaxconn
      value: "4096"
    - name: kernel.shm_rmid_forced
      value: "1"
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]     # bind to ports < 1024
      seccompProfile:
        type: RuntimeDefault
    resources:
      requests:
        memory: "128Mi"
        cpu: "100m"
      limits:
        memory: "256Mi"
        cpu: "250m"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir:
      sizeLimit: "64Mi"
```

### 5.8 Sysctls in Pods (Namespaced Only)

Only **namespaced sysctls** can be set per pod. **Node-level sysctls** require host access:

| Namespaced (pod-level) | Node-level (host sysctl) |
|------------------------|------------------------|
| `net.core.somaxconn` | `net.core.netdev_max_backlog` |
| `net.core.netdev_budget` | `net.core.somaxconn` (shared) |
| `net.core.rmem_max` | `kernel.shmmax` |
| `net.core.wmem_max` | `kernel.pid_max` |
| `net.ipv4.tcp_syncookies` | `vm.swappiness` |
| `net.ipv4.ip_local_port_range` | `fs.file-max` |
| `net.ipv4.ip_unprivileged_port_start` | `fs.nr_open` |
| `net.ipv4.tcp_tw_reuse` | |
| `net.ipv4.tcp_fin_timeout` | |
| `net.ipv4.tcp_keepalive_time` | |
| `kernel.shm_rmid_forced` | |

```yaml
spec:
  sysctls:
  - name: net.core.somaxconn
    value: "4096"
  - name: net.ipv4.ip_local_port_range
    value: "1024 65535"
  - name: kernel.shm_rmid_forced
    value: "1"
```

### 5.9 PriorityClass & Preemption

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: high-priority
value: 1000000                # higher = more important (system-cluster-critical = 2000000000)
globalDefault: false
preemptionPolicy: PreemptLowerPriority
description: "Production services"
---
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: low-priority
value: 100
globalDefault: true
preemptionPolicy: PreemptLowerPriority
description: "Batch jobs"
```

---

## 6. cgroup v2 Deep Dive

### 6.1 Controllers & Interface Files

| Controller | Key Files | Purpose |
|-----------|-----------|---------|
| `cpu` | `cpu.max`, `cpu.weight`, `cpu.max.burst`, `cpu.stat` | CFS bandwidth limiting |
| `memory` | `memory.max`, `memory.min`, `memory.low`, `memory.high`, `memory.peak`, `memory.current`, `memory.swap.max` | Memory limits with low/high/min watermarks |
| `io` | `io.max`, `io.weight`, `io.stat` | Block I/O (BPF-based in v2) |
| `pids` | `pids.max`, `pids.current` | Process count limiting |
| `cpuset` | `cpuset.cpus`, `cpuset.mems`, `cpuset.effective` | CPU/core pinning |
| `hugetlb` | `hugetlb.2MB.max`, `hugetlb.1GB.max` | Huge page limits |
| `freezer` | `cgroup.freeze` | Freeze/thaw processes |
| `device` | (via BPF, not file-based) | Device access control |
| `rdma` | `rdma.max` | RDMA resource limits |

### 6.2 Memory Watermark Model (cgroup v2)

```
memory.current usage:
│
│    memory.high (throttling begins — page reclaim kicks in)
│    ─────────────────
│    memory.max  (hard limit — OOM-kill at this boundary)
│    ─────────────────
│
├──── memory.min ──── (never reclaim below this)
├──── memory.low ──── (prefer not to reclaim below this)
```

```bash
# Examples — cgroup v2 syntax
echo "500M"   > /sys/fs/cgroup/myapp/memory.max    # hard limit
echo "200M"   > /sys/fs/cgroup/myapp/memory.high   # soft throttle
echo "100M"   > /sys/fs/cgroup/myapp/memory.low     # prefer not to reclaim
echo "50M"    > /sys/fs/cgroup/myapp/memory.min     # never reclaim below
echo "max 100000" > /sys/fs/cgroup/myapp/cpu.max    # 0.1 CPU (quota/period)
echo "100"    > /sys/fs/cgroup/myapp/cpu.weight     # relative weight (1–10000)
echo "256"    > /sys/fs/cgroup/myapp/pids.max       # max 256 processes
```

### 6.3 Cgroup v1 vs v2 Key Differences

| Aspect | cgroup v1 | cgroup v2 |
|--------|-----------|-----------|
| Controllers | Separate per-resource hierarchies | Unified hierarchy |
| Memory accounting | Separate `memory.usage_in_bytes`, `memory.memsw.*` | `memory.current`, `memory.swap.current` |
| I/O control | `blkio.*` files | `io.max` (BPF-based) |
| CPU control | `cpu.cfs_quota_us`, `cpu.shares` | `cpu.max` (quota/period), `cpu.weight` |
| PIDs | `pids.max` (same) | `pids.max` (same) |
| Docker default | Hybrid (v1 for blkio, v2 for cpu/memory) | v2 only (modern Docker) |
| Kubelet default | v1 (legacy) | v2 (1.26+, default since 1.28) |

---

## 7. Workload-Specific Tuning Cheat Sheets

### 7.1 PostgreSQL / Database

```
sysctl:
  vm.swappiness = 1
  vm.dirty_ratio = 10
  vm.dirty_background_ratio = 5
  vm.min_free_kbytes = 131072
  vm.nr_hugepages = 1024         # if using huge pages for shared_buffers
  kernel.shmmax = 68719476736
  kernel.shmall = 4294967296
  fs.aio-max-nr = 1048576

ulimit:
  nofile = 131072
  memlock = unlimited
  nproc = 8192

Docker:
  --memory=4g --memory-reservation=3g --shm-size=256m
  --ulimit nofile=131072:131072 --ulimit memlock=-1:-1
  --pids-limit=500

Kubernetes:
  requests: { memory: "3Gi", cpu: "2" }
  limits:   { memory: "4Gi", cpu: "2" }   # guaranteed = static pinning
  securityContext:
    fsGroup: 999
  volumeMounts:
    - name: shm
      mountPath: /dev/shm
  volumes:
    - name: shm
      emptyDir:
        medium: Memory
        sizeLimit: "256Mi"
```

### 7.2 Redis / In-Memory Cache

```
sysctl:
  vm.overcommit_memory = 1
  vm.swappiness = 1
  vm.dirty_ratio = 5
  vm.min_free_kbytes = 65536

ulimit:
  nofile = 65535

Docker:
  --memory=2g --memory-reservation=1g --memory-swap=2g
  --cap-add IPC_LOCK      # for mlock (optional, depends on config)
  --pids-limit=100

Kubernetes:
  requests: { memory: "1Gi", cpu: "500m" }
  limits:   { memory: "2Gi", cpu: "1" }
```

### 7.3 Nginx / Web Server / Reverse Proxy

```
sysctl:
  net.core.somaxconn = 65535
  net.core.netdev_max_backlog = 5000
  net.core.rmem_max = 134217728
  net.core.wmem_max = 134217728
  net.ipv4.tcp_max_syn_backlog = 8192
  net.ipv4.tcp_tw_reuse = 1
  net.ipv4.tcp_fin_timeout = 15
  net.ipv4.tcp_keepalive_time = 600
  net.ipv4.ip_local_port_range = 1024 65535
  fs.file-max = 2097152

ulimit:
  nofile = 65535

Docker:
  --cpus=2 --memory=512m --pids-limit=200
  --sysctl net.core.somaxconn=4096

Kubernetes:
  requests: { memory: "256Mi", cpu: "500m" }
  limits:   { memory: "512Mi", cpu: "1" }
  sysctls:
    - name: net.core.somaxconn
      value: "4096"
```

### 7.4 Kafka / Event Streaming

```
sysctl:
  vm.swappiness = 1
  vm.dirty_ratio = 20
  vm.dirty_background_ratio = 15
  vm.min_free_kbytes = 131072
  vm.max_map_count = 262144
  net.core.rmem_max = 134217728
  net.core.wmem_max = 134217728
  net.ipv4.tcp_keepalive_time = 300
  net.ipv4.tcp_keepalive_intvl = 30
  net.ipv4.tcp_keepalive_probes = 3

ulimit:
  nofile = 100000

Kubernetes:
  requests: { memory: "4Gi", cpu: "2" }
  limits:   { memory: "8Gi", cpu: "4" }
  volumeMounts:
    - mountPath: /var/lib/kafka/data
  # For high throughput: consider exclusive CPU with NUMA pinning
```

### 7.5 Elasticsearch / Search Engine

```
sysctl:
  vm.max_map_count = 262144       # REQUIRED by ES
  vm.swappiness = 1
  vm.min_free_kbytes = 65536
  fs.file-max = 2097152

ulimit:
  nofile = 65535
  memlock = unlimited
  nproc = 4096

Docker:
  --memory=4g --memory-reservation=3g --ulimit memlock=-1:-1 --ulimit nofile=65535

Kubernetes:
  initContainer: sysctl -w vm.max_map_count=262144  # or host-level
  requests: { memory: "3Gi", cpu: "1" }
  limits:   { memory: "4Gi", cpu: "2" }
  securityContext:
    capabilities:
      add: ["IPC_LOCK"]
```

### 7.6 JVM Applications (Java/Spring/Quarkus)

```
sysctl:
  vm.max_map_count = 262144       # JNI, NIO, glibc malloc arenas
  fs.file-max = 2097152

ulimit:
  nofile = 65535
  nproc = 4096

Docker:
  --memory=2g --memory-reservation=1.5g
  -XX:MaxRAMPercentage=75.0        # modern: use % of container limit
  -XX:+UseContainerSupport         # auto-detect container limits (JDK 8u191+, 11+)
  -XX:+UseCGroupMemoryLimitForHeap

Kubernetes:
  requests: { memory: "1Gi", cpu: "1" }
  limits:   { memory: "2Gi", cpu: "2" }   # MaxRAMPercentage uses limits
  env:
    - name: JAVA_OPTS
      value: "-XX:MaxRAMPercentage=75.0 -XX:InitialRAMPercentage=50.0"
```

### 7.7 ML / GPU Workloads

```
sysctl:
  vm.swappiness = 0                # Never swap GPU pinned memory
  vm.nr_hugepages = 4096           # 8GB huge pages for NCCL/DPDK
  vm.min_free_kbytes = 131072

ulimit:
  nofile = 1048576
  memlock = unlimited              # CUDA pinned memory

Kubernetes:
  requests: { memory: "8Gi", cpu: "4", "nvidia.com/gpu": "1" }
  limits:   { memory: "16Gi", cpu: "8", "nvidia.com/gpu": "1" }
  runtimeClassName: nvidia        # requires RuntimeClass with handler
  hostIPC: true                    # NCCL shared memory optimization (less secure)
  securityContext:
    capabilities:
      add: ["IPC_LOCK"]
```

### 7.8 Sidecar / Ambassador / Envoy Proxy

```
Kubernetes:
  requests: { memory: "64Mi", cpu: "50m" }
  limits:   { memory: "128Mi", cpu: "100m" }
  # Keep tiny — this is infrastructure overhead
```

### 7.9 CronJob / Batch Workloads

```
Kubernetes:
  resources: {}                    # BestEffort — first to be evicted
  # OR with limits for resource safety:
  requests: { memory: "128Mi", cpu: "100m" }
  limits:   { memory: "256Mi", cpu: "500m" }
  # Use a low PriorityClass:
  priorityClassName: low-priority
  activeDeadlineSeconds: 3600      # auto-kill if stuck
  restartPolicy: OnFailure
  ttlSecondsAfterFinished: 86400   # auto-cleanup
```

---

## 8. Specialized Controls

### 8.1 Seccomp Profiles (syscall filtering)

```json
// Minimal seccomp profile — allow only specified syscalls
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    { "names": ["read","write","close","fstat","mmap","mprotect",
                "munmap","brk","ioctl","access","pipe2","dup2",
                "getpid","socket","connect","sendto","recvfrom",
                "bind","listen","accept4","epoll_create1","epoll_ctl",
                "epoll_wait","clock_gettime","exit_group"],
      "action": "SCMP_ACT_ALLOW" }
  ]
}
```

### 8.2 Huge Pages for DPDK / High-Performance Networking

```bash
# Reserve 1024 × 2MB = 2GB huge pages
echo 1024 > /sys/kernel/mm/transparent_hugepage/hpage_pmd_size
echo 1024 > /proc/sys/vm/nr_hugepages

# Or boot parameter
# default_hugepagesz=2M hugepagesz=2M hugepages=1024

# For K8s: mount hugepages in pod
volumes:
- name: hugepages-2mi
  emptyDir:
    medium: HugePages-2Mi
```

### 8.3 Transparent Huge Pages (THP)

```bash
# Check THP status
cat /sys/kernel/mm/transparent_hugepage/enabled
cat /sys/kernel/mm/transparent_hugepage/defrag

# For databases (PostgreSQL, MongoDB, Redis): disable THP (causes latency spikes)
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag

# For general workloads: keep "madvise" (only when app explicitly requests)
echo madvise > /sys/kernel/mm/transparent_hugepage/enabled

# For K8s init container to disable:
# kubectl debug node -it --image=busybox -- chroot /host sh -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled'
```

### 8.4 NUMA Topology & CPU Pinning

```bash
# Check NUMA topology
lscpu | grep -i numa
# NUMA node(s):          2
# NUMA node0 CPU(s):     0-11
# NUMA node1 CPU(s):     12-23

# numactl to bind processes
numactl --cpunodebind=0 --membind=0 myapp    # pin to NUMA node 0
numactl --physcpubind=0-3 --membind=0 myapp  # pin to specific cores

# K8s: cpu-manager-policy=static + topology-manager-policy=restricted
# Pod with integer CPU request gets exclusive cores on a single NUMA node
```

### 8.5 OOM Score & Priority

```bash
# oom_score_adj: -1000 to 1000 (-1000 = never OOM-kill, 1000 = always kill first)
echo -500 > /proc/$(pidof postgres)/oom_score_adj

# K8s: QoS maps to OOM score
#   Guaranteed: -998
#   Burstable:   min(0, 1000 - (1000 × memory requested / node total memory))
#   BestEffort:  1000

# systemd equivalent:
# OOMScoreAdjust=-500
```

---

## 9. Docker Daemon vs Kubernetes — Control Hierarchy

```
┌──────────────────────────────────────────────────────┐
│ Host: sysctl + /etc/security/limits.conf + cgroup root │
│  (ultimate authority; nothing below can exceed this)   │
├──────────────────────────────────────────────────────┤
│ Docker daemon (/etc/docker/daemon.json)               │
│  default-ulimits, default-cgroup-parent, storage-opts │
├──────────────────────────────────────────────────────┤
│ Docker container (docker run / compose)               │
│  --cpus, --memory, --ulimit, --cap-drop, --pids-limit │
├──────────────────────────────────────────────────────────────────────────────┐
│ K8s node: kubelet (--system-reserved, --kube-reserved, --cpu-manager-policy) │
│ K8s namespace: ResourceQuota, LimitRange                                      │
├──────────────────────────────────────────────────────────────────────────────┤
│ K8s pod: resources.requests/limits, securityContext, sysctls, runtimeClass │
│ K8s container: resources.requests/limits, securityContext (capabilities)   │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Inheritance rules:**
- Container limits cannot exceed host sysctl limits
- Pod sysctls override node sysctls for namespaced parameters
- Docker `--ulimit` cannot exceed `fs.nr_open` (systemd already sets high)
- K8s limits are enforced via cgroups (same mechanism as Docker)
- `LimitRange` defaults apply to pods that don't specify their own limits
- `ResourceQuota` caps aggregate usage across all pods in a namespace

---

## 10. Common Pitfalls & Anti-Patterns

| Pitfall | Consequence | Fix |
|---------|-------------|-----|
| No `requests` on pods | BestEffort QoS; first to be evicted; no scheduling hints | Always set requests |
| `requests` >> `limits` ratio | Pod reserves but doesn't use → node underutilization | Keep ratio reasonable (LimitRange maxRatio) |
| `memory.swap` enabled in container | Swap hides OOM, causes unpredictable latency | `--memory-swap=0` or `vm.swappiness=0` |
| Missing `--shm-size` for PostgreSQL | `/dev/shm` only 64MB → init failures | `--shm-size=256m` or emptyDir medium=Memory |
| `fs.nr_open` not increased | Can't raise `nofile` past 1048576 | Set `fs.nr_open=1048576` in sysctl |
| `vm.max_map_count` too low | Elasticsearch/JVM crash on startup | Set to 262144 |
| PID exhaustion with many containers | `kernel.pid_max` reached; pods fail to start | Raise `kernel.pid_max=4194304` |
| Privileged containers in production | Full host access = container escape | `--cap-drop ALL`, never `--privileged` |
| `overcommit_memory=1` without swap | OOM-kill with no warning | Use only for Redis with swap monitoring |
| CPU Manager `static` without reserved | System daemons fight with workload for exclusive cores | Reserve 1+ core per node |
| THP enabled for databases | 2ms latency spikes from khugepaged compaction | Disable THP for DB nodes |
| No `pids_limit` on containers | Fork bomb takes down host | Always set `--pids-limit=100` (or similar) |
| `nofile` default 1024 in containers | Connection pool exhaustion under load | Set `--ulimit nofile=65535:65535` |
| Hugepages not pre-allocated | Runtime allocation latency, fragmentation | Pre-allocate at boot via `nr_hugepages` |
| `--oom-kill-disable` + no memory limit | Host OOM kills everything else instead | Never disable OOM without a limit |

---

## 11. Observability & Monitoring

### Key cgroup metrics to watch

```bash
# Memory pressure (PSI — Pressure Stall Information)
cat /sys/fs/cgroup/memory.pressure
#   avg10=0.00 avg60=0.00 avg300=0.00 total=0

# CPU pressure
cat /sys/fs/cgroup/cpu.pressure

# Per-container stats
# Docker:
docker stats --no-stream
# cgroup v2:
cat /sys/fs/cgroup/system.slice/docker-<id>.scope/memory.current
cat /sys/fs/cgroup/system.slice/docker-<id>.scope/memory.peak
cat /sys/fs/cgroup/system.slice/docker-<id>.scope/memory.swap.current
cat /sys/fs/cgroup/system.slice/docker-<id>.scope/cpu.stat
cat /sys/fs/cgroup/system.slice/docker-<id>.scope/io.stat

# K8s:
kubectl top pods --containers
kubectl top nodes
# cadvisor / prometheus metrics:
#   container_memory_working_set_bytes
#   container_memory_usage_bytes
#   container_memory_swap
#   container_cpu_usage_seconds_total
#   container_fs_reads_bytes_total
#   container_fs_writes_bytes_total
```

### Key Prometheus alerts

```yaml
# OOM risk
- alert: ContainerOOMKilling
  expr: rate(kube_pod_container_status_restarts_total{reason="OOMKilled"}[5m]) > 0
  for: 0m

# CPU throttling
- alert: ContainerCPUThrottlingHigh
  expr: rate(container_cpu_cfs_throttled_periods_total[5m]) / rate(container_cpu_cfs_periods_total[5m]) > 0.5
  for: 10m

# Memory approaching limit
- alert: ContainerMemoryNearLimit
  expr: container_memory_working_set_bytes / container_spec_memory_limit_bytes > 0.9
  for: 5m

# PID pressure
- alert: ContainerPIDPressure
  expr: sum(kube_pod_container_info) by (node) / kube_node_status_allocatable_pods > 0.8

# FD exhaustion
- alert: ContainerFDExhaustion
  expr: process_open_fds / process_max_fds > 0.85
  for: 10m
```

---

## 12. Quick Reference Card

```
┌─────────────┬──────────────────────────────────────────────────────────┐
│  Layer      │  Key Controls                                            │
├─────────────┼──────────────────────────────────────────────────────────┤
│ Host/VM     │  sysctl (net/core/vm/fs/kernel), ulimit (limits.conf),  │
│             │  cgroup v2 root, hugepages, THP, NUMA, swap             │
├─────────────┼──────────────────────────────────────────────────────────┤
│ Docker      │  --cpus, --memory, --pids-limit, --ulimit, --cap-drop,  │
│             │  --shm-size, --sysctl, --security-opt, --blkio-weight,  │
│             │  daemon.json defaults                                   │
├─────────────┼──────────────────────────────────────────────────────────┤
│ K8s Pod     │  requests/limits (CPU/memory/storage), SecurityContext,  │
│             │  sysctls (namespaced), RuntimeClass, PodOverhead,       │
│             │  PriorityClass, topologyManager                          │
├─────────────┼──────────────────────────────────────────────────────────┤
│ K8s NS      │  LimitRange (defaults/enforce), ResourceQuota (caps),    │
│             │  PodSecurityStandards (baseline/restricted)              │
└─────────────┴──────────────────────────────────────────────────────────┘
```
