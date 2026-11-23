# Linux 5.4-rc3 unprivileged LPE audit (eBPF / io_uring / binder / vsock)

- Tree: `VERSION=5 PATCHLEVEL=4 EXTRAVERSION=-rc3`
- Commit: `d418d070057c45fd6f21567278f95452bfe690d1`
- Branch: `cursor/vulnerability-hunter-agent-a5f6`
- Run: `bc-4d827597-3f72-59f2-a352-3144facec097`
- Detected (PST): `2026-11-23T08:18:53-0800`

## Verdict

Two validated **HIGH** findings in io_uring (CVE-2019-19241 credentials, CVE-2022-3176 POLLFREE UAF). Named eBPF ALU32 / JMP32 LPE CVEs from later kernels are **not** present at this rc. Binder CVE-2019-2215 is fixed. vsock multi-transport race and watch_queue are absent.

## eBPF surface (verified)

| Item | Result |
|------|--------|
| `sysctl_unprivileged_bpf_disabled` | BSS zero → **0** (unprivileged BPF **enabled**) |
| Sysctl | One-way 0→1 only (`kernel/sysctl.c:1252-1261`) |
| Gate | `bpf()` rejects unprivileged only if sysctl≠0 (`syscall.c:2830`) |
| Unpriv prog types | `SOCKET_FILTER`, `CGROUP_SKB` (`syscall.c:1653-1656`) |
| `bpf_jit_enable` | `IS_BUILTIN(CONFIG_BPF_JIT_ALWAYS_ON)` → typically 0 |
| `bpf_reg_state` | Only `smin/smax/umin/umax` (64-bit); **no** `u32_*` / `s32_*` |
| JMP32 | Present (`BPF_JMP32`); uses `coerce_reg_to_size` — **no** `__reg_bound_offset32` |
| ALU32 tracking CVEs | 2021-3490 / 2020-8835 / 2020-27194 / 2021-31440 → **not this rc** |

Unprivileged BPF is intentional 5.4 design and expands attack surface, but is not filed as a standalone CVE finding.

## io_uring

- Present (`fs/io_uring.c`, since 5.1).
- SQPOLL gated by `CAP_SYS_ADMIN`.
- **No** `creds` / `override_creds` anywhere → CVE-2019-19241.
- Poll wake ignores POLLFREE → CVE-2022-3176 with signalfd/binder.

## binder

- `binder_thread_release` has POLLFREE + `synchronize_rcu` → CVE-2019-2215 **fixed**.
- Same POLLFREE waitqueues remain hazardous when polled via io_uring (CVE-2022-3176).

## vsock / watch_queue

- vsock: single global `transport` under `vsock_register_mutex`; no assign/deassign race (CVE-2021-26708 needs 5.5+).
- watch_queue: not in tree.

## Outputs

- `linux---flagged-vulnerabilities.json` (this branch + automation memories)
