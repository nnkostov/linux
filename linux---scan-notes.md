# Linux 5.4-rc3 unprivileged LPE audit

- Tree: `VERSION=5 PATCHLEVEL=4 EXTRAVERSION=-rc3`
- Branch: `cursor/vulnerability-hunter-agent-a5f6`
- HEAD at report: `de1884872d58` (pre-report); findings committed on top

## Runs

| Focus | Run | Detected (PST) |
|-------|-----|----------------|
| eBPF / io_uring / binder / vsock / watch_queue | `bc-4d827597-3f72-59f2-a352-3144facec097` | 2026-11-23T08:18:53-0800 |
| xt_compat / AF_PACKET / iSCSI / TIPC / n_gsm·6pack | `bc-5a163ee8-021e-5449-ac7e-5dc67e3712b9` | 2026-11-23T08:25:58-0800 |

## Validated HIGH/CRITICAL (this tree)

1. **CVE-2019-19241** — io_uring workers use kworker creds (`fs/io_uring.c`)
2. **CVE-2022-3176** — io_uring poll ignores POLLFREE (`fs/io_uring.c`)
3. **CVE-2021-22555** — xtables COMPAT `IPT_SO_SET_REPLACE` heap overflow (`x_tables.c` / `*_tables.c`); `ns_capable(CAP_NET_ADMIN)` via user+net ns
4. **CVE-2020-14386** — AF_PACKET `unsigned short macoff/netoff` + `PACKET_RESERVE` (`af_packet.c`); `ns_capable(CAP_NET_RAW)` via user+net ns
5. **CVE-2021-27365/64/63** — iSCSI netlink unbounded attrs / sysfs sprintf / handle leak; unprivileged NETLINK_ISCSI to pid 0
6. **6pack `cooked_buf[400]`** — unbounded `decode_data` via PTY+N_6PACK

## Rejected (named classes)

- TIPC **MSG_CRYPTO / CVE-2021-43267** — not in 5.4-rc3
- **n_gsm** — no complete HIGH chain verified (MRU checks present)
- Prior: eBPF ALU32/JMP32 LPEs (post-5.4 features), binder CVE-2019-2215 fixed, vsock multi-transport absent, watch_queue absent

## Outputs

- `linux---flagged-vulnerabilities.json`
- `linux---scan-notes.md`
