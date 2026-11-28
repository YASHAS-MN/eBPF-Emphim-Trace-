# Comparative forensic evaluation 01

## Scope and reproducibility

One low-volume run per collector per existing benign workload (test_m2_exec and test_m2_unlinked_exec), four separate captures, same x86_64 7.0.0-44-generic host. Frozen EphimTrace implementation cba9b01; harness e5299b4. Tracee v0.24.1 official x86_64 archive verified by owner against published checksum. Selected 25 inventoried events, JSON output, parse-arguments-fds, sort-events, process tree source=events, loopback Prometheus metrics. Signature plugin builtin.so failed to load due to Go net package version mismatch; signatures not evaluated. All workload and collector exit codes zero. strace 6.8 available but not used: independent workload handshakes and exit checks supplied ground truth.

Owner-provided workload-only archive SHA256 b730ecee86d49ed6ecb6ee0056ed1cb1f9e8832e197c6fc9dc07c254f4634418 inspected directly; contains comparison_report.json, four workload event JSON files and logs, four Tracee metrics snapshots. Full system captures and graph files not supplied; keep private. No performance or universal completeness claim.

## Memfd workload: event-level reconciliation

Four named objects, successful create returning FD3, three benign script executions, fourth invalid binary rejected with ENOEXEC. Tracee parent 78714, children 78715–78718; EphimTrace parent 78835, children 78836–78839. Different sessions, not identical PIDs or inode numbers.

| Object | Tracee inode (dev 1) / child | EphimTrace token / inode / child | Outcome |
|---|---|---|---|
| m2_exec_script_1 | 373190 / 78715 | 1 / 369343 / 78836 | success |
| m2_exec_fexecve | 373191 / 78716 | 2 / 369344 / 78837 | success |
| m2_exec_proc_reopen | 373192 / 78717 | 3 / 369345 / 78838 | success |
| m2_corrupt_exec | 373193 / 78718 | 4 / 369346 / 78839 | failure |

Tracee: four memfd_create returnValue=3; vfs_write matched each memfd pathname, dev/inode and returnValue 17,17,17,45 bytes; security_bprm_check same object identity for each child; same process identity followed by sched_process_exec for first three, with /usr/bin/dash interpreter, and no successful exec for fourth. Dedicated process_execute_failed ties inode 373193 to returnValue=-8; sched_process_exit reports exit_code 42 for failed child and 0 for three successes. The failed execveat has two records at identical timestamp with returnValue -8 and 0, so do not count raw syscall events as unique attempts or treat the zero as success; dedicated failure and sched exec evidence resolve this case. Tracee close records include FD3 closures on parent, correlated by actor/FD/time, not explicit object destruction. No destruction-specific event observed in selected set; no unsupported-feature inference.

EphimTrace: four completed creations, distinct tokens 1–4 despite reused FD3; four writes (requested sizes 17,17,17,45, not verified returned bytes); four token-specific exec attempts; success tokens 1–3 only, child identities matched ground truth. Token 4 attempt followed by exit, no success event: outcome known from workload log, not explicit failure code in telemetry. Ten FD_INSTALLED, seven FD_CLOSED, seven FILE_RELEASED, four DESTROYED; each token has one parent close FD3 and one destroy, ordered after attempt; no claim that all descriptor closures observed (exit cleanup limitation). Interpreter inode 2490662 is distinct from memfd inode, preserved token associates script with process success. Process exit codes not known in production schema. These are event-level checks, not direct inspection of graph edges.

## Unlinked workload

Tracee parent 78793 child 78794: workload verified inode 939866 device 259:5, mount ns 4026531832, stat/access ENOENT after unlink and child executable reference persisted. Tracee vfs_write on worker returned 30120 bytes, inode 939866; fork, sched_process_exec, unlink return 0, security_inode_unlink and child exit matched actor/path/inode and order. Tracee kernel dev value 271581189 = (259 << 20) | 5, corresponds to userspace stat dev 66309, not an identity mismatch. Exec timestamp 1795859229003300842; unlink syscall 1795859229003870859; security_inode_unlink 1795859229003878203; child exit 1795859229003986626. LSM event is not independently a completion confirmation; syscall result and workload confirm removal. Tracee ctime changes are not object identifiers alone. Tracee additionally observed regular executable write; EphimTrace current memfd-specific write instrumentation does not cover this regular-file write.

EphimTrace parent 78852 child 78853: workload inode 940029 device 66309 mount ns 4026531832; raw seq18 fork, seq20 successful exec (21026768088881 ns), seq24 VFS_UNLINK_COMPLETED ret=0 flags=31 (21026768709652 ns), seq26 child exit (21026768813557 ns). Same dev/inode/ns and path on exec and completed unlink; seq30 successful rmdir for directory inode 940028. Workload independently verified child still held deleted executable. No claim that unlink destroys object or that path alone is reliable.

## Preservation and loss reporting

| Metric | Tracee memfd | Tracee unlinked | EphimTrace memfd | EphimTrace unlinked |
|---|---:|---:|---:|---:|
| Full session records | 13370 | 6857 | 141 | 112 |
| Workload filtered records | 106 | 58 | 62 | 17 |
| Invalid JSON lines | 0 | 0 | N/A | N/A |
| Recorded submission/ring drops | 0 | 0 | 0 | 0 |
| Tracee errors before → after | 920→5277 | 311→3181 | N/A | N/A |
| Strict verified/replayed | Not tested | Not tested | 141/141 | 112/112 |
| Graph nodes/edges (session summary) | Not tested | Not tested | 33/86 | 34/66 |

Tracee errors rose by 4357 and 2870 over system-wide snapshots, which include idle/drain periods; generic accumulated error metric, not lost-event count, cause not established. All three Tracee loss counters zero at both snapshots; final scrape before shutdown (unlinked snapshot shows queued events, 6799 events counter vs 6857 final JSON records). Do not claim session-wide losslessness from snapshots. EphimTrace strict verified manifest, CRC, sequence continuity, final synchronization and zero reported instrumented losses, no reconstruction error, input hashes unchanged according to local harness. Tracee JSON persisted and hashed once, parseable, no dedicated integrity/crash controls tested; cannot claim absence of alternative persistence/replay functionality. Tracee analyze experimental not exercised. EphimTrace graph export succeeded per summaries, actual exported graph contents unavailable in archive and not independently checked for this comparison; prior Phase 1 graph validation separate.

## Related systems (documentary only)

Falco rule-driven runtime detection and syscall event processing: https://falco.org/docs/ ; https://falco.org/docs/reference/rules/supported-events/
Tetragon process lifecycle events, configurable kernel observation and enforcement: https://tetragon.io/docs/use-cases/process-lifecycle/process-execution/ ; https://tetragon.io/docs/reference/tracing-policy/
CamFlow whole-system data provenance through Linux Security Module: https://camflow.org/
Tracee versioned metrics API: https://pkg.go.dev/github.com/aquasecurity/tracee@v0.24.1/pkg/metrics
These descriptions establish relevance, not capability absence or comparative results. No native testing of Falco/Tetragon/CamFlow.

## Conclusion

Both systems supply useful forensic evidence for all tested positive execution cases and the unlinked execution sequence. Tracee offers richer exit/failure codes, actual returned write bytes, regular-file write visibility and process entity metadata. EphimTrace's demonstrated specialization is dedicated session-local memfd object tokens across reuse, explicit release/destruction telemetry, completed unlink identity and built-in framed evidence verification plus offline graph export. These are complementary strengths. The study is bounded evidence of practical differentiation, not novelty proof, performance ranking, universal precision/recall, security superiority, or full parity of configuration. Single host, single run per condition; different selected event scopes and clock domains, signature plugin excluded. No more comparative runs required for current engineering milestone. Next: mandatory owner-operated manual CLI lifecycle demonstration, stop before GUI until explicit approval.
