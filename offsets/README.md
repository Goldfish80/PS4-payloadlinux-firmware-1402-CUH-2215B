# Firmware 14.02 porting offsets

- `ps4_14_0_2_offsets.h`: original upstream RVA table.
- `ps4_14_02_loader.h`: complete 14.02 table extracted from the local port, including `kmem_alloc`.
- `1402.h`: FreeBSD SDK offsets used by the port, including process/memory helpers and allocation patches.
- `fw_offsets.h`: original firmware detection/allocation table; includes the 1402 row and other firmware reference rows.
- `guards-1402.h` and `guard_manifest.json`: the port's instruction signatures and runtime checks, including syscall 153, southbridge, direct-map indices and allocation patches.
- `offsets_1402.tsv`: PS4debug-derived RVAs, historical live addresses, dump file offsets, bytes and match results.
- `offsets_linux_1402.tsv` and `linux1402_verification.json`: Linux loader RVAs, historical live verification, dump bytes and disassembly.
- `history/besoins_kexec.tsv`: initial 14.00/14.02 comparison, preserved as a historical work sheet. Its missing entries predate the later verification files above.

Absolute addresses describe the captured console session and may change on another boot. File offsets and RVAs differ across ELF segments. Function names retain source attribution; matching bytes alone do not prove their semantic role. `Starsha_UcodeInfo = 0` is an unresolved placeholder.

Original file provenance and SHA-256 hashes are in `../dumps/PROVENANCE.json`.
