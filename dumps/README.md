# Kernel captures and analysis

`kernel_20261115_full.elf` is the full 20,080,272-byte kernel capture already included in this repository. The short kernel captures and process maps are retained alongside it. `live_kernel_head.bin` and `kernel_20261115_192141.json` add the porting workspace's kernel header and ELF segment metadata.

`analysis/` contains the static string/relocation/code-pointer catalogue, SCE table audit, symbol analysis and final Scout report from the local PS4 workspace. The SCE audit reports erased symbol/name tables; candidate addresses are not proven function names. Live addresses refer to historical captures.

See `../offsets/` for the live address tables, dump-backed signatures and loader checks. `PROVENANCE.json` records source paths and SHA-256 hashes of copied files. `SHA256SUMS` covers all files in `dumps/` and `offsets/` except itself.
