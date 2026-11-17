# PS4 Debian WLAN warning flood

This separate work folder tracks the repeated MediaTek WLAN warnings seen while Linux runs on the PS4. It is not part of the PS4 porting repository and contains no console dumps or network credentials.

## Current finding

At baseline, the running kernel command line contained both `loglevel=7` and `ignore_loglevel`, with `console=tty0`; `/sys/module/printk/parameters/ignore_loglevel` read `Y`, and `/proc/sys/kernel/printk` reported `1 5 1 7`. Linux documents that `ignore_loglevel` bypasses the console log-level filter and can be changed at runtime through that sysfs parameter. This explains why changing the console level with `dmesg -n` did not stop the flood. The active fix now sets it to `N` and restores normal console level 7.

The WLAN interface is up and NetworkManager reports it connected. The kernel log repeatedly records `rlmModifyVhtBwPara` warnings (`S1=42, S2=50`, then `S1 change to 50`). The driver also logged command-queue/mailbox warnings around initialization. The messages are in the kernel log; the current tmux shell itself is not being flooded.


## Fix strategy

1. The initial RLM debug mask was `0x03` (ERROR + WARN). Setting only module `0x0e` (`RLM`) to `0x01` disables its warnings while preserving its errors.
2. After this change, the `rlmModifyVhtBwPara` count stayed at 844 over 15 seconds; after the persistent service restarted with console level 7, it stayed at 844 over another 30 seconds. A later live-only 30-second check yielded no WLAN/RLM lines. `wlan0` remained connected. These observations confirm that no new matching messages were generated during the checks.
3. The systemd unit in `ps4-console-logfilter.service` is installed, enabled, and active. It neutralizes `ignore_loglevel`, restores the normal command-line console level 7, and reapplies the RLM-only mask before NetworkManager starts after each Debian boot.
4. The diagnostic `ignore_loglevel` option remains in the PS4 boot command line, but Debian now neutralizes it during startup. No Wi-Fi link restart was needed for the current fix.
5. `research/rlm-warn-to-info.patch` records the minimal source-side cleanup for a future kernel rebuild. It is not applied to the currently running kernel.

The `rlmModifyVhtBwPara` messages come from the PS4's MediaTek MT76x8/MT6632 SDIO driver. The public source logs both the input center segments and the successful 160 MHz normalization as `WARN`, then calls this function while parsing VHT operation information. For S1=42/S2=50 it recognizes a valid 160 MHz segment and changes S1 to 50. This is a normal conversion path mislabeled as warning-level output, not evidence of a Wi-Fi fault. A public PS4 Linux release describes the driver variant as work in progress, so unrelated WLAN warnings may still need review.

## References

- [Linux kernel parameter `ignore_loglevel`](https://docs.kernel.org/admin-guide/kernel-parameters.html): says this option prints all kernel messages to the console and can be changed through `/sys/module/printk/parameters/ignore_loglevel`.
- [Linux printk basics](https://docs.kernel.org/core-api/printk-basics.html): kernel messages go to the log buffer and can be read with `dmesg` independently of console display.
- [MediaTek WLAN RLM source example](https://android.googlesource.com/kernel/mediatek/%2B/android-mtk-3.18/drivers/misc/mediatek/connectivity/wlan/gen3/mgmt/rlm.c): confirms RLM is part of MediaTek's WLAN management code; this is not yet matched to the exact PS4 kernel build.
- [PS4 MT76x8/MT6632 source](https://github.com/striker91n/ps4-linux-7.3/blob/main/drivers/net/wireless/mediatek/mt76x8/drv_wlan/MT6632/wlan/mgmt/rlm.c): contains the matching function and its WARN-level output.
- [PS4 Linux MT7668 driver status](https://github.com/feeRnt/ps4-linux-12xx/releases): identifies the MT76x8/MT6632 driver variant as work in progress.
