# Driver-side cause

The active interface is bound to `/sys/bus/sdio/drivers/mt76x8-mt6632_sdio`. The public PS4 kernel tree has the corresponding MediaTek MT76x8/MT6632 source at `drivers/net/wireless/mediatek/mt76x8/drv_wlan/MT6632/wlan/mgmt/rlm.c`.

In `rlmModifyVhtBwPara`, the driver logs `S1` and `S2` at `WARN` severity whenever both segment values are set. If the values differ by 8, it treats the information as 160 MHz, accepts center segments 50/82/114/163, normalizes S1 to that center, clears S2, and logs the successful normalization at `WARN` too. The parser calls this routine for VHT operation information. The console's `S1=42, S2=50` followed by `S1 change to 50` matches this successful path.

The driver's `/proc/net/wlan/dbg_level` interface exposes a mask per module. Its header documents bit 0 as ERROR and bit 1 as WARN. `DBG_RLM_IDX` is index `0x0e`; the live mask was `0x03`, enabling both. Setting it to `0x01` keeps RLM errors enabled and suppresses RLM warnings and less severe chatter. This is a runtime driver setting; it does not require a kernel rebuild or Wi-Fi disconnect.

The 160 MHz channel information may be valid. The identified bug is that routine parsing/conversion messages are logged as warnings, so repeated VHT operation parsing fills the console. The mask fix removes the noise at its source while leaving the Wi-Fi link active.
