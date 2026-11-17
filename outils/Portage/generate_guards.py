#!/usr/bin/env python3
from pathlib import Path
import json,struct
root=Path(__file__).resolve().parents[1];report=Path('/project/PS4/portage-linux/recherche/linux1402_verification.json');m=json.loads(report.read_text());d=(root/'Scout/reports/kernel_20261115_full.elf').read_bytes()
rows=[]
for r in m['offsets']:
 if r.get('matches_dump') is True and r['name'] not in ('sysent','pstate_before_shutdown'):
  rows.append((r['name'],int(r['rva'],16),bytes.fromhex(r['live_hex'])[:16]))
rows.append(('kmem_alloc',0x466920,d[0x466920:0x466930]))
t='''/* Generated from this console's live verified code and its captured kernel dump.
 * Source offsets: ArabPixel PS4_14_02, preserved commit 741b0ef96780afbb262ea7ea3958bcb3dcd09067.
 * Signature agreement is a compatibility check, not independent proof of a function name. */
#ifndef LOCAL_GUARDS_1402_H
#define LOCAL_GUARDS_1402_H
struct guard1402 { unsigned int rva; unsigned char bytes[16]; };
static const struct guard1402 guards1402[] = {
'''
for name,rva,b in rows:t+='    { '+hex(rva)+', { '+', '.join('0x%02x'%x for x in b)+' } }, /* '+name+' */\n'
t+='''};
static int guard_1402_image(unsigned long long base)
{
    if (*(volatile unsigned int *)base != 0x464c457f) return 101;
    for (unsigned int i = 0; i < sizeof(guards1402)/sizeof(guards1402[0]); ++i)
        for (unsigned int j = 0; j < 16; ++j)
            if (*(volatile unsigned char *)(base + guards1402[i].rva + j) != guards1402[i].bytes[j]) return (int)i + 1;
    if (*(volatile unsigned int *)(base + 0x21d279c) != 0x40100) return 102;
    unsigned int l4 = *(volatile unsigned int *)(base + 0x1b2c394);
    unsigned int l3 = *(volatile unsigned int *)(base + 0x1b2c398);
    if (!l4 || l4 >= 512 || l3 >= 512) return 103;
    if ((*(volatile unsigned long long *)(base + 0x22d1d50) >> 48) != 0xffff) return 104;
    unsigned char p1 = *(volatile unsigned char *)(base + 0x4669ec);
    unsigned char p2 = *(volatile unsigned char *)(base + 0x4669f4);
    if ((p1 != 3 && p1 != 7) || (p2 != 3 && p2 != 7)) return 105;
    if (*(volatile unsigned char *)(base + 0x3a31af) != 0xbf) return 106;
    unsigned int ps = *(volatile unsigned int *)(base + 0x3a31b0);
    if (ps != 1 && ps != 3) return 107;
    /* syscall 153 must still be nosys, never silently overwrite another handler. */
    if (*(volatile unsigned long long *)(base + 0x1102b70 + 153 * 48 + 8) != base + 0x1c07a0) return 108;
    return 0;
}
static int guard_1402(unsigned long long base)
{
    if ((base & 0x3fff) || (base >> 48) != 0xffff) return 100;
    return guard_1402_image(base);
}
#endif
'''
p=root/'Portage/loader/linux/guards-1402.h';p.write_text(t);print(p,len(rows))
(root/'Portage/guard_manifest.json').write_text(json.dumps([{'name':n,'rva':hex(a),'bytes':b.hex()} for n,a,b in rows],indent=2))
