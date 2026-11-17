#!/usr/bin/env python3
from pathlib import Path
import subprocess
root=Path(__file__).parent
s=(root/'loader/linux/ps4-kexec-common/kernel.c').read_text();region=s[s.index('#define\tM_WAITOK'):s.index('int kernel_hook_install')]
pro='''#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define TESTING
#undef offsetof
#include "../loader/linux/ps4-kexec-common/kernel.h"
struct ksym_t kern;
static int alloc_calls, free_calls, fail_alloc, fail_map;
static vm_offset_t next_addr=0x100000, last_freed;
static size_t last_size;
static int logger(const char *s,...) { (void)s; return 0; }
static vm_offset_t mock_alloc(vm_map_t m,vm_size_t s,int f,vm_paddr_t lo,vm_paddr_t hi,unsigned long a,unsigned long b,vm_memattr_t attr) {
(void)m;(void)s;(void)f;(void)lo;(void)hi;(void)a;(void)b;(void)attr;
alloc_calls++;if(fail_alloc)return 0;next_addr+=0x10000;return next_addr;
}
static vm_paddr_t mock_map(pmap_t p,vm_offset_t va) {(void)p;return fail_map?0:va+0x10000000;}
static void mock_free(vm_map_t m,vm_offset_t va,vm_size_t n) {(void)m;free_calls++;last_freed=va;last_size=n;}
'''
epilog='''int main(void) {
void *map=0;kern.kernel_map=&map;kern.dmap_base=0xffffabbb00000000ULL;
for(unsigned long long pa=0;pa<0x400000000ULL;pa+=0x4000)if(DM_TO_ID(PA_TO_DM(pa))!=pa)return 9;
kern.printf=logger;kern.kmem_alloc_contig=mock_alloc;kern.pmap_extract=mock_map;kern.kmem_free=mock_free;
fail_alloc=1;if(kernel_alloc_contig(42)!=0||alloc_calls!=1)return 1;fail_alloc=0;
fail_map=1;if(kernel_alloc_contig(43)!=0||free_calls!=1||last_freed!=next_addr||last_size!=43)return 2;fail_map=0;
void *p=kernel_alloc_contig(1234);vm_offset_t original=next_addr;
if(!p)return 3;
kernel_free_contig(p,999);
if(last_freed!=original||last_size!=1234||free_calls!=2)return 4;
kernel_free_contig((void*)0x1234,5);if(free_calls!=2)return 5;
void *all[4];for(int i=0;i<4;i++)if(!(all[i]=kernel_alloc_contig(80+i)))return 6;
int calls=alloc_calls;if(kernel_alloc_contig(99)||alloc_calls!=calls)return 7;
for(int i=0;i<4;i++)kernel_free_contig(all[i],1);
if(!kernel_alloc_contig(10))return 8;
puts("PASS: failed allocation terminates; physical-map failure cleans original VA; correct VA/size freed; unknown free rejected; capacity and reuse verified");return 0;
}
'''
b=root/'build/allocator_test.c';b.write_text(pro+region+epilog)
subprocess.run(['cc','-O2','-Wall',str(b),'-o',str(root/'build/allocator_test')],check=True)
subprocess.run([str(root/'build/allocator_test')],check=True)
