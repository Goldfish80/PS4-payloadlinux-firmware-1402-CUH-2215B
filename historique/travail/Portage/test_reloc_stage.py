#!/usr/bin/env python3
from pathlib import Path
import subprocess,os
root=Path(__file__).resolve().parent
s=(root/'loader/linux/ps4-kexec-common/reloc_stage.c').read_text()
s=s.replace('#include "kernel.h"','').replace('#include "linux_boot.h"','')
pre=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#define TESTING
#undef offsetof
#undef ENAMETOOLONG
#include "types.h"
#include "linux_boot.h"
struct record {void *p;size_t n;u64 pa;} records[8];
static unsigned calls,fail_at,live;static int bad_pa,free_error;
static unsigned char *image_buf,*initrd_buf;
static u64 to_pa(void *p){for(unsigned i=0;i<8;i++)if(records[i].p==p)return records[i].pa;return 0;}
#define DM_TO_ID(p) to_pa(p)
static void *alloc(size_t n,u64 pa){
 if(++calls==fail_at)return NULL;
 void *p=calloc(1,n);if(!p)abort();
 for(unsigned i=0;i<8;i++)if(!records[i].p){records[i]=(struct record){p,n,pa};live++;return p;}abort();
}
static void release(void *p,size_t n){if(!p)return;for(unsigned i=0;i<8;i++)if(records[i].p==p){if(records[i].n!=n)free_error=1;free(p);records[i].p=NULL;live--;return;}free_error=1;}
static void *kernel_alloc_stage(size_t n){return alloc(n,0);}
static void kernel_free_stage(void *p,size_t n){release(p,n);}
static void *kernel_alloc_contig_range(size_t n,u64 low,u64 high){(void)high;return alloc(n,low+calls*0x10000);}
static void kernel_free_contig(void *p,size_t n){release(p,n);}
static u64 map_page(void *p,u64 va){(void)p;if(bad_pa)return 0;
 if(va>=(u64)image_buf&&va<(u64)image_buf+0x13c4000)return 0x240000000ULL+va-(u64)image_buf;
 if(va>=(u64)initrd_buf&&va<(u64)initrd_buf+0xc24000)return 0x280000000ULL+va-(u64)initrd_buf;
 return 0;
}
static int logger(const char *s,...){(void)s;return 0;}
static struct {u64 (*pmap_extract)(void*,u64);void *kernel_pmap_store;int(*printf)(const char*,...);} kern={map_page,NULL,logger};
'''
post=r'''
int main(void){
 image_buf=aligned_alloc(0x4000,0x13c4000);initrd_buf=aligned_alloc(0x4000,0xc24000);
 if(!image_buf||!initrd_buf)return 1;
 memset(image_buf,0,0x4000);struct boot_params *bp=(void*)image_buf;
 bp->hdr.setup_sects=31;bp->hdr.init_size=0x3236000;bp->hdr.initrd_addr_max=0x37ffffff;
 for(unsigned fail=1;fail<=3;fail++){
  calls=0;fail_at=fail;
  if(reloc_stage_prepare(image_buf,20718592,initrd_buf,12726774)!=ENOMEM||live||free_error)return 2;
 }
 fail_at=0;calls=0;bad_pa=1;
 if(reloc_stage_prepare(image_buf,20718592,initrd_buf,12726774)!=EINVAL||live||free_error)return 3;
 bad_pa=0;calls=0;
 if(reloc_stage_prepare(image_buf,20718592,initrd_buf,12726774)||live!=2)return 4;
 const struct reloc_stage_info *r=reloc_stage_info();
 if(r->plan_count!=2042||r->image_physical!=0x5ffc000||r->initrd_physical!=0x20000000)return 5;
 reloc_stage_cancel();reloc_stage_cancel();if(live||free_error)return 6;
 bp->hdr.init_size=0x20000000;if(reloc_stage_prepare(image_buf,20718592,initrd_buf,12726774)!=EINVAL||live)return 7;
 bp->hdr.init_size=0x3236000;bp->hdr.initrd_addr_max=0x20000000;
 if(reloc_stage_prepare(image_buf,20718592,initrd_buf,12726774)!=EINVAL||live)return 8;
 free(image_buf);free(initrd_buf);
 puts("PASS: real-size staging (2042 high-PA pages), allocation failures 1/2/3, mapping failure cleanup, repeated cancel, decompression and initrd bounds");return 0;
}
'''
p=root/'build/reloc_stage_test.c';p.write_text(pre+s+post)
subprocess.run(['cc','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-iquote',str(root/'loader/linux/ps4-kexec-common'),str(p),str(root/'loader/linux/ps4-kexec-common/reloc_plan.c'),'-o',str(root/'build/reloc_stage_test')],check=True)
subprocess.run([str(root/'build/reloc_stage_test')],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
