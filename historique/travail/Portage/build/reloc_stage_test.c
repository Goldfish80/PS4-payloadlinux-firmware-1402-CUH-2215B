
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
#include "reloc_stage.h"
#include "reloc_plan.h"


#define PLAN_BYTES 0x10000ULL
#define KERNEL_ENTRY_PHYSICAL 0x6000000ULL
#define INITRD_PHYSICAL 0x20000000ULL
static struct reloc_stage_info info;
static struct reloc_move *plan;
static void *scratch;
static int within(u64 p, u64 base, u64 size)
{
    return p >= base && p - base < size;
}
void reloc_stage_cancel(void)
{
    kernel_free_contig(scratch, RELOC_PAGE_SIZE);
    kernel_free_contig(plan, PLAN_BYTES);
    scratch = NULL; plan = NULL;
    info = (struct reloc_stage_info){0};
}
const struct reloc_stage_info *reloc_stage_info(void) { return &info; }
int reloc_stage_prepare(void *image, size_t image_size,
                        void *initrd, size_t initrd_size)
{
    int err=EINVAL;
    struct reloc_move *pending=NULL;
    if (plan || scratch || !image || !initrd || image_size<0x1000 || !initrd_size)
        return EINVAL;
    const struct boot_params *header=image;
    u64 setup=((u64)header->hdr.setup_sects+1)*512;
    u64 image_rounded=(image_size+RELOC_PAGE_SIZE-1)&~(RELOC_PAGE_SIZE-1);
    u64 initrd_rounded=(initrd_size+RELOC_PAGE_SIZE-1)&~(RELOC_PAGE_SIZE-1);
    if (!setup || (setup&(RELOC_PAGE_SIZE-1)) || setup>0x10000 || setup>=image_size ||
        image_rounded>0x8000000 || initrd_rounded>0x8000000 ||
        (u64)header->hdr.init_size+KERNEL_ENTRY_PHYSICAL>=INITRD_PHYSICAL)
        return EINVAL;
    u64 image_target=KERNEL_ENTRY_PHYSICAL-setup;
    if (image_target+image_rounded>=INITRD_PHYSICAL ||
        INITRD_PHYSICAL+initrd_rounded>header->hdr.initrd_addr_max+1ULL)
        return EINVAL;
    u64 pages=(image_rounded+initrd_rounded)/RELOC_PAGE_SIZE;
    /* At most one extra move per cycle; worst case is disjoint 2-cycles. */
    if (!pages || pages+pages/2 > PLAN_BYTES/sizeof(struct reloc_move)) return EINVAL;
    pending=kernel_alloc_stage(pages*sizeof(*pending));
    plan=kernel_alloc_contig_range(PLAN_BYTES,0x28000000,RELOC_PHYSICAL_LIMIT-1);
    scratch=kernel_alloc_contig_range(RELOC_PAGE_SIZE,0x28000000,RELOC_PHYSICAL_LIMIT-1);
    if (!pending || !plan || !scratch) { err=ENOMEM; goto fail; }
    u64 plan_pa=DM_TO_ID(plan),scratch_pa=DM_TO_ID(scratch);
    if ((plan_pa&(RELOC_PAGE_SIZE-1)) || plan_pa+PLAN_BYTES>RELOC_PHYSICAL_LIMIT ||
        (scratch_pa&(RELOC_PAGE_SIZE-1)) || scratch_pa+RELOC_PAGE_SIZE>RELOC_PHYSICAL_LIMIT)
        goto fail;
    unsigned int n=0;
    for (unsigned int buffer=0;buffer<2;buffer++) {
        u64 size=buffer?initrd_rounded:image_rounded;
        u64 target=buffer?INITRD_PHYSICAL:image_target;
        u8 *source=buffer?initrd:image;
        for (u64 offset=0;offset<size;offset+=RELOC_PAGE_SIZE) {
            u64 pa=kern.pmap_extract(kern.kernel_pmap_store,(u64)(source+offset));
            u64 dst=target+offset;
            if (!pa || (pa&(RELOC_PAGE_SIZE-1)) || pa+RELOC_PAGE_SIZE>RELOC_PHYSICAL_LIMIT ||
                within(pa,plan_pa,PLAN_BYTES) || pa==scratch_pa ||
                within(dst,plan_pa,PLAN_BYTES) || dst==scratch_pa) goto fail;
            pending[n++]=(struct reloc_move){pa,dst};
        }
    }
    int count=reloc_plan_build(pending,n,plan,PLAN_BYTES/sizeof(*plan),scratch_pa);
    if (count<0) goto fail;
    info=(struct reloc_stage_info){image_target,INITRD_PHYSICAL,plan_pa,(u64)count};
    kernel_free_stage(pending,pages*sizeof(*pending));
    kern.printf("Page relocation plan: %u pages, %d moves; kernel %llx, initrd %llx\n",
                n,count,info.image_physical,info.initrd_physical);
    return 0;
fail:
    kernel_free_stage(pending,pages*sizeof(*pending));
    reloc_stage_cancel();return err;
}

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
