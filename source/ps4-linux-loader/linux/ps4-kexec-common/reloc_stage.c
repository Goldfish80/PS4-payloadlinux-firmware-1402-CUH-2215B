#include "reloc_stage.h"
#include "reloc_plan.h"
#include "kernel.h"
#include "linux_boot.h"
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
