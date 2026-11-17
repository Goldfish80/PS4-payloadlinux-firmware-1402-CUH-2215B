#include <stdio.h>
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
#define	M_WAITOK 0x0002
#define	M_ZERO   0x0100

#define	VM_MEMATTR_DEFAULT		0x06

/* Keep the original vm_map address: the returned direct-map alias cannot be
 * passed to kmem_free. sys_kexec needs four allocations per invocation. */
static struct {
    void *alias;
    vm_offset_t mapped;
    size_t size;
} contig_allocations[4];

void *kernel_alloc_contig(size_t size)
{
    return kernel_alloc_contig_range(size, 0, ~(vm_paddr_t)0);
}

void *kernel_alloc_contig_range(size_t size, vm_paddr_t low, vm_paddr_t high)
{
    unsigned int slot;
    for (slot = 0; slot < 4 && contig_allocations[slot].alias; ++slot) {}
    if (slot == 4 || !size) return NULL;
    // use kmem_alloc_contig instead of contigalloc to avoid messing with a malloc_type...
    vm_offset_t ret = kern.kmem_alloc_contig(
                 *kern.kernel_map, size, M_ZERO | M_WAITOK, low,
                 high, 1, 0, VM_MEMATTR_DEFAULT);

    if (!ret) {
        kern.printf("Failed to allocate %zud bytes\n", size);
        return NULL;
    }
    vm_paddr_t physical = kern.pmap_extract(kern.kernel_pmap_store, ret);
    if (!physical) {
        kern.kmem_free(*kern.kernel_map, ret, size);
        return NULL;
    }
    void *alias = (void *)PA_TO_DM(physical);
    contig_allocations[slot].alias = alias;
    contig_allocations[slot].mapped = ret;
    contig_allocations[slot].size = size;
    return alias;
}

void kernel_free_contig(void *addr, size_t size)
{
    if (!addr)
        return;
    (void)size;
    for (unsigned int slot = 0; slot < 4; ++slot) {
        if (contig_allocations[slot].alias == addr) {
            kern.kmem_free(*kern.kernel_map, contig_allocations[slot].mapped,
                           contig_allocations[slot].size);
            contig_allocations[slot].alias = NULL;
            return;
        }
    }
    kern.printf("Refusing to free an untracked contiguous allocation\n");
}

void *kernel_alloc_stage(size_t size)
{
    if (!size || size > 128ULL * 1024 * 1024) return NULL;
    size = (size + PAGE_SIZE - 1) & ~(size_t)(PAGE_SIZE - 1);
    void *ptr = (void *)kern.kmem_alloc(*kern.kernel_map, size);
    if (ptr) memset(ptr, 0, size);
    return ptr;
}

void kernel_free_stage(void *addr, size_t size)
{
    if (!addr || !size) return;
    size = (size + PAGE_SIZE - 1) & ~(size_t)(PAGE_SIZE - 1);
    kern.kmem_free(*kern.kernel_map, (vm_offset_t)addr, size);
}

int main(void) {
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
