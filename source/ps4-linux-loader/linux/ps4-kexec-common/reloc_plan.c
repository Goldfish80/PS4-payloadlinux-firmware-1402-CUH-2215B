#include "reloc_plan.h"
static int valid_page(unsigned long long pa)
{
    return pa && !(pa & (RELOC_PAGE_SIZE-1)) &&
           pa <= RELOC_PHYSICAL_LIMIT-RELOC_PAGE_SIZE;
}
int reloc_plan_build(struct reloc_move *p, unsigned int n,
                     struct reloc_move *out, unsigned int capacity,
                     unsigned long long scratch)
{
    unsigned int used=0;
    if (!valid_page(scratch) || n > 4096) return -1;
    for (unsigned int i=0;i<n;i++) {
        if (!valid_page(p[i].src) || !valid_page(p[i].dst) ||
            p[i].src==scratch || p[i].dst==scratch) return -2;
        for (unsigned int j=0;j<i;j++)
            if (p[i].src==p[j].src || p[i].dst==p[j].dst) return -3;
    }
    while (n) {
        unsigned int ready=n;
        for (unsigned int i=0;i<n;i++) {
            if (p[i].src==p[i].dst) { ready=i; break; }
            unsigned int j;
            for (j=0;j<n;j++)
                if (j!=i && p[j].src==p[i].dst) break;
            if (j==n) { ready=i; break; }
        }
        if (ready<n) {
            if (p[ready].src!=p[ready].dst) {
                if (used>=capacity) return -4;
                out[used++]=p[ready];
            }
            p[ready]=p[--n];
        } else {
            /* A dependency cycle. Save one source page, making its old
             * physical location safe to overwrite, then finish that cycle. */
            for (unsigned int i=0;i<n;i++)
                if (p[i].src==scratch) return -5;
            if (used>=capacity) return -4;
            out[used].src=p[0].src;out[used++].dst=scratch;
            p[0].src=scratch;
        }
    }
    return (int)used;
}
