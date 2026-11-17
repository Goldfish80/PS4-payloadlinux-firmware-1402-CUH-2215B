/* Page relocation ordering for the checked PS4 Linux handoff.
 * The plan is built while the old OS is running, then executed from low
 * memory after other CPUs stop and identity page tables become active. */
#ifndef RELOC_PLAN_H
#define RELOC_PLAN_H
#define RELOC_PAGE_SIZE 0x4000ULL
#define RELOC_PHYSICAL_LIMIT 0x400000000ULL /* first 16 GiB mapped by thunk */
struct reloc_move { unsigned long long src, dst; };
int reloc_plan_build(struct reloc_move *pending, unsigned int count,
                     struct reloc_move *output, unsigned int capacity,
                     unsigned long long scratch);
#endif
