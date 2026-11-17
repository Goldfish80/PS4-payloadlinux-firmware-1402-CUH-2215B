#ifndef RELOC_STAGE_H
#define RELOC_STAGE_H
#include "types.h"
struct reloc_stage_info {
    u64 image_physical, initrd_physical, plan_physical, plan_count;
};
int reloc_stage_prepare(void *image, size_t image_size,
                        void *initrd, size_t initrd_size);
const struct reloc_stage_info *reloc_stage_info(void);
void reloc_stage_cancel(void);
#endif
