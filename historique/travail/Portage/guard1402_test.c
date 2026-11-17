#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "loader/linux/guards-1402.h"
int main(void) {
    unsigned char *image=aligned_alloc(16384,0x2400000);
    if(!image) return 1;
    memset(image,0,0x2400000);uintptr_t base=(uintptr_t)image;
    *(uint32_t*)image=0x464c457f;
    for(size_t i=0;i<sizeof(guards1402)/sizeof(guards1402[0]);i++) memcpy(image+guards1402[i].rva,guards1402[i].bytes,16);
    *(uint32_t*)(image+0x21d279c)=0x40100;
    *(uint32_t*)(image+0x1b2c394)=343;*(uint32_t*)(image+0x1b2c398)=236;
    *(uint64_t*)(image+0x22d1d50)=0xffffabbb14000000ULL;
    image[0x4669ec]=3;image[0x4669f4]=7;image[0x3a31af]=0xbf;
    *(uint32_t*)(image+0x3a31b0)=1;
    *(uint64_t*)(image+0x1102b70+153*48+8)=base+0x1c07a0;
    if(guard_1402_image(base)) return 2;
    int cases=0;
    for(size_t i=0;i<sizeof(guards1402)/sizeof(guards1402[0]);i++)for(int j=0;j<16;j++) {
        image[guards1402[i].rva+j]^=1;
        if(guard_1402_image(base)!=(int)i+1) return 3;
        image[guards1402[i].rva+j]^=1;cases++;
    }
    *(uint32_t*)(image+0x21d279c)=0x30100;
    if(guard_1402_image(base)!=102) return 4;
    *(uint32_t*)(image+0x21d279c)=0x40100;
    *(uint64_t*)(image+0x1102b70+153*48+8)=base+0x12345;
    if(guard_1402_image(base)!=108) return 5;
    if(guard_1402(base)!=100) return 6;
    free(image);printf("PASS: %d corrupted code bytes rejected; wrong southbridge, occupied syscall and non-kernel base rejected\n",cases);return 0;
}
