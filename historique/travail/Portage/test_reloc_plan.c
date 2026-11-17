#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "loader/linux/ps4-kexec-common/reloc_plan.h"
static uint32_t rng=0x14be12;
static unsigned next(void){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;}
static int exercise(struct reloc_move *moves,unsigned n) {
    struct reloc_move original[64],pending[64],out[128];
    unsigned long long memory[130],expected[130];
    memcpy(original,moves,n*sizeof(*moves));memcpy(pending,moves,n*sizeof(*moves));
    for(unsigned i=0;i<130;i++)memory[i]=expected[i]=0x140200000000ULL+i;
    for(unsigned i=0;i<n;i++)expected[original[i].dst/RELOC_PAGE_SIZE]=memory[original[i].src/RELOC_PAGE_SIZE];
    int count=reloc_plan_build(pending,n,out,128,129*RELOC_PAGE_SIZE);
    if(count<0)return 1;
    for(int i=0;i<count;i++) {
        if(out[i].src/RELOC_PAGE_SIZE>=130||out[i].dst/RELOC_PAGE_SIZE>=130)return 2;
        memory[out[i].dst/RELOC_PAGE_SIZE]=memory[out[i].src/RELOC_PAGE_SIZE];
    }
    for(unsigned i=0;i<n;i++) if(memory[original[i].dst/RELOC_PAGE_SIZE]!=expected[original[i].dst/RELOC_PAGE_SIZE])return 3;
    return 0;
}
/* Model physical pages sparsely: high physical addresses need no huge host mapping. */
static unsigned index_of(unsigned long long pa, unsigned long long base) {
 return (unsigned)((pa-base)/RELOC_PAGE_SIZE);
}
static int large_case(unsigned n, int cycle) {
 struct reloc_move *p=calloc(n,sizeof(*p)),*out=calloc(2*n,sizeof(*out));
 unsigned long long *memory=calloc(2*n+1,sizeof(*memory));
 if(!p||!out||!memory){free(p);free(out);free(memory);return 1;}
 const unsigned long long base=0x240000000ULL; /* above 4 GiB */
 for(unsigned i=0;i<2*n+1;i++)memory[i]=0x140200000000ULL+i;
 for(unsigned i=0;i<n;i++)p[i]=(struct reloc_move){base+i*RELOC_PAGE_SIZE,
   base+(cycle?(i+1)%n:n+i)*RELOC_PAGE_SIZE};
 int count=reloc_plan_build(p,n,out,2*n,base+2*n*RELOC_PAGE_SIZE),bad=count<0;
 for(int i=0;i<count&&!bad;i++) {
  unsigned src=index_of(out[i].src,base),dst=index_of(out[i].dst,base);
  if(src>2*n||dst>2*n){bad=1;break;}memory[dst]=memory[src];
 }
 for(unsigned i=0;i<n&&!bad;i++)if(memory[cycle?(i+1)%n:n+i]!=0x140200000000ULL+i)bad=1;
 free(p);free(out);free(memory);return bad;
}
int main(void){
 if(large_case(2042,0)||large_case(2042,1)||large_case(4096,1))return 9;

 struct reloc_move p[64],out[128];
 p[0]=(struct reloc_move){RELOC_PAGE_SIZE,2*RELOC_PAGE_SIZE};p[1]=(struct reloc_move){2*RELOC_PAGE_SIZE,RELOC_PAGE_SIZE};
 if(exercise(p,2))return 1;
 p[0]=(struct reloc_move){RELOC_PAGE_SIZE,2*RELOC_PAGE_SIZE};p[1]=(struct reloc_move){2*RELOC_PAGE_SIZE,3*RELOC_PAGE_SIZE};p[2]=(struct reloc_move){3*RELOC_PAGE_SIZE,RELOC_PAGE_SIZE};
 if(exercise(p,3))return 2;
 for(int test=0;test<20000;test++){
  unsigned src[128],dst[128];for(unsigned i=0;i<128;i++)src[i]=dst[i]=i+1;
  for(unsigned i=127;i;i--){unsigned j=next()%(i+1),x=src[i];src[i]=src[j];src[j]=x;j=next()%(i+1);x=dst[i];dst[i]=dst[j];dst[j]=x;}
  unsigned n=1+next()%64;
  for(unsigned i=0;i<n;i++)p[i]=(struct reloc_move){src[i]*RELOC_PAGE_SIZE,dst[i]*RELOC_PAGE_SIZE};
  if(exercise(p,n))return 3;
 }
 p[0]=(struct reloc_move){RELOC_PAGE_SIZE,2*RELOC_PAGE_SIZE};p[1]=p[0];
 if(reloc_plan_build(p,2,out,128,129*RELOC_PAGE_SIZE)!=-3)return 4;
 p[0]=(struct reloc_move){RELOC_PAGE_SIZE+1,2*RELOC_PAGE_SIZE};if(reloc_plan_build(p,1,out,128,129*RELOC_PAGE_SIZE)!=-2)return 5;
 p[0]=(struct reloc_move){RELOC_PAGE_SIZE,RELOC_PHYSICAL_LIMIT};if(reloc_plan_build(p,1,out,128,129*RELOC_PAGE_SIZE)!=-2)return 6;
 p[0]=(struct reloc_move){RELOC_PAGE_SIZE,2*RELOC_PAGE_SIZE};if(reloc_plan_build(p,1,out,0,129*RELOC_PAGE_SIZE)!=-4)return 7;
 if(reloc_plan_build(p,1,out,128,RELOC_PAGE_SIZE)!=-2)return 8;
 puts("PASS: 2042-page high-PA copies/cycle and 4096-page cycle; 20000 randomized page-copy plans, overlaps, cycles, duplicate/unaligned/out-of-range pages, scratch conflicts and output bounds");return 0;
}
