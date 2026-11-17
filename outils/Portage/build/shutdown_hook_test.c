
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define TESTING
#undef offsetof
#include "../loader/linux/ps4-kexec-common/kernel.h"
struct ksym_t kern;
static int pins,unpins,corrupt;static unsigned char *site;
static int logger(const char *s,...){(void)s;return 0;}
static void pin(void){pins++;}static void unpin(void){unpins++;}
static u64 write_protect_disable(void){return 0x10000;}
static void write_protect_restore(u64 v){(void)v;}
static void wbinvd(void){if(corrupt){site[0]=0;corrupt=0;}}
int kernel_hook_install(void *target, void *hook)
{
    uintptr_t t = (uintptr_t)target; // addr to redirect to
    uintptr_t h = (uintptr_t)hook; // place to write the thunk

    if (!hook || !target) {
        return 0;
    }

    kern.printf("kernel_hook_install(%p, %p)\n", target, hook);

    if (!(t & (1ULL << 63))) {
        kern.printf("\n===================== WARNING =====================\n");
        kern.printf("hook target function address: %p\n", target);
        kern.printf("It looks like we're running from userland memory.\n");
        kern.printf("Please run this code from a kernel memory mapping.\n\n");
        return 0;
    }
    s64 displacement = t - (h + 5);

    u8 original[14];
    memcpy(original, hook, sizeof(original));
    unsigned int patch_size;
    kern.sched_pin();
    u64 wp = write_protect_disable();
    if (displacement < -0x80000000 || displacement > 0x7fffffff) {
        kern.printf("  Using 64bit absolute jump\n");
        struct __attribute__((packed)) jmp_t{
            u8 op[2];
            s32 zero;
            void *target;
        } jmp = {
            .op = { 0xff, 0x25 },
            .zero = 0,
            .target = target,
        };
        ASSERT_STRSIZE(struct jmp_t, 14);
        memcpy(hook, &jmp, sizeof(jmp));
        patch_size = sizeof(jmp);
    } else {
        kern.printf("  Using 32bit relative jump\n");
        struct __attribute__((packed)) jmp_t{
            u8 op[1];
            s32 imm;
        } jmp = {
            .op = { 0xe9 },
            .imm = displacement,
        };
        ASSERT_STRSIZE(struct jmp_t, 5);
        memcpy(hook, &jmp, sizeof(jmp));
        patch_size = sizeof(jmp);
    }
    wbinvd();
    /* Verify the actual encoded destination before reporting armed. */
    volatile u8 *code = hook;
    uintptr_t installed = 0;
    if (patch_size == 5 && code[0] == 0xe9) {
        s32 rel; memcpy(&rel, (u8 *)hook + 1, sizeof(rel));
        installed = h + 5 + rel;
    } else if (patch_size == 14 && code[0] == 0xff && code[1] == 0x25 &&
               !code[2] && !code[3] && !code[4] && !code[5]) {
        memcpy(&installed, (u8 *)hook + 6, sizeof(installed));
    }
    int verified = installed == t;
    if (!verified) { memcpy(hook, original, patch_size); wbinvd(); }
    write_protect_restore(wp);
    kern.sched_unpin();
    kern.printf("Shutdown hook readback: %s, site %p, destination %p\n",
                verified ? "PASS" : "FAIL", hook, (void *)installed);
    return verified;
}


int main(void){
 unsigned char code[64],original[64];site=code;memset(code,0x90,sizeof(code));memcpy(original,code,sizeof(code));
 kern.printf=logger;kern.sched_pin=pin;kern.sched_unpin=unpin;
 if(kernel_hook_install(NULL,code)||kernel_hook_install((void*)1,code))return 1;
 void *target=(void*)0xffffffffc7123450ULL;
 if(!kernel_hook_install(target,code)||code[0]!=0xff||code[1]!=0x25||pins!=1||unpins!=1)return 2;
 uintptr_t decoded;memcpy(&decoded,code+6,8);if(decoded!=(uintptr_t)target)return 3;
 memcpy(code,original,sizeof(code));corrupt=1;
 if(kernel_hook_install(target,code)||memcmp(code,original,sizeof(code))||pins!=2||unpins!=2)return 4;
 puts("PASS: shutdown absolute jump readback; corruption rejected and original bytes restored; pin/unpin balanced");return 0;
}
