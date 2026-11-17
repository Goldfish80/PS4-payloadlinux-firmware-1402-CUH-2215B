#!/usr/bin/env python3
from pathlib import Path
import subprocess,os
r=Path(__file__).resolve().parent
s=(r/'loader/linux/ps4-kexec-common/kernel.c').read_text();s=s[s.index('int kernel_hook_install('):s.index('void kernel_syscall_install(')]
pre=r'''
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
'''
post=r'''
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
'''
p=r/'build/shutdown_hook_test.c';p.write_text(pre+s+post)
subprocess.run(['cc','-O1','-g','-fsanitize=address,undefined',str(p),'-o',str(r/'build/shutdown_hook_test')],check=True)
subprocess.run([str(r/'build/shutdown_hook_test')],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0','UBSAN_OPTIONS':'halt_on_error=1'})
