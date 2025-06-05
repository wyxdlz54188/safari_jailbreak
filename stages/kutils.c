#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include "common.h"
#include "time_saved/time_saved.h"
#include <asl.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <spawn.h>
#include "csblob.h"

void set_csflags(uint64_t proc) {
    uint32_t csflags = rk32(proc + koffset(KSTRUCT_OFFSET_PROC_CSFLAGS));
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    wk32(proc + koffset(KSTRUCT_OFFSET_PROC_CSFLAGS), csflags);
}

void set_tfplatform(uint64_t proc) {
    // task.t_flags & TF_PLATFORM
    uint64_t task = rk64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    uint32_t t_flags = rk32(task + koffset(KSTRUCT_OFFSET_TASK_FLAGS));
    
    t_flags |= TF_PLATFORM;
    wk32(task+koffset(KSTRUCT_OFFSET_TASK_FLAGS), t_flags);

}

const uint64_t kernel_address_space_base = 0xffff000000000000;
void Kernel_memcpy(uint64_t dest, uint64_t src, uint32_t length) {
    if (dest >= kernel_address_space_base) {
        // copy to kernel:
        kwrite(dest, (void*) src, length);
    } else {
        // copy from kernel
        kread(src, (void*)dest, length);
    }
}