#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <asl.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <spawn.h>

#include "common.h"
#include "csblob.h"
#include "physpuppet/libprejailbreak.h"
#include "physpuppet/utils.h"

const uint64_t kernel_address_space_base = 0xffff000000000000;
void kmemcpy(uint64_t dest, uint64_t src, uint32_t length) {
    if (dest >= kernel_address_space_base) {
        // copy to kernel:
        kwritebuf(dest, (void*) src, length);
    } else {
        // copy from kernel
        kreadbuf(src, (void*)dest, length);
    }
}

uint64_t borrow_ucreds(pid_t to_pid, pid_t from_pid) {
    uint64_t to_proc = proc_find(to_pid);
    uint64_t from_proc = proc_find(from_pid);
    
    uint64_t to_ucred = kread64(to_proc + koffsetof(proc, ucred));
    uint64_t from_ucred = kread64(from_proc + koffsetof(proc, ucred));
    
    kwrite64(to_proc + koffsetof(proc, ucred), from_ucred);
    
    return to_ucred;
}

void unborrow_ucreds(pid_t to_pid, uint64_t to_ucred) {
    uint64_t to_proc = proc_find(to_pid);
    
    kwrite64(to_proc + koffsetof(proc, ucred), to_ucred);
}
