#include "stage1.h"
#include <dlfcn.h>
#include <asl.h>
#include <unistd.h>
#include <fcntl.h>

#include <pthread.h>
#include <dispatch/dispatch.h>
#include <stdio.h>

#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h> 


#define GLOB __attribute__((section("__DATA, __data")))
// this will create "anonymous" global char[] from a string literal
// e.g. strcmp(a, CSTR("hello"));
#define CSTR(x) ({\
        static GLOB char tempstr[] = x;\
        tempstr;\
        })


#include <stdio.h>

void set_registers() {
    __asm__ volatile (
        "movz x0,  0x4142, lsl #48\n"
        "movk x0,  0x4344, lsl #32\n"
        "movk x0,  0x4546, lsl #16\n"
        "movk x0,  0x4748, lsl #0\n"

        "mov x1,  x0\n"
        "mov x2,  x0\n"
        "mov x3,  x0\n"
        "mov x4,  x0\n"
        "mov x5,  x0\n"
        "mov x6,  x0\n"
        "mov x7,  x0\n"
        "mov x8,  x0\n"
        "mov x9,  x0\n"
        "mov x10, x0\n"
        "mov x11, x0\n"
        "mov x12, x0\n"
        "mov x13, x0\n"
        "mov x14, x0\n"
        "mov x15, x0\n"
        "mov x16, x0\n"
        "mov x17, x0\n"
        "mov x18, x0\n"
        "mov x19, x0\n"
        "mov x20, x0\n"
        "mov x21, x0\n"
        "mov x22, x0\n"
        "mov x23, x0\n"
        "mov x24, x0\n"
        "mov x25, x0\n"
        "mov x26, x0\n"
        "mov x27, x0\n"
        "mov x28, x0\n"
        "mov x29, x0\n"
        "mov x30, x0\n"
    );
}

int _start(unsigned long long webcore_base, uint64_t stage2_payload, uint64_t stage2_len) {
    
    set_registers();

    return 0x1337;
}
