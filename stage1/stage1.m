#include "stage1.h"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

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
        "movz x26,  0x4142, lsl #48\n"
        "movk x26,  0x4344, lsl #32\n"
        "movk x26,  0x4546, lsl #16\n"
        "movk x26,  0x4748, lsl #0\n"

        // "mov x1,  x0\n"
        // "mov x2,  x0\n"
        // "mov x3,  x0\n"
        // "mov x4,  x0\n"
        // "mov x5,  x0\n"
        // "mov x6,  x0\n"
        // "mov x7,  x0\n"
        // "mov x8,  x0\n"
        // "mov x9,  x0\n"
        // "mov x10, x0\n"
        // "mov x11, x0\n"
        // "mov x12, x0\n"
        // "mov x13, x0\n"
        // "mov x14, x0\n"
        // "mov x15, x0\n"
        // "mov x16, x0\n"
        // "mov x17, x0\n"
        // "mov x18, x0\n"
        // "mov x19, x0\n"
        // "mov x20, x0\n"
        // "mov x21, x0\n"
        // "mov x22, x0\n"
        // "mov x23, x0\n"
        // "mov x24, x0\n"
        // "mov x25, x0\n"
        // "mov x26, x0\n"
        // "mov x27, x0\n"
        "mov x28, x26\n"
        "mov x29, x26\n"
        "mov x30, x26\n"
    );
}

int main() {
    NSLog(@"[stage1] loaded");

    set_registers();

    return 0x1337;
}