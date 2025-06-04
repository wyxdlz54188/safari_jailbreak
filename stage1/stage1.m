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

int main() {
    NSLog(@"[stage1] loaded");

    return 0x1337;
}