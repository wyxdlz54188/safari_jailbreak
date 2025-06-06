#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import "krw.h"
#import "proc.h"
#import "offsets.h"
#import "csblob.h"
#include "kutils.h"

int rejailbreak_chimera(void) {
    offsets_init();

    set_proc_csflags(getpid());
    set_csblob(getpid());

    NSLog(@"[stage3] done rejailbreak_chimera");

    return 0;
}