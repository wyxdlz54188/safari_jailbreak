#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import "krw.h"
#import "proc.h"
#import "offsets.h"
#import "csblob.h"
#import "kutils.h"
#import "stage3.h"

int rejailbreak_chimera(void) {
    offsets_init();

    set_proc_csflags(getpid());
    set_csblob(getpid());

    uint64_t our_cr_label = borrow_cr_label(getpid(), 0);
    unborrow_cr_label(getpid(), our_cr_label);

    LOG(@"done rejailbreak_chimera");

    sleep(3);

    return 0;
}