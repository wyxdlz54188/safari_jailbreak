#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import "krw.h"
#import "proc.h"
#import "offsets.h"
#import "csblob.h"
#import "kutils.h"
#include "apfs_util.h"
#import "stage3.h"

int rejailbreak_chimera(void) {
    offsets_init();

    set_proc_csflags(getpid());
    set_csblob(getpid());

    uint64_t our_cr_label = borrow_cr_label(getpid(), 0);
    set_ucred_cr_svuid(getpid(), 0);
    setuid(0); setuid(0);

    if(getuid() != 0) return 1;
    LOG(@"uid = %d", getuid());
    uint64_t kernelsignpost_addr = write_kernelsignpost();
    LOG(@"kernelsignpost_addr = 0x%llx", kernelsignpost_addr);

    int snapshot_success = list_snapshots("/");
    LOG(@"snapshot_success = %d", snapshot_success);

    unborrow_cr_label(getpid(), our_cr_label);
    LOG(@"done rejailbreak_chimera");

    sleep(3);

    return 0;
}