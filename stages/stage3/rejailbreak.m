#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import "krw.h"
#import "proc.h"
#import "offsets.h"
#import "csblob.h"
#import "kutils.h"
#include "remount.h"
#import "stage3.h"

int rejailbreak_chimera(void) {
    offsets_init();

    set_proc_csflags(getpid());
    set_csblob(getpid());

    uint64_t our_cr_label = borrow_cr_label(getpid(), 0);
    set_ucred_cr_svuid(getpid(), 0);
    setuid(0); setuid(0);

    if(getuid() != 0) goto err;
    LOG(@"uid = %d", getuid());
    uint64_t kernelsignpost_addr = write_kernelsignpost();
    LOG(@"kernelsignpost_addr = 0x%llx", kernelsignpost_addr);

    int snapshot_success = list_snapshots("/");
    LOG(@"snapshot_success = %d", snapshot_success);
    if(snapshot_success != 0)   goto err;


    int remount_status = remount_root_as_rw();
    LOG(@"remount_status = %d", remount_status);
    if(remount_status != 0)     goto err;

    LOG(@"done rejailbreak_chimera");sleep(3);
    return 0;

err:
    unborrow_cr_label(getpid(), our_cr_label);
    LOG(@"failed rejailbreak_chimera");sleep(3);

    return 1;
}