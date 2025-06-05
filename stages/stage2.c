#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include "common.h"
#include "time_saved/time_saved.h"
#include <asl.h>

int main() {
  

  int tfpzero = start_time_saved();
  asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] tfp0 = 0x%x\n", tfpzero);

  return 0;
}


uint64_t entry[] = { MAGIC, (uint64_t)&main };
