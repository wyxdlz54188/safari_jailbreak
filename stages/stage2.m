#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <Foundation/Foundation.h>
#include "common.h"

#define LOG(msg) \
  NSLog(@msg); \
  fprintf(stderr, msg); \
  fflush(stderr); \

int main() {
  LOG("[stage2] Starting...\n");
  LOG("[stage2] Starting...\n");
  LOG("[stage2] Starting...\n");
  LOG("[stage2] Starting...\n");
  LOG("[stage2] Starting...\n");
  LOG("[stage2] Starting...\n");
  LOG("[stage2] Starting...\n");

  return 0;
}


uint64_t entry[] = { MAGIC, (uint64_t)&main };
