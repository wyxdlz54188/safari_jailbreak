#include <dlfcn.h>
#include <asl.h>
#include <unistd.h>
#include <fcntl.h>

#include <pthread.h>
#include <dispatch/dispatch.h>
#include <stdio.h>

#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h> 

int _start(unsigned long long webcore_base, uint64_t stage2_payload, uint64_t stage2_len);