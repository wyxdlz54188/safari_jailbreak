#include <stdint.h>

void set_csflags(uint64_t proc);

void set_tfplatform(uint64_t proc);

void Kernel_memcpy(uint64_t dest, uint64_t src, uint32_t length);
uint64_t proc_of_pid(pid_t pid) ;