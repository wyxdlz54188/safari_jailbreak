#include <stdint.h>
#include <unistd.h>

void set_proc_csflags(pid_t pid);
void set_csblob(pid_t pid);

uint64_t borrow_cr_label(pid_t to_pid, pid_t from_pid);
void unborrow_cr_label(pid_t to_pid, uint64_t to_cr_label);