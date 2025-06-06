#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include "offsets.h"
#include "krw.h"

extern uint64_t g_kernproc;

uint64_t proc_of_pid(pid_t pid) {
    uint64_t proc = g_kernproc;
    
    while (true) {
        if(kread32(proc + off_p_pid) == pid) {
            return proc;
        }
        proc = kread64(proc + off_p_list_le_prev);
        if(!proc) {
            return -1;
        }
    }
    
    return 0;
}

uint64_t proc_by_name(char* nm) {
    uint64_t proc = g_kernproc;
    
    while (true) {
        uint64_t nameptr = proc + off_p_comm;
        char name[40];
        kreadbuf(nameptr, &name, 40);
        if(strcmp(name, nm) == 0) {
            return proc;
        }
        proc = kread64(proc + off_p_list_le_prev);
        if(!proc) {
            return -1;
        }
    }
    
    return 0;
}

pid_t pid_by_name(char* nm) {
    uint64_t proc = proc_by_name(nm);
    if(proc == -1) return -1;
    return kread32(proc + off_p_pid);
}