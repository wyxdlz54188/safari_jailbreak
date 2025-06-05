#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include "time_saved.h"

#include "offsets.h"
uint64_t* offsets = NULL;

uint64_t kstruct_offsets_12_0[] = {
    0xb,   // KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
    0x10,  // KSTRUCT_OFFSET_TASK_REF_COUNT,
    0x14,  // KSTRUCT_OFFSET_TASK_ACTIVE,
    0x20,  // KSTRUCT_OFFSET_TASK_VM_MAP,
    0x28,  // KSTRUCT_OFFSET_TASK_NEXT,
    0x30,  // KSTRUCT_OFFSET_TASK_PREV,
    0xd8,  // KSTRUCT_OFFSET_TASK_ITK_SELF,
    0x300, // KSTRUCT_OFFSET_TASK_ITK_SPACE,
    
#if __arm64e__
    0x368, // KSTRUCT_OFFSET_TASK_BSD_INFO,
    0x0,   // KSTRUCT_OFFSET_TASK_FLAGS (I don't know)
#else
    0x358, // KSTRUCT_OFFSET_TASK_BSD_INFO,
    0x390, // KSTRUCT_OFFSET_TASK_FLAGS
#endif
    0x0,   // KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
    0x4,   // KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
    0x40,  // KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
    0x50,  // KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
    0x60,  // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
    0x68,  // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
    0x88,  // KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG,
    0x90,  // KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
    0xa0,  // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
    
    0x10,  // KSTRUCT_OFFSET_PROC_TASK,
    0x60,  // KSTRUCT_OFFSET_PROC_PID,
    0x100, // KSTRUCT_OFFSET_PROC_P_FD
    0xF8,  // KSTRUCT_OFFSET_PROC_UCRED
    0x290, // KSTRUCT_OFFSET_PROC_CSFLAGS
    
    0x0,   // KSTRUCT_OFFSET_FILEDESC_FD_OFILES
    
    0x10,   // KSTRUCT_OFFSET_FILEPROC_F_FGLOB
    
    0x38,  // KSTRUCT_OFFSET_FILEGLOB_FG_DATA
    
    0x10,  // KSTRUCT_OFFSET_SOCKET_SO_PCB
    
    0x10,  // KSTRUCT_OFFSET_PIPE_BUFFER
    
    0x14,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE
    0x20,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE
    0x28,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TASK

    0x78,  // KSTRUCT_OFFSET_UCRED_CR_LABEL
    0x10,  // KSTRUCT_OFFSET_SANDBOX_SLOT
    
    0x7c,  // KFREE_ADDR_OFFSET
    
    0xdd0, // IOSURFACE_CREATE_OUTSIZE
    
    0xb7,  // getExternalTrapForIndex

    0xFFFFFFF0088957E8,   // KOFFSET_ZONE_MAP_REF
    0xfffffff008930e80,   // KOFFSET_TRUSTCACHE
};


uint64_t koffset(kstruct_offset offset) {
    if (offsets == NULL) {
        // printf("[-] Please call init_offsets() prior to querying offsets\n");
        return 0;
    }
    return offsets[offset];
}

uint32_t create_outsize;

int init_offsets() {
    offsets = kstruct_offsets_12_0;
    return 0;
}
