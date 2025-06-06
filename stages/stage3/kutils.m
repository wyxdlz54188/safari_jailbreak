#include "kutils.h"
#include "offsets.h"
#include "krw.h"
#include "csblob.h"
#include "proc.h"

void set_proc_csflags(pid_t pid) {
    uint64_t proc = proc_of_pid(pid);
    uint32_t csflags = kread32(proc + off_p_csflags);
    csflags = csflags | CS_DEBUGGED | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW;
    csflags &= ~(CS_RESTRICT | CS_HARD | CS_KILL);
    kwrite32(proc + off_p_csflags, csflags);
}

void set_csblob(pid_t pid) {
    uint64_t proc = proc_of_pid(pid);
    uint64_t textvp = kread64(proc + off_p_textvp);
    
    uint64_t task = kread64(proc + off_p_task);
    uint32_t t_flags = kread32(task + off_task_t_flags);
    t_flags |= TF_PLATFORM;
    kwrite32(task+off_task_t_flags, t_flags);
    
    if (textvp != 0){
        uint32_t vnode_type_tag = kread32(textvp + off_vnode_v_type);
        uint16_t vnode_type = vnode_type_tag & 0xffff;
        
        if (vnode_type == 1){
            uint64_t ubcinfo = kread64(textvp + off_vnode_vu_ubcinfo);
            
            uint64_t csblobs = kread64(ubcinfo + off_ubc_info_cs_blobs);
            while (csblobs != 0){
                
                unsigned int csb_platform_binary = kread32(csblobs + off_cs_blob_csb_platform_binary);
                
                kwrite32(csblobs + off_cs_blob_csb_platform_binary, 1);
                
                csb_platform_binary = kread32(csblobs + off_cs_blob_csb_platform_binary);
                csblobs = kread64(csblobs);
            }
        }
    }
}

uint64_t borrow_cr_label(pid_t to_pid, pid_t from_pid) {
    uint64_t to_proc = proc_of_pid(to_pid);
    uint64_t from_proc = proc_of_pid(from_pid);
    
    uint64_t to_ucred = kread64(to_proc + off_p_ucred);
    uint64_t from_ucred = kread64(from_proc + off_p_ucred);

    uint64_t to_cr_label = kread64(to_ucred + off_u_cr_label);
    uint64_t from_cr_label = kread64(from_ucred + off_u_cr_label);
    
    kwrite64(to_ucred + off_u_cr_label, from_cr_label);
    
    return to_cr_label;
}

void unborrow_cr_label(pid_t to_pid, uint64_t to_cr_label) {
    uint64_t to_proc = proc_of_pid(to_pid);
    uint64_t to_ucred = kread64(to_proc + off_p_ucred);
    
    kwrite64(to_ucred + off_u_cr_label, to_cr_label);
}

void set_ucred_cr_svuid(pid_t pid, uint64_t val) {
    uint64_t proc = proc_of_pid(pid);
    uint64_t ucred = kread64(proc + off_p_ucred);
    kwrite64(ucred + off_u_cr_svuid, val);
}