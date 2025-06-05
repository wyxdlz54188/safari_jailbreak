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

extern uint64_t kernel_slide;

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
    int rv;
    int fd;
    uint8_t *p;
    off_t sz;
    struct stat st;
    uint8_t buf[16];
    
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
    
    fake_chain.count = cnt;
    
    size_t length = (sizeof(fake_chain) + cnt * sizeof(hash_t) + 0x3FFF) & ~0x3FFF;
    uint64_t kernel_trust = kalloc(length);
    
    kwrite(kernel_trust, &fake_chain, sizeof(fake_chain));
    kwrite(kernel_trust + sizeof(fake_chain), allhash, cnt * sizeof(hash_t));
    
    wk64(trust_chain, kernel_trust);
    
    free(allhash);
    
    return 0;
}