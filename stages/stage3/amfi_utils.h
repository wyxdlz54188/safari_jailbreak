#include <stdint.h>

void getSHA256inplace(const uint8_t* code_dir, uint8_t *out);
uint8_t *getSHA256(const uint8_t* code_dir);
uint8_t *getCodeDirectory(const char* name);

// Trust cache types
typedef char hash_t[20];

struct trust_chain {
    uint64_t next;
    unsigned char uuid[16];
    unsigned int count;
} __attribute__((packed));


void inject_trusts(int pathc, const char *paths[]);