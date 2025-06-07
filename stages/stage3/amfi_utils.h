#include <stdint.h>

// Trust cache types
typedef char hash_t[20];

struct trust_chain {
    uint64_t next;
    unsigned char uuid[16];
    unsigned int count;
} __attribute__((packed));


void inject_trusts(int pathc, const char *paths[]);