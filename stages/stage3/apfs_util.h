#define get_dirfd(vol) open(vol, O_RDONLY, 0)

int list_snapshots(const char *vol);