#include <stdio.h>
#include <mach/mach.h>
#include "krw.h"
#include "alert.h"
#include "rejailbreak.h"

#define IS_UNJAILBROKEN_DEVICE 1

mach_port_t g_hsp4;
uint64_t g_kbase;
uint64_t g_kernproc;

uint64_t hex_to_u64(const char *s) {
    return (uint64_t)strtoull(s, NULL, 0);
}

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
#if IS_UNJAILBROKEN_DEVICE
		sleep(1);
		setuid(0); setuid(0);	//needed setuid to get hsp4 port
		
		NSLog(@"[stage3] loaded.");
		
  		host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &g_hsp4);
  		NSLog(@"[stage3] hsp4: 0x%x", g_hsp4);

		int fd = open("/tmp/stage3_got_hsp4", O_CREAT | O_WRONLY, 0644);
    	if (fd >= 0) close(fd);

		// save global kernel info
		char* kbase_str = argv[1];
		g_kbase = hex_to_u64(kbase_str);
		NSLog(@"[stage3] kbase: 0x%llx", g_kbase);
		char* kernproc_str = argv[2];
		g_kernproc = hex_to_u64(kernproc_str);
		NSLog(@"[stage3] kernproc: 0x%llx", g_kernproc);

		// test krw
		if(kread64(g_kbase) == 0x100000cfeedfacf) NSLog(@"[stage3] confirmed krw works");
#endif
		NSString *msg = [NSString stringWithFormat:@"hsp4: 0x%x, kbase: %s", g_hsp4, argv[1]];
		popupTimeout(CFSTR("kernel pwned"), (__bridge CFStringRef)msg, CFSTR("OK"), NULL, NULL, 3);

		rejailbreak_chimera();

		return 0;
	}
}
