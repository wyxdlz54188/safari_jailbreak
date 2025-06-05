#include <stdio.h>
#include <mach/mach.h>
#include "krw.h"

mach_port_t hsp4;
uint64_t kbase;

uint64_t hex_to_u64(const char *s) {
    return (uint64_t)strtoull(s, NULL, 0);
}

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		sleep(0.5);
		setuid(0); setuid(0);	//needed setuid to get hsp4 port
		
		NSLog(@"[stage3] loaded.");
  		host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &hsp4);

  		NSLog(@"[stage3] hsp4: 0x%x", hsp4);

		int fd = open("/tmp/stage3_got_hsp4", O_CREAT | O_WRONLY, 0644);
    	if (fd >= 0) close(fd);

		// test krw
		char* kbase_str = argv[1];
		kbase = hex_to_u64(kbase_str);
		NSLog(@"[stage3] kbase: 0x%llx", kbase);
		if(kread64(kbase) == 0x100000cfeedfacf) NSLog(@"[stage3] confirmed krw works");

		//TODO: chimera ...

		return 0;
	}
}
