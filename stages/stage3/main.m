#include <stdio.h>
#include <mach/mach.h>


int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		sleep(1);
		setuid(0); setuid(0);	//needed setuid to get hsp4 port
		
		NSLog(@"[stage3] loaded.");
		mach_port_t hsp4 = MACH_PORT_NULL;
  		host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &hsp4);

  		NSLog(@"[stage3] hsp4: 0x%x", hsp4);

		int fd = open("/tmp/stage3_got_hsp4", O_CREAT | O_WRONLY, 0644);
    	if (fd >= 0) close(fd);
		//uid 501 start~

		

		return 0;
	}
}
