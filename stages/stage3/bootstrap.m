#include "bootstrap.h"
#include "NSData+GZip.h"
#include "amfi_utils.h"

#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <mach-o/dyld.h>
#include <copyfile.h>
#include <spawn.h>

#define cp(to, from) copyfile(from, to, 0, COPYFILE_ALL)

void extract_bootstrap() {
    //we need tar, rm, basebinaries.tar, and launchctl

    mkdir("/chimera", 0755);
    extractGz("tar", "/chimera/tar");
    chmod("/chimera/tar", 0755);
    inject_trusts(1, (const char **)&(const char*[]){"/chimera/tar"});

    unlink("/chimera/jailbreakd");
    unlink("/chimera/jailbreakd_client");
    unlink("/chimera/pspawn_payload.dylib");

    extractGz("rm", "/chimera/rm");
    chmod("/chimera/rm", 0755);

    pid_t pd;
    posix_spawn(&pd, "/chimera/tar", NULL, NULL, (char **)&(const char*[]){ "/chimera/tar", "-xpf", progname("basebinaries.tar"), "-C", "/chimera", NULL }, NULL);
    waitpid(pd, NULL, 0);
    unlink("/chimera/launchctl");
    extractGz("launchctl", "/chimera/launchctl");
    chmod("/chimera/launchctl", 0755);

    if (!file_exist("/bin/launchctl"))
    {
        cp("/bin/launchctl", "/chimera/launchctl");
        chmod("/bin/launchctl", 0755);
    }

    unlink("/usr/lib/pspawn_payload-stg2.dylib");
    cp("/usr/lib/pspawn_payload-stg2.dylib", "/chimera/pspawn_payload-stg2.dylib");

    inject_trusts(6, (const char **)&(const char*[]){
        "/chimera/inject_criticald",
        "/chimera/pspawn_payload.dylib",
        "/chimera/pspawn_payload-stg2.dylib",
        "/chimera/jailbreakd",
        "/chimera/jailbreakd_client",
        "/chimera/launchctl"
    });
}

void extractGz(const char *from, const char *to) {
    NSData *gz = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@(from) ofType:@"gz"]];
    NSData *extracted = [gz gunzippedData];
    int fd = open(to, O_CREAT | O_WRONLY, 0755);
    write(fd, [extracted bytes], [extracted length]);
    close(fd);
}

const char* realPath() {
    char path[4096];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
    char *pt = realpath(path, NULL);
    return pt;
}

const char* progname(const char* prog) {
    NSString *execpath = [[NSString stringWithUTF8String:realPath()] stringByDeletingLastPathComponent];

    NSString *bootstrap = [execpath stringByAppendingPathComponent:[NSString stringWithUTF8String:prog]];
    return [bootstrap UTF8String];
}

int file_exist(const char *filename) {
    struct stat buffer;
    int r = stat(filename, &buffer);
    return (r == 0);
}