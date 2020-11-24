#include <sys/sysinfo.h>    // sysinfo
#include <stdio.h>
#include <unistd.h>     // sysconf
#include <syscalls.h>       // just contains a wrapper function - error

int main()
{
    struct sysinfo info;

    if (sysinfo(&info) != 0)
        error("sysinfo: error reading system statistics");

    printf("Uptime: %ld:%ld:%ld\n", info.uptime/3600, info.uptime%3600/60, info.uptime%60);
    printf("Total RAM: %ld MB\n", info.totalram/1024/1024);
    printf("Free RAM: %ld MB\n", (info.totalram-info.freeram)/1024/1024);
    printf("Process count: %d\n", info.procs);
    printf("Page size: %ld bytes\n", sysconf(_SC_PAGESIZE));

    return 0;
}
