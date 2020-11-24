#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Thomas");
MODULE_DESCRIPTION("Hello Module");
MODULE_VERSION("0.0.1");

static int __init lkm_example_init(void) {
 printk(KERN_INFO "Hello, World!\n");
 return 0;
}

static void __exit lkm_example_exit(void) {
 printk(KERN_INFO "Goodbye, World!\n");
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);
