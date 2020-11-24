#ifndef ROOTKIT_MAIN_H_INCLUDED
#define ROOTKIT_MAIN_H_INCLUDED

void hide(void);

void unhide(void);

static int __init lkm_example_init(void);

static void __exit lkm_example_exit(void);

#endif