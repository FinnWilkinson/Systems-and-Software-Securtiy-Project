#include <stdio.h>
#include <stdlib.h>

#define START_ROOTKIT "echo \"this is what i'd be saying if i were starting the rootkit\""
#define RUN_ORIGINAL  "echo \"this is what i'd be saying if i were running the original /sbin/init\""

int main(int argc, char *argv[]) {
    // start our rootkit
    int return_rootkit  = system(START_ROOTKIT);

    // run the original /sbin/init
    int return_original = system(RUN_ORIGINAL);

    return return_original;
}