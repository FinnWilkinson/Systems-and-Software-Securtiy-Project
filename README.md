# S3CW
Repository for Systems and Software Security unit coursework

# Building Instructions

## Backdoor Instructions

### Turn on SSH port forwarding
For own computer connecting to rootkit back door:
1. Find your local ip address, subnet mask, and Default gateway (ipconfig for windows/mac, ifconfig for linux). Default gateway is typically your ip address with the last section being 1 (i.e. x.x.x.1, where 0 <= x <= 255)
2. We need to ensure our own pc has a static IP on the network to make sure port forwarding works:

**Windows**
1. Go to **network Settings** -> **change adapter settings**
2. Right click on **wifi** or **ethernet** (depending how you connect to your network)
3. Go **properties** -> select **Internet Protocol Version 4 (TCP/IPv4)** -> **properties**
4. Select **use following IP address**
5. Enter the information you collected from `ipconfig` in respective fields. For DNS server, we can use Google's Public DNS which has address `8.8.8.8`

**Mac**

**Linux**


**Now we have a static IP set, we need to dd port forwarding rule**
1. Goto your routers settings
2. Add a port forwarding rule (usually in security or firewall) for port 22 and your local static ip address

### Configuration before installing rootkit
1. Make sure python is installed, and run `python config.py` to set up file with your pc username and public ip address
2. Go to directory with rootkit folder in it, and generate ssh key-pair with `ssh-keygen`
3. In the rootkit folder, make sure it contains both `ssh_key.pub` and `backdoor_config.txt` files



### Booting Vagrant
In order to showcase our rootkit, we will be using a Vagrant VM running Ubuntu 12.04. Make sure if you are using a VM that is has a **Bridged Connection** in its Network settings
1. `vagrant up` in folder containing vagrant file
2. move rootkit files to 'guest' folder (in same directory as vagrant file is in)
3. `vagrant ssh` 
### Clean Build Instructions Once in Vagrant
1. ``` sudo apt-get install linux-headers-`uname -r` ``` 
2. `cd /vagrant` to go to shared 'guest' folder
3. `make all`
4. `sudo insmod rootkit.ko`

