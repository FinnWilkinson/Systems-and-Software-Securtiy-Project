# S3CW
Repository for Systems and Software Security unit coursework

# Building Instructions

### Network settings for backdoor
MAKE SURE IN VM NETWORK SETTINGS: Settings->Network->Adapter 1->attached to = bridged adapter.
- This gives the VM its own ip on the network. Otherwise backdoor wont work. This now means that you cannot do `vagrant ssh`.
- To get around this, in virtualbox type `ifconfig` and look for ip address (i.e. 129.168.0.100)
- You can then do `ssh vagrant@<VAGRANT_IP>` where you would usually do `vagrant ssh`

### Booting Vagrant
1. `vagrant up` in folder containing vagrant file
2. move `rootkit.c` and `Makefile` to 'guest' folder (in same directory as vagrant file is in)
3. `vagrant ssh` 
### Clean Build Instructions Once in Vagrant
1. ``` sudo apt-get install linux-headers-`uname -r` ``` 
2. `cd /vagrant` to go to shared 'guest' folder
3. `make all`
4. `sudo insmod rootkit.ko`

