# S3CW
Repository for Systems and Software Security unit coursework

# Building Instructions
### Booting Vagrant
1. `vagrant up` in folder containing vagrant file
2. move `rootkit.c` and `Makefile` to 'guest' folder (in same directory as vagrant file is in)
3. `vagrant ssh` 
### Clean Build Instructions Once in Vagrant
1. ``` sudo apt-install linux-headers-`uname -r` ``` 
2. `cd /vagrant` to go to shared 'guest' folder
3. `make all`
4. `sudo insmod rootkit.ko`

