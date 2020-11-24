cmd_/vagrant/rootkit.ko := ld -r -m elf_x86_64 -T /usr/src/linux-headers-3.2.0-126-generic/scripts/module-common.lds --build-id  -o /vagrant/rootkit.ko /vagrant/rootkit.o /vagrant/rootkit.mod.o
