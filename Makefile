$(if $(wildcard config.mak),,$(error Please run configure first))
include config.mak

export KDIR
export ARCH

actmirred:
	@./patches/dlnd_patch_actmirred.sh

all: actmirred
	$(MAKE) -C kernel
	$(MAKE) -C user

install: all
	$(MAKE) -C kernel install
	$(MAKE) -C user install

uninstall:
	$(MAKE) -C kernel uninstall
	$(MAKE) -C user uninstall

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C user clean

.PHONY: actmirred all install uninstall clean
