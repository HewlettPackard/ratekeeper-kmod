obj-m := act_mirred.o
ifndef KDIR
KDIR   := /lib/modules/$(shell uname -r)
endif

KBUILD := $(KDIR)/build
PWD   := $(shell pwd)

all: *.c
	@echo KBUILD, $(KBUILD)
	$(MAKE) -C $(KBUILD) SUBDIRS=$(PWD) modules

clean:
	rm -rf *.o *.ko *mod.c *~ .*.cmd .tmp_versions Module.symvers \
	 modules.order

.PHONY: all clean
