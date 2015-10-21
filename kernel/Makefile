EXTRA_CFLAGS += -Wall -Wmissing-prototypes -Wstrict-prototypes
ifndef KDIR
KDIR   := /lib/modules/$(shell uname -r)
endif

obj-m  := ratekeeper.o
KBUILD := $(KDIR)/build
KNET   := $(KDIR)/kernel/net
PWD    := $(shell pwd)
HOOK   := $(PWD)/tc/

ratekeeper-y := messaging.o monitor.o rk.o

all: *.c
	$(MAKE) -C tc
	$(MAKE) -C $(KBUILD) SUBDIRS=$(PWD) \
	KBUILD_EXTRA_SYMBOLS=$(HOOK)/Module.symvers modules

clean:
	rm -rf *.o *.ko *mod.c *~ .*.cmd .tmp_versions Module.symvers \
	 modules.order
	$(MAKE) -C tc clean

install: all
	install -m 0644 ratekeeper.ko $(KNET)
	@if [ ! -e "$(KNET)/sched/act_mirred.ko.u" ]; then \
		mv $(KNET)/sched/act_mirred.ko $(KNET)/sched/act_mirred.ko.u; \
	fi
	install -m 0644 tc/act_mirred.ko $(KNET)/sched/
	depmod

uninstall:
	rm -f $(KNET)/ratekeeper.ko
	depmod

.PHONY: all install uninstall clean
