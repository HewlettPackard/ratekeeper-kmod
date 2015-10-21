CC = gcc
CFLAGS = -Wall -g

LIBNL = $(shell pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0)
LIBS = $(LIBNL) -lm -lrt

SRCS = tc.c util.c ifcache.c
OBJS = $(SRCS:.c=.o)

RKD_SRCS = rkvif.c rkinc.c
RKD_OBJS = $(RKD_SRCS:.c=.o)

all: rk-daemon rkconfig

rk-daemon: $(OBJS) $(RKD_OBJS) rk-daemon.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

rkconfig: $(OBJS) rkconfig.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@ $(LIBS)
# TODO: dependencies related to .h files

install: all
	install -m 0755 rk-daemon /usr/bin
	install -m 0755 rkconfig /usr/bin
	install -m 0755 etc/init.d/ratekeeper /etc/init.d
	install -m 0644 etc/default/ratekeeper /etc/default

uninstall:
	rm -f /usr/bin/rk-daemon
	rm -f /usr/bin/rkconfig
	rm -f /etc/init.d/ratekeeper
	rm -f /etc/default/ratekeeper

clean:
	rm -rf *.o *~ rk rk-daemon rkconfig

.PHONY: all install uninstall clean
