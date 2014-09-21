KVERSION = $(shell uname -r)

obj-m += smartcapwap.o

smartcapwap-y := \
	main.o \
	netlinkapp.o \
	capwap.o \
	capwap_private.o \
	socket.o \
	iface.o

all:
	make -C /lib/modules/$(KVERSION)/build M="$(PWD)" modules

clean:
	make -C /lib/modules/$(KVERSION)/build M="$(PWD)" clean
