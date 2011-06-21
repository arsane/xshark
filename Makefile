# Makefile - build xshark binary
#
# Copyright 2010 Sam Liao
#
# Modification History
#
# Description
# This file contains the makefile rules for building the xshark 
# for linux.
#

CC = $(CROSS_COMPILE)gcc

CFLAGS += -g -Wall -I/usr/include/wireshark `pkg-config --cflags glib-2.0 gthread-2.0`

OBJS := xshark.o xdb.o xprint.o

all : xshark 

xshark : $(OBJS)
	$(LINK.o) -o $@ $(OBJS) `pkg-config --libs glib-2.0 gthread-2.0` \
		-Wl,-rpath=/usr/lib/wireshark \
		/usr/lib/wireshark/libwireshark.so /usr/lib/wireshark/libwiretap.so

clean:
	$(RM) xshark $(OBJS:.o=.d) $(OBJS)

-include $(OBJS:.o=.d)

%.o : %.c
	$(COMPILE.c) -MMD -MP -o $@ $<

.PHONY: all clean
