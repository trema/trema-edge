#
# Copyright (C) 2012 NEC Corporation
#

CC = gcc
AR = ar
RANLIB = ranlib

CFLAGS = -I../../lib/ -g -std=gnu99 -D_GNU_SOURCE -fno-strict-aliasing -Wall -Werror -Wextra -Wformat=2 -Wcast-qual -Wcast-align -Wwrite-strings -Wconversion -Wfloat-equal -Wpointer-arith
LDFLAGS = -ltrema -lpthread -lsqlite3 -ldl -lrt

LIBDIR = ../../lib

TARGET_LEARNSW = learning_switch
SRCS_LEARNSW = learning_switch.c
OBJS_LEARNSW = $(SRCS_LEARNSW:.c=.o)

TARGETS = $(TARGET_LEARNSW)
SRCS = $(SRCS_LEARNSW)
OBJS = $(OBJS_LEARNSW)

DEPENDS = .depends

.PHONY: all clean

.SUFFIXES: .c .o

all: depend $(TARGETS)

$(TARGET_LEARNSW): $(OBJS_LEARNSW)
	$(CC) -L$(LIBDIR) -o $(TARGET_LEARNSW) $(OBJS_LEARNSW) $(LIBDIR)/libtrema.a $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $<

depend: 
	$(CC) -MM $(CFLAGS) $(SRCS) > $(DEPENDS)

clean:
	@rm -rf $(DEPENDS) $(OBJS) $(TARGETS) *~

-include $(DEPENDS)
