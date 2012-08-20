#
# Copyright (C) 2012 NEC Corporation
#

SUBDIRS = dumper dumper_debug learning_switch

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)
	@for DIR in $(SUBDIRS); do ( cd $$DIR; make all ); done

clean: $(SUBDIRS)
	@for DIR in $(SUBDIRS); do ( cd $$DIR; make clean ); done
