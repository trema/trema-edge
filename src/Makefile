#
# Copyright (C) 2013 NEC Corporation
#

SUBDIRS = lib packetin_filter switch_manager switchd examples

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)
	@for DIR in $(SUBDIRS); do ( cd $$DIR; make all ); done

clean: $(SUBDIRS)
	@for DIR in $(SUBDIRS); do ( cd $$DIR; make clean ); done
