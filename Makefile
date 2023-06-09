#
# Copyright (c) 2014 Vitaly Sinilin <vs@kp4.ru>
#
# See the included COPYING file.
#
VERSION = 0.2+git

CFLAGS = -W -Wall -D_BSD_SOURCE -D_DEFAULT_SOURCE -DVERSION_STR=\"$(VERSION)\"

ifdef DEBUG
	CFLAGS += -g -DDEBUG
endif

DESTDIR =
PREFIX = /usr/local

bindir = $(PREFIX)/bin
mandir = $(PREFIX)/share/man

override bindir := $(DESTDIR)$(bindir)
override mandir := $(DESTDIR)$(mandir)

all: egctl

install: egctl
	install -D egctl $(bindir)/egctl
	install -D -m 644 egctl.1 $(mandir)/man1/egctl.1

uninstall:
	$(RM) $(bindir)/egctl
	$(RM) $(mandir)/man1/egctl.1

clean:
	$(RM) egctl

.PHONY: all install uninstall clean
