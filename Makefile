# Makefile based on BSD make.
# Our mk stubs also work with GNU make.
# Copyright 2008 Roy Marples <roy@marples.name>

PROG=		dhcpcd-dbus
SRCS=		dhcpcd.c dhcpcd-dbus.c main.c

CONFFILES=	dhcpcd-dbus.conf
FILES=		name.marples.roy.dhcpcd.service
CLEANFILES+=	name.marples.roy.dhcpcd.service

PREFIX?=	/usr/local
BINDIR?=	${PREFIX}/libexec
SYSCONFDIR?=	${PREFIX}/etc/dbus-1/system.d
FILESDIR?=	${PREFIX}/share/dbus-1/system-services

_DBUSCFLAGS_SH=	pkg-config --cflags dbus-1
_DBUSCFLAGS!=	${_DBUSCFLAGS_SH}
DBUSCFLAGS=	${_DBUSCFLAGS}$(shell ${_DBUSCFLAGS_SH})

_DBUSLIBS_SH=	pkg-config --libs dbus-1
_DBUSLIBS!=	${_DBUSLIBS_SH}
DBUSLIBS=	${_DBUSLIBS}$(shell ${_DBUSLIBS_SH})

CFLAGS+=	${DBUSCFLAGS}
LDADD+=		${DBUSLIBS}

.SUFFIXES: .in

all: ${TARGET} ${FILES}

.in:
	sed -e 's:@BINDIR@:${BINDIR}:g' $@.in > $@

MK=		mk
include ${MK}/sys.mk
include ${MK}/prog.mk
