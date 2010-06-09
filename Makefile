PROG=		dhcpcd-dbus
SRCS=		dhcpcd.c dbus-dict.c dhcpcd-dbus.c wpa.c wpa-dbus.c
SRCS+=		eloop.c main.c

OBJS=		${SRCS:.c=.o}

CFLAGS?=	-O2
include config.mk

CONFFILES=	dhcpcd-dbus.conf
FILES=		name.marples.roy.dhcpcd.service
CONFDIR=	${SYSCONFDIR}/dbus-1/system.d
FILESDIR=	${PREFIX}/share/dbus-1/system-services
CLEANFILES+=	name.marples.roy.dhcpcd.service

_VERSION_SH=	sed -n 's/\#define VERSION[[:space:]]*"\(.*\)".*/\1/p' defs.h
_VERSION!=	${_VERSION_SH}
VERSION=	${_VERSION}$(shell ${_VERSION_SH})

GITREF?=	HEAD
DISTPREFIX?=	${PROG}-${VERSION}
DISTFILE?=	${DISTPREFIX}.tar.bz2

.SUFFIXES: .in

all: ${PROG} ${FILES}

.in:
	${SED} -e 's:@LIBEXECDIR@:${LIBEXECDIR}:g' $@.in > $@

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c $< -o $@

.depend: ${SRCS} ${COMPAT_SRCS}
	${CC} ${CPPFLAGS} -MM ${SRCS} ${COMPAT_SRCS} > .depend

depend: .depend

${PROG}: .depend ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

install:
	${INSTALL} -d ${DESTDIR}${LIBEXECDIR}
	${INSTALL} -m ${BINMODE} ${PROG} ${DESTDIR}${LIBEXECDIR}
	${INSTALL} -d ${DESTDIR}${CONFDIR}
	${INSTALL} -m ${FILESMODE} ${CONFFILES} ${DESTDIR}${CONFDIR}
	${INSTALL} -d ${DESTDIR}${FILESDIR}
	${INSTALL} -m ${FILESMODE} ${FILES} ${DESTDIR}${FILESDIR}

clean:
	rm -f ${OBJS} ${PROG} ${PROG}.core ${CLEANFILES}

distclean: clean
	rm -f .depend config.h config.mk

dist:
	git archive --prefix=${DISTPREFIX}/ ${GITREF} | bzip2 > ${DISTFILE}

include Makefile.inc
