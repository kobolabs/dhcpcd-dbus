/*
 * dhcpcd-dbus
 * Copyright 2009 Roy Marples <roy@marples.name>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#include "config.h"
#include "eloop.h"
#include "dhcpcd.h"
#include "dhcpcd-dbus.h"
#include "wpa.h"

const char copyright[] = "Copyright (c) 2009-2012 Roy Marples";

static void
cleanup(void)
{

	dhcpcd_dbus_close();
	wpa_close(NULL);
#ifdef DEBUG_MEMORY
	dhcpcd_close();
#endif
}

static void
handle_signal(int sig)
{

	if (sig) {
		syslog(LOG_INFO, "Got signal %d, exiting", sig);
		exit(EXIT_SUCCESS);
	}
}

int
main(void)
{

	openlog(PACKAGE, LOG_PERROR, LOG_DAEMON);
	setlogmask(LOG_UPTO(LOG_INFO));
	syslog(LOG_INFO, "starting " PACKAGE "-" VERSION);

	atexit(cleanup);
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	/* Ignore pipes */
	signal(SIGPIPE, SIG_IGN);

	if (dhcpcd_dbus_init() == -1)
		exit(EXIT_FAILURE);
	dhcpcd_init(NULL);

	syslog(LOG_INFO, "init completed, waiting for events");
	start_eloop();
	exit(EXIT_SUCCESS);
}
