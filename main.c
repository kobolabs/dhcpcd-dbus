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
#include <poll.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#include "config.h"
#include "dhcpcd.h"
#include "dhcpcd-dbus.h"
#include "wpa.h"

static struct pollfd *fds;
static size_t nfds;

#ifdef DEBUG_MEMORY
static void
cleanup(void)
{
	free(fds);
	wpa_close(NULL);
}
#endif

int
main(void)
{
	size_t n, dhcpcd_n;
	int i, t;

	openlog(PACKAGE, LOG_PERROR, LOG_DAEMON);
	setlogmask(LOG_UPTO(LOG_INFO));
	syslog(LOG_INFO, "starting " PACKAGE "-" VERSION);

#ifdef DEBUG_MEMORY
	atexit(cleanup);
#endif

	if (dhcpcd_dbus_init() == -1)
		exit(EXIT_FAILURE);

	for (;;) {
		dhcpcd_n = dhcpcd_add_listeners(NULL);
		if (dhcpcd_n == 0) {
			dhcpcd_init();
			dhcpcd_n = dhcpcd_add_listeners(NULL);
			/* Attempt another dhcpcd connection */
			t = 1000;
		} else
			t = -1;
		n = dhcpcd_n;
		n += dhcpcd_dbus_add_listeners(NULL);
		if (n > nfds) {
			nfds = n;
			fds = malloc(sizeof(*fds) * nfds);
			if (fds == NULL) {
				syslog(LOG_ERR, "malloc: %m");
				exit(EXIT_FAILURE);
			}
		}
		n = dhcpcd_add_listeners(fds);
		n += dhcpcd_dbus_add_listeners(fds + n);
		i = poll(fds, n, t);
		if (i == 0)
			continue;
		dhcpcd_check_listeners(fds, n);
		dhcpcd_dbus_check_listeners(fds, n);
	}
	exit(EXIT_SUCCESS);
}
