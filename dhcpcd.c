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

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "config.h"
#include "dhcpcd.h"
#include "dhcpcd-dbus.h"

/* Only GLIBC doesn't support strlcpy */
#ifdef __GLIBC__
#  if !defined(__UCLIBC__) && !defined (__dietlibc__)
#    define strlcpy(dst, src, n) snprintf(dst, n, "%s", src);
#  endif
#endif

char *dhcpcd_version = NULL;
const char *dhcpcd_status = NULL;
struct config *configs = NULL;

static int command_fd = -1;
static int listen_fd = -1;

const char *const up_reasons[] = {
	"BOUND",
	"RENEW",
	"REBIND",
	"REBOOT",
	"IPV4LL",
	"INFORM",
	"TIMEOUT",
	NULL
};

static ssize_t
_dhcpcd_command(int fd, const char *cmd, char **buffer) 
{
	ssize_t bytes, len;
	char c[1024], *p;

	/* each argument is NULL seperated.
	 * We may need to send a space one day, so the API
	 * in this function may need to be improved */
	bytes = strlen(cmd) + 1;
	strlcpy(c, cmd, sizeof(c));
	p = c;
	while ((p = strchr(p, ' ')) != NULL)
		*p++ = '\0';
	bytes = write(fd, c, bytes);
	if (bytes == -1)
		return -1;
	if (buffer == NULL)
		return 0;

	bytes = read(fd, c, sizeof(ssize_t));
	if (bytes == 0 || bytes == -1)
		return bytes;
	memcpy(&len, c, sizeof(ssize_t));
	*buffer = malloc(len + 1);
	if (*buffer == NULL) {
		syslog(LOG_ERR, "malloc: %m");
		exit(EXIT_FAILURE);
	}
	bytes = read(fd, *buffer, len);
	if (bytes != -1 && bytes < len)
		*buffer[bytes] = '\0';
	return bytes;
}

ssize_t
dhcpcd_command(const char *cmd, char **buffer) 
{
	return _dhcpcd_command(command_fd, cmd, buffer);
}

static int
dhcpcd_open(void)
{
	int fd, len;
	struct sockaddr_un sun;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return -1;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, DHCPCD_SOCKET, sizeof(sun.sun_path));
	len = sizeof(sun.sun_family) + strlen(sun.sun_path) + 1;
	if (connect(fd, (struct sockaddr *)&sun, len) == 0)
		return fd;
	close(fd);
	return -1;
}

size_t
add_dhcpcd_listeners(struct pollfd *fds)
{
	if (listen_fd == -1)
		return 0;

	if (fds != NULL) {
		fds->fd = listen_fd;
		fds->events = POLLIN | POLLHUP | POLLERR;
	}
	return 1;
}

static const char *
_get_dhcp_config(const char *data, size_t len, const char *var)
{
	const char *end;
	size_t vlen;

	end = data + len;
	vlen = strlen(var);
	while (data < end) {
		if (strncmp(data, var, vlen) == 0)
			return data + vlen;
		data += strlen(data) + 1;
	}
	return NULL;
}

const char *
get_dhcp_config(const struct config *c, const char *var)
{
	return _get_dhcp_config(c->data, c->data_len, var);
}

static const char *
get_status(void)
{
	const char *nstatus, *reason;
	const struct config *c;
	const char *const *r;

	nstatus = NULL;
	for (c = configs; c; c = c->next) {
		reason = get_dhcp_config(c, "reason=");
		if (reason == NULL)
			continue;
		for (r = up_reasons; *r; r++) {
			if (strcmp(*r, reason) == 0) {
				nstatus = "connected";
				break;
			}
		}
		if (nstatus && strcmp(nstatus, "connected") == 0)
			break;
		if (strcmp(reason, "CARRIER") == 0)
			nstatus = "connecting";
	}
	if (nstatus == NULL)
		nstatus = "disconnected";
	return nstatus;
}

struct config *
find_config(const char *iface)
{
	struct config *c;

	for (c = configs; c; c = c->next)
		if (strcmp(c->iface, iface) == 0)
			return c;
	return NULL;
}

static struct config *
add_config(char *data, size_t len)
{
	const char *iface;
	struct config *c;

	iface = _get_dhcp_config(data, len, "interface=");
	if (iface == NULL) {
		syslog(LOG_ERR, "dhcpcd: no interface in config");
		return NULL;
	}
	c = find_config(iface);
	if (c == NULL) {
		c = malloc(sizeof(*c));
		if (c == NULL) {
			syslog(LOG_ERR, "malloc: %m");
			return NULL;
		}
		c->next = configs;
		configs = c;
	} else
		free(c->data);

	c->iface = iface;
	c->data = data;
	c->data_len = len;
	return c;
}

static struct config *
read_config(int fd)
{
	char sbuf[sizeof(ssize_t)], *rbuf;
	ssize_t bytes, len;
	struct config *c;

	bytes = read(fd, sbuf, sizeof(sbuf));
	if (bytes == 0 || bytes == -1) {
		syslog(LOG_ERR, "lost connection to dhcpcd");
		return NULL;
	}
	memcpy(&len, sbuf, sizeof(len));
	rbuf = malloc(len + 1);
	if (rbuf == NULL) {
		syslog(LOG_ERR, "malloc: %m");
		exit(EXIT_FAILURE);
	}
	bytes = read(fd, rbuf, len);
	if (bytes == 0 || bytes == -1) {
		syslog(LOG_ERR, "lost connection to dhcpcd");
		free(rbuf);
		return NULL;
	}
	if (bytes != len) {
		free(rbuf);
		syslog(LOG_ERR, "dhcpcd: failed to read buffer");
		return NULL;
	}
	rbuf[bytes] = '\0';
	c = add_config(rbuf, len);
	if (c == NULL) {
		free(rbuf);
		return NULL;
	}
	return c;
}

void
check_dhcpcd_listeners(struct pollfd *fds, size_t nfds)
{
	size_t i;
	struct config *c;
	const char *nstatus;

	for (i = 0; i < nfds; i++) {
		if (fds[i].fd != listen_fd)
			continue;
		if (fds[i].revents & POLLIN) {
			c = read_config(fds[i].fd);
			if (c == NULL) {
				dhcpcd_close();
				break;
			}
			configure_dbus(c);
			nstatus = get_status();
			if (strcmp(nstatus, dhcpcd_status)) {
				dhcpcd_status = nstatus;
				signal_dhcpcd_status(nstatus);
			}
		}
	}
}

int
dhcpcd_init(void)
{
	char cmd[128];
	ssize_t nifs, bytes;
	struct config *c;
	static int last_errno;
	const char *nstatus;

	if (command_fd != -1)
		return 0;
	command_fd = dhcpcd_open();
	if (command_fd == -1) {
		if (errno != last_errno) {
			last_errno = errno;
			syslog(LOG_ERR, "failed to connect to dhcpcd: %m");
		}
		return -1;
	}

	if (dhcpcd_command("--version", &dhcpcd_version) > 0) {
		syslog(LOG_INFO, "connected to dhcpcd-%s", dhcpcd_version);
	} else {
		syslog(LOG_ERR, "failed to get dhcpcd version");
		exit(EXIT_FAILURE);
	}

	listen_fd = dhcpcd_open();
	if (listen_fd == -1)
		return -1;
	_dhcpcd_command(listen_fd, "--listen", NULL);

	while (configs != NULL) {
		c = configs->next;
		free(configs);
		configs = c;
	}
	dhcpcd_command("--getinterfaces", NULL);
	bytes = read(command_fd, cmd, sizeof(ssize_t));
	if (bytes != sizeof(ssize_t))
		return bytes;
	memcpy(&nifs, cmd, sizeof(ssize_t));
	for (;nifs > 0; nifs--) {
		c = read_config(command_fd);
		if (c == NULL)
			return configs == NULL ? -1 : 0;
		syslog(LOG_INFO, "retrieved interface %s (%s)",
		       c->iface, get_dhcp_config(c, "reason="));
	}

	nstatus = get_status();
	if (dhcpcd_status == NULL || strcmp(nstatus, dhcpcd_status)) {
		dhcpcd_status = nstatus;
		signal_dhcpcd_status(nstatus);
	}

	return 0;
}

int
dhcpcd_close(void)
{
	int retval;
	struct config *c;

	retval = shutdown(command_fd, SHUT_RDWR);
	command_fd = -1;
	retval |= shutdown(listen_fd, SHUT_RDWR);
	listen_fd = -1;
	while (configs != NULL) {
		c = configs->next;
		free(configs->data);
		free(configs);
		configs = c;
	}
	return retval;
}
