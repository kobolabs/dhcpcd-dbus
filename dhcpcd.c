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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "config.h"
#include "dhcpcd.h"
#include "dhcpcd-dbus.h"
#include "eloop.h"
#include "wpa.h"

char *dhcpcd_version = NULL;
const char *dhcpcd_status = NULL;
struct dhcpcd_config *dhcpcd_configs = NULL;
static char *order;

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

int
set_nonblock(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1
	    || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
	{
		syslog(LOG_ERR, "fcntl: %m");
		return -1;
	}
	return 0;
}

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
dhcpcd_add_listeners(struct pollfd *fds)
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
_get_value(const char *data, size_t len, const char *var)
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
dhcpcd_get_value(const struct dhcpcd_config *c, const char *var)
{
	return _get_value(c->data, c->data_len, var);
}

static const char *
get_status(void)
{
	const char *nstatus, *reason;
	const struct dhcpcd_config *c;
	const char *const *r;

	if (command_fd == -1 || listen_fd == -1)
		return "down";
	nstatus = NULL;
	for (c = dhcpcd_configs; c; c = c->next) {
		reason = dhcpcd_get_value(c, "reason=");
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

struct dhcpcd_config *
dhcpcd_get_config(const char *iface)
{
	struct dhcpcd_config *c;

	for (c = dhcpcd_configs; c; c = c->next)
		if (strcmp(c->iface, iface) == 0)
			return c;
	return NULL;
}

static void
sort_configs(void)
{
	struct dhcpcd_config *c, *nc = NULL, *nl = NULL;
	char *tmp, *p, *token;

	if (order == NULL)
		return;
	tmp = p = strdup(order);
	while ((token = strsep(&p, " "))) {
		if (*token == '\0')
			continue;
		c = dhcpcd_get_config(token);
		if (c == NULL)
			continue;
		if (c->next)
			c->next->prev = c->prev;
		if (c->prev)
			c->prev->next = c->next;
		else
			dhcpcd_configs = c->next;
		c->next = NULL;
		c->prev = nl;
		if (nl) {
			nl->next = c;
			nl = c;
		} else
			nc = nl = c;
	}
	free(tmp);
	dhcpcd_configs = nc;

	printf ("new order: ");
	for (c = dhcpcd_configs; c; c = c->next)
		printf ("%s ", c->iface);
	printf ("\n");
}

static struct dhcpcd_config *
prepend_config(char *data, size_t len)
{
	const char *iface;
	struct dhcpcd_config *c;

	iface = _get_value(data, len, "interface=");
	if (iface == NULL) {
		syslog(LOG_ERR, "dhcpcd: no interface in config");
		return NULL;
	}
	c = dhcpcd_get_config(iface);
	if (c == NULL) {
		c = malloc(sizeof(*c));
		if (c == NULL) {
			syslog(LOG_ERR, "malloc: %m");
			return NULL;
		}
		if (dhcpcd_configs)
			dhcpcd_configs->prev = c;
		c->next = dhcpcd_configs;
		c->prev = NULL;
		dhcpcd_configs = c;
	} else
		free(c->data);

	c->iface = iface;
	c->data = data;
	c->data_len = len;
	return c;
}

static struct dhcpcd_config *
read_config(int fd)
{
	char sbuf[sizeof(ssize_t)], *rbuf;
	ssize_t bytes, len;
	struct dhcpcd_config *c;

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
	c = prepend_config(rbuf, len);
	if (c == NULL) {
		free(rbuf);
		return NULL;
	}
	return c;
}

static void
update_status(void)
{
	const char *nstatus;

	nstatus = get_status();
	if (dhcpcd_status == NULL || strcmp(nstatus, dhcpcd_status)) {
		dhcpcd_status = nstatus;
		dhcpcd_dbus_signal_status(nstatus);
	}
}

static void
handle_event(_unused void *data)
{
	struct dhcpcd_config *c;
	const char *str;

	c = read_config(listen_fd);
	if (c == NULL) {
		dhcpcd_close();
		add_timeout_sec(1, dhcpcd_init, NULL);
		return;
	}
	str = dhcpcd_get_value(c, "interface_order=");
	if (str == NULL ||
	    order == NULL ||
	    strcmp(str, order))
	{
		free(order);
		if (str == NULL)
			order = NULL;
		else
			order = strdup(str);
		sort_configs();
	}
	dhcpcd_dbus_configure(c);
	wpa_configure(c);
	update_status();
}

static void
free_configs(void)
{
	struct dhcpcd_config *c;

	while (dhcpcd_configs != NULL) {
		c = dhcpcd_configs->next;
		free(dhcpcd_configs);
		dhcpcd_configs = c;
	}
}

void
dhcpcd_init(_unused void *data)
{
	char cmd[128];
	ssize_t nifs, bytes;
	struct dhcpcd_config *c;
	static int last_errno;
	const char *ifo;

	if (command_fd != -1)
		return;
	command_fd = dhcpcd_open();
	if (command_fd == -1) {
		if (errno != last_errno) {
			last_errno = errno;
			syslog(LOG_ERR, "failed to connect to dhcpcd: %m");
		}
		update_status();
		add_timeout_sec(1, dhcpcd_init, NULL);
		return;
	}

	if (dhcpcd_command("--version", &dhcpcd_version) > 0) {
		syslog(LOG_INFO, "connected to dhcpcd-%s", dhcpcd_version);
	} else {
		syslog(LOG_ERR, "failed to get dhcpcd version");
		exit(EXIT_FAILURE);
	}

	listen_fd = dhcpcd_open();
	if (listen_fd == -1) {
		update_status();
		add_timeout_sec(1, dhcpcd_init, NULL);
		return;
	}
	_dhcpcd_command(listen_fd, "--listen", NULL);
	set_nonblock(listen_fd);

	free_configs();
	dhcpcd_command("--getinterfaces", NULL);
	bytes = read(command_fd, cmd, sizeof(ssize_t));
	if (bytes != sizeof(ssize_t))
		return;
	memcpy(&nifs, cmd, sizeof(ssize_t));
	for (;nifs > 0; nifs--) {
		c = read_config(command_fd);
		ifo = dhcpcd_get_value(c, "interface_order=");
		if (ifo != NULL) {
			free(order);
			order = strdup(ifo);
		}
		if (c == NULL)
			return;
		syslog(LOG_INFO, "retrieved interface %s (%s)",
		       c->iface, dhcpcd_get_value(c, "reason="));
	}

	sort_configs();
	update_status();
	for (c = dhcpcd_configs; c; c = c->next)
		wpa_configure(c);

	add_event(listen_fd, handle_event, NULL);

	return;
}

int
dhcpcd_close(void)
{
	int retval;

	retval = shutdown(command_fd, SHUT_RDWR);
	command_fd = -1;
	delete_event(listen_fd);
	retval |= shutdown(listen_fd, SHUT_RDWR);
	listen_fd = -1;
	free_configs();
	dhcpcd_status = "down";
	dhcpcd_dbus_signal_status(dhcpcd_status);
	return retval;
}
