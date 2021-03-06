/*
 * dhcpcd-dbus
 * Copyright 2009-2012 Roy Marples <roy@marples.name>
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

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "config.h"
#include "dhcpcd-dbus.h"
#include "eloop.h"
#include "wpa.h"
#include "wpa-dbus.h"

struct if_sock {
	char *iface;
	int cmd_fd;
	char *cmd_path;
	int ctrl_fd;
	char *ctrl_path;
	int attached;
	struct if_sock *next;
};
static struct if_sock *socks;

static void wpa_init(void *arg);

static int
_wpa_open(const char *iface, char **path)
{
	static int counter;
	int fd, len;
	struct sockaddr_un sun;

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
		return -1;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof(sun.sun_path),
	    "/tmp/" PACKAGE "-wpa-%d.%d", getpid(), counter++);
	*path = strdup(sun.sun_path);
	len = sizeof(sun.sun_family) + strlen(sun.sun_path) + 1;
	if (bind(fd, (struct sockaddr *)&sun, len) == -1) {
		close(fd);
		unlink(*path);
		free(*path);
		*path = NULL;
		return -1;
	}
	snprintf(sun.sun_path, sizeof(sun.sun_path),
	    WPA_CTRL_DIR "/%s", iface);
	len = sizeof(sun.sun_family) + strlen(sun.sun_path) + 1;
	if (connect(fd, (struct sockaddr *)&sun, len) == 0) {
		set_nonblock(fd);
		return fd;
	}
	close(fd);
	unlink(*path);
	free(*path);
	*path = NULL;
	return -1;
}

static struct if_sock *
find_if_sock(const char *iface)
{
	struct if_sock *ifs;

	for (ifs = socks; ifs; ifs = ifs->next) {
		if (strcmp(ifs->iface, iface) == 0)
			return ifs;
	}
	return NULL;
}

static ssize_t
_wpa_cmd(int fd, const char *cmd, char *buffer, ssize_t len)
{
	int retval;
	ssize_t bytes;
	struct pollfd pfd;

	if (buffer)
		*buffer = '\0';
	bytes = write(fd, cmd, strlen(cmd));
	if (bytes == -1 || bytes == 0)
		return -1;
	if (buffer == NULL || len == 0)
		return 0;
	pfd.fd = fd;
	pfd.events = POLLIN | POLLHUP;
	pfd.revents = 0;
	retval = poll(&pfd, 1, 2000);
	if (retval == -1) {
		syslog(LOG_ERR, "poll: %m");
		return -1;
	}
	if (retval == 0 || !(pfd.revents & (POLLIN | POLLHUP)))
		return -1;

	bytes = read(fd, buffer, len == 1 ? 1 : len - 1);
	if (bytes != -1)
		buffer[bytes] = '\0';
	return bytes;
}

ssize_t
wpa_cmd(const char *iface, const char *cmd, char *buffer, ssize_t len)
{
	struct if_sock *ifs;

	ifs = find_if_sock(iface);
	if (ifs == NULL)
		return -1;
	return _wpa_cmd(ifs->cmd_fd, cmd, buffer, len);
}

static int
attach_detach(struct if_sock *ifs, int attach)
{
	char buffer[10];

	if (ifs->attached == attach)
		return 0;
	if (attach > 0) {
		if (_wpa_cmd(ifs->ctrl_fd, "ATTACH", buffer, sizeof(buffer)) == -1)
			return -1;
		if (strcmp(buffer, "OK\n") != 0)
			return -1;
	} else {
		if (_wpa_cmd(ifs->ctrl_fd, "DETACH", NULL, 0) == -1)
			return -1;
	}
	ifs->attached = attach;
	return 0;
}

static struct if_sock *
wpa_open(const char *iface)
{
	struct if_sock *ifs = NULL;
	int cmd_fd = -1, ctrl_fd = -1;
	char *cmd_path = NULL, *ctrl_path = NULL;

	cmd_fd = _wpa_open(iface, &cmd_path);
	if (cmd_fd == -1)
		goto fail;
	ctrl_fd = _wpa_open(iface, &ctrl_path);
	if (ctrl_fd == -1)
		goto fail;
	ifs = malloc(sizeof(*ifs));
	if (ifs == NULL)
		goto fail;
	ifs->iface = strdup(iface);
	if (ifs->iface == NULL)
		goto fail;
	ifs->cmd_fd = cmd_fd;
	ifs->cmd_path = cmd_path;
	ifs->ctrl_fd = ctrl_fd;
	ifs->ctrl_path = ctrl_path;
	ifs->next = socks;
	ifs->attached = 0;
	socks = ifs;
	return ifs;

fail:
	if (cmd_fd != -1)
		close(cmd_fd);
	if (ctrl_fd != -1)
		close(ctrl_fd);
	free(cmd_path);
	free(ctrl_path);
	free(ifs);
	return NULL;
}

int
wpa_close(const char *iface)
{
	struct if_sock *ifs, *ifn, *ifl;
	int retval;

	ifl = NULL;
	retval = 0;
	for (ifs = socks; ifs && (ifn = ifs->next, 1); ifs = ifn) {
		if (iface == NULL || strcmp(ifs->iface, iface) == 0) {
			attach_detach(ifs, -1);
			delete_event(ifs->ctrl_fd);
			delete_timeout(NULL, ifs);
			retval |= shutdown(ifs->ctrl_fd, SHUT_RDWR);
			retval |= shutdown(ifs->cmd_fd, SHUT_RDWR);
			free(ifs->iface);
			unlink(ifs->cmd_path);
			free(ifs->cmd_path);
			unlink(ifs->ctrl_path);
			free(ifs->ctrl_path);
			if (ifl == NULL)
				socks = ifs->next;
			else
				ifl->next = ifs->next;
			free(ifs);
			if (iface != NULL)
				break;
		}
	}
	return retval;
}

static int
read_event(const struct if_sock *ifs)
{
	char buffer[256], *p;
	ssize_t bytes;

	bytes = read(ifs->ctrl_fd, buffer, sizeof(buffer));
	if (bytes == -1 || bytes == 0)
		return -1;
	buffer[bytes] = '\0';
	bytes = strlen(buffer);
	if (buffer[bytes - 1] == ' ')
		buffer[--bytes] = '\0';
	for (p = buffer + 1; *p != '\0'; p++)
		if (*p == '>') {
			p++;
			break;
		}
	if (strcmp(p, "CTRL-EVENT-SCAN-RESULTS") == 0)
		wpa_dbus_signal_scan_results(ifs->iface);
	else if ((strncmp(p, "CTRL-EVENT-DISCONNECTED", 23) == 0) ||
		(strncmp(p, "CTRL-EVENT-ASSOC-REJECT", 23) == 0) ||
		(strncmp(p, "CTRL-EVENT-AUTH-REJECT", 22) == 0) ||
		(strncmp(p, "CTRL-EVENT-SCAN-FAILED", 22) == 0))
		wpa_dbus_signal_wpa_fail_event(p);
	return bytes;
}

static void
handle_wpa(void *ifs)
{
	read_event((const struct if_sock *)ifs);
}

static void
ping(void *arg)
{
	char buffer[20];
	struct if_sock *ifs;
	struct dhcpcd_config *c;

	ifs = (struct if_sock *)arg;
	if (_wpa_cmd(ifs->cmd_fd, "PING", buffer, sizeof(buffer)) > 0 &&
	    strncmp(buffer, "PONG\n", 5) == 0) {
		wpa_dbus_signal_status();
		add_timeout_sec(1, ping, ifs);
		return;
	}

	syslog(LOG_ERR, "lost connection to wpa_supplicant on interface %s",
	    ifs->iface);
	c = dhcpcd_get_config(ifs->iface, "ipv4");
	wpa_close(c->iface);
	add_timeout_sec(1, wpa_init, (void *)UNCONST(c->iface));
}

static void
bss_current()
{
	wpa_dbus_signal_signal_strength();
	add_timeout_sec(30, bss_current, NULL);
}

static void
wpa_init(void *arg)
{
	const char *iface;
	struct if_sock *ifs;

	iface = (const char *)arg;
	ifs = wpa_open(iface);
	if (ifs == NULL) {
		add_timeout_sec(1, wpa_init, arg);
		return;
	}
	if (attach_detach(ifs, 1) != 0) {
		wpa_close(iface);
		add_timeout_sec(1, wpa_init, arg);
		return;
	}

	add_event(ifs->ctrl_fd, handle_wpa, ifs);
	add_timeout_sec(1, ping, ifs);
	add_timeout_sec(2, bss_current, NULL);
	syslog(LOG_INFO, "connected to wpa_supplicant on interface %s", iface);
	wpa_dbus_signal_scan_results(iface);
}

int
wpa_configure(const struct dhcpcd_config *c)
{
	const char *p;

	p = dhcpcd_get_value(c, "reason=");
	if (p == NULL)
		return 0;
	if (strcmp(p, "STOP") == 0 ||
	    strcmp(p, "RELEASE") == 0)
		return wpa_close(c->iface);

	if (find_if_sock(c->iface) == NULL)
		wpa_init((void *)UNCONST(c->iface));
	if (find_if_sock(c->iface) == NULL)
		return 0;
	return -1;
}
