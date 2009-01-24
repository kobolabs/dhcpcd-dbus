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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "config.h"
#include "wpa.h"

struct if_sock {
	char *iface;
	int fd;
	char *sock;
	struct if_sock *next;
};
static struct if_sock *socks;

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
	snprintf(sun.sun_path, sizeof(sun.sun_path), WPA_CTRL_DIR "/%s", iface);
	len = sizeof(sun.sun_family) + strlen(sun.sun_path) + 1;
	if (connect(fd, (struct sockaddr *)&sun, len) == 0)
		return fd;
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

int
wpa_open(const char *iface)
{
	struct if_sock *ifs;
	int fd;
	char *path;

	if (find_if_sock(iface) != NULL)
		return 0;
	fd = _wpa_open(iface, &path);
	if (fd == -1)
		return -1;
	ifs = malloc(sizeof(*ifs));
	if (ifs == NULL) {
		close(fd);
		return -1;
	}
	ifs->iface = strdup(iface);
	if (ifs->iface == NULL) {
		close(fd);
		free(ifs);
		return -1;
	}
	ifs->fd = fd;
	ifs->sock = path;
	ifs->next = socks;
	socks = ifs;
	return 0;
}

ssize_t wpa_cmd(const char *iface, const char *cmd, char *buffer, ssize_t len)
{
	struct if_sock *ifs;
	ssize_t bytes;

	ifs = find_if_sock(iface);
	if (ifs == NULL)
		return -1;
	write(ifs->fd, cmd, strlen(cmd));
	if (buffer == NULL || len == 0)
		return 0;
	bytes = read(ifs->fd, buffer, len);
	if (bytes != -1)
		buffer[bytes] = '\0';
	return bytes;
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
			retval |= shutdown(ifs->fd, SHUT_RDWR);
			free(ifs->iface);
			unlink(ifs->sock);
			free(ifs->sock);
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
