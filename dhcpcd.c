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
static char *cffile;
int command_fd = -1;
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

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1 ||
	    fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
	{
		syslog(LOG_ERR, "fcntl: %m");
		return -1;
	}
	return 0;
}

static char *lbuf;
static size_t lbuf_len;

#ifdef DEBUG_MEMORY
static void
free_lbuf(void)
{
	free(lbuf);
}
#endif

/* Handy routine to read very long lines in text files.
 * This means we read the whole line and avoid any nasty buffer overflows.
 * We strip leading space and avoid comment lines, making the code that calls
 * us smaller.
 * As we don't use threads, this API is clean too. */
static char *
get_line(FILE * __restrict fp)
{
	char *p, *e, *nbuf;
	size_t last;
#ifdef DEBUG_MEMORY
	static int setup;
#endif

	if (feof(fp))
		return NULL;

#ifdef DEBUG_MEMORY
	if (setup == 0) {
		setup = 1;
		atexit(free_lbuf);
	}
#endif

	last = 0;
	do {
		if (lbuf == NULL || last != 0) {
			lbuf_len += BUFSIZ;
			nbuf = realloc(lbuf, lbuf_len);
			if (nbuf == NULL) {
				free(lbuf);
				lbuf = NULL;
				lbuf_len = 0;
				return NULL;
			}
			lbuf = nbuf;
		}
		p = lbuf + last;
		memset(p, 0, BUFSIZ);
		if (fgets(p, BUFSIZ, fp) == NULL)
			break;
		last += strlen(p);
		if (last != 0 && lbuf[last - 1] == '\n') {
			lbuf[last - 1] = '\0';
			break;
		}
	} while(!feof(fp));
	if (last == 0)
		return NULL;

	e = p + last - 1;
	for (p = lbuf; p < e; p++) {
		if (*p != ' ' && *p != '\t')
			break;
	}
	return p;
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
	if (*buffer == NULL)
		return -1;
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
	if (str == NULL || order == NULL || strcmp(str, order)) {
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
		free(dhcpcd_configs->data);
		free(dhcpcd_configs);
		dhcpcd_configs = c;
	}
}

void
free_option_values(struct option_value *o)
{
	struct option_value *p;

	while (o != NULL) {
		p = o->next;
		free(o->option);
		free(o->value);
		free(o);
		o = p;
	}
}

#define ACT_READ  (1 << 0)
#define ACT_WRITE (1 << 1)
#define ACT_LIST  (1 << 2)

static struct option_value *
_options(int action, const char *block, const char *name,
    const struct option_value *no, char ***list)
{
	FILE *fp;
	struct option_value *options, *o;
	const struct option_value *co;
	char *line, *option, *p;
	char **buf, **nbuf;
	int skip, free_opts;
	size_t len, buf_size, buf_len, i;

	fp = fopen(cffile, "r");
	if (fp == NULL)
		return NULL;
	options = o = NULL;
	skip = block && !(action & ACT_LIST) ? 1 : 0;
	buf = NULL;
	buf_len = buf_size = 0;
	free_opts = 1;
	while ((line = get_line(fp))) {
		option = strsep(&line, " \t");
		/* Trim trailing whitespace */
		if (line && *line) {
			p = line + strlen(line) - 1;
			while (p != line &&
			    (*p == ' ' || *p == '\t') &&
			    *(p - 1) != '\\')
				*p-- = '\0';
		}
		if (action & ACT_LIST) {
			if (strcmp(option, block) == 0)
				skip = 0;
			else
				skip = 1;
		} else {
			/* Start of a block, skip if not ours */
			if (strcmp(option, "interface") == 0 ||
			    strcmp(option, "ssid") == 0)
			{
				if (block && name && line &&
				    strcmp(option, block) == 0 &&
				    strcmp(line, name) == 0)
					skip = 0;
				else
					skip = 1;
				continue;
			}
		}
		if ((action & ACT_WRITE && skip) ||
		    (action & ACT_LIST && !skip))
		{
			if (buf_len + 2 > buf_size) {
				buf_size += 32;
				nbuf = realloc(buf, sizeof(char *) * buf_size);
				if (nbuf == NULL)
					goto exit;
				buf = nbuf;
			}
			if (action & ACT_WRITE && line && *line != '\0') {
				len = strlen(option) + strlen(line) + 2;
				buf[buf_len] = malloc(len);
				if (buf[buf_len] == NULL)
					goto exit;
				snprintf(buf[buf_len], len,
				    "%s %s", option, line);
			} else {
				if (action & ACT_LIST)
					buf[buf_len] = strdup(line);
				else
					buf[buf_len] = strdup(option);
				if (buf[buf_len] == NULL)
					goto exit;
			}
			buf_len++;
		}
		if (skip || action & ACT_LIST)
			continue;
		if (*option == '\0' || *option == '#' || *option == ';')
			continue;
		if (o == NULL)
			options = o = malloc(sizeof(*options));
		else {
			o->next = malloc(sizeof(*o));
			o = o->next;
		}
		if (o == NULL)
			goto exit;
		o->next = NULL;
		o->option = strdup(option);
		if (o->option == NULL) {
			o->value = NULL;
			goto exit;
		}
		if (line == NULL || *line == '\0')
			o->value = NULL;
		else {
			o->value = strdup(line);
			if (o->value == NULL)
				goto exit;
		}
	}

	if (action & ACT_WRITE) {
		fp = freopen(cffile, "w", fp);
		if (fp == NULL)
			goto exit;
		for (i = 0; i < buf_len; i++) {
			fputs(buf[i], fp);
			fputc('\n', fp);
		}
		if (no && block)
			fprintf(fp, "\n%s %s\n", block, name);
		for (co = no; co; co = co->next) {
			if (co->value)
				fprintf(fp, "%s %s\n", co->option, co->value);
			else
				fprintf(fp, "%s\n", co->option);
		}
	}

	free_opts = 0;

exit:
	if (fp != NULL)
		fclose(fp);
	if (action & ACT_LIST) {
		if (buf)
			buf[buf_len] = NULL;
		*list = buf;
	} else {
		for (i = 0; i < buf_len; i++)
			free(buf[i]);
		free(buf);
	}
	if (free_opts)
		free_option_values(options);
	return options;
}

struct option_value *
dhcpcd_read_options(const char *block, const char *name)
{
	return _options(ACT_READ, block, name, NULL, NULL);
}

int
dhcpcd_write_options(const char *block, const char *name,
    const struct option_value *opts)
{
	int serrno;

	serrno = errno;
	errno = 0;
	_options(ACT_WRITE, block, name, opts, NULL);
	if (errno)
		return -1;
	errno = serrno;
	return 0;
}

char **
dhcpcd_list_blocks(const char *block)
{
	char **list;

	list = NULL;
	_options(ACT_LIST, block, NULL, NULL, &list);
	return list;
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

	if (dhcpcd_command("--getconfigfile", &cffile) <= 0) {
		syslog(LOG_ERR, "failed to get dhcpcd config file");
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
	for (; nifs > 0; nifs--) {
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
	free(cffile);
	cffile = NULL;
#ifdef DEBUG_MEMORY
	free(dhcpcd_version);
	dhcpcd_version = NULL;
	free(order);
	order = NULL;
#endif
	dhcpcd_status = "down";
	dhcpcd_dbus_signal_status(dhcpcd_status);
	return retval;
}
