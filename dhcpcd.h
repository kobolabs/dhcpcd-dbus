/* 
 * dhcpcd-dbus
 * Copyright 2009 Roy Marples <roy@marples.name>
 * All rights reserved

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

#ifndef DHCPCD_H
#define DHCPCD_H

#include <poll.h>

extern char *dhcpcd_version;
extern const char *dhcpcd_status;

struct dhcpcd_config {
	const char *iface;
	char *data;
	size_t data_len;
	struct dhcpcd_config *next;
	struct dhcpcd_config *prev;
};
extern struct dhcpcd_config *dhcpcd_configs;

int set_nonblock(int);
void dhcpcd_init(void *);
int dhcpcd_close(void);
struct dhcpcd_config *dhcpcd_get_config(const char *iface);
const char *dhcpcd_get_value(const struct dhcpcd_config *, const char *);
ssize_t dhcpcd_command(const char *, char **);
size_t dhcpcd_add_listeners(struct pollfd *);
void dhcpcd_check_listeners(struct pollfd *, size_t);

#endif
