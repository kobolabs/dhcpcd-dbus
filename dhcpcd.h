/* 
 * dhcpcd-dbus
 * Copyright 2009-2012 Roy Marples <roy@marples.name>
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

extern char *dhcpcd_version;
extern const char *dhcpcd_status;

struct option_value {
	char *option;
	char *value;
	struct option_value *next;
};

struct dhcpcd_config {
	const char *iface;
	const char *type;
	char *data;
	size_t data_len;
	char* wpa_state;
	struct dhcpcd_config *prev;
	struct dhcpcd_config *next;
};
extern struct dhcpcd_config *dhcpcd_configs;

int set_nonblock(int);
void dhcpcd_init(void *);
int dhcpcd_close(void);
struct dhcpcd_config *dhcpcd_get_config(const char *, const char *);
const char *dhcpcd_get_value(const struct dhcpcd_config *, const char *);
ssize_t dhcpcd_command(const char *, char **);
void free_option_value(struct option_value *);
void free_option_values(struct option_value *);
struct option_value *dhcpcd_read_options(const char *, const char *);
int dhcpcd_write_options(const char *, const char *,
    const struct option_value *);
char **dhcpcd_list_blocks(const char *);

#endif
