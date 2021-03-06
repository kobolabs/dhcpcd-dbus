/*
 * dhcpcd-dbus
 * Copyright 2008-2012 Roy Marples <roy@marples.name>
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

#ifndef DEFS_H
#define DEFS_H

#define PACKAGE			"dhcpcd-dbus"
#define VERSION			"0.6.0"

#include "config.h"

#define DHCPCD_SERVICE "name.marples.roy.dhcpcd"
#define DHCPCD_PATH    "/name/marples/roy/dhcpcd"

#define DHCPCD_SOCKET  RUNDIR "/dhcpcd.sock"

#define WPA_CTRL_DIR   RUNDIR "/wpa_supplicant"

#define UNCONST(a)	((void *)(unsigned long)(const void *)(a))

#if defined(__GNUC__)
# define _printf(a, b)  __attribute__((__format__(__printf__, a, b)))
# define _unused __attribute__((__unused__))
#else
# define _printf(a, b)
# define _unused
#endif

#endif
