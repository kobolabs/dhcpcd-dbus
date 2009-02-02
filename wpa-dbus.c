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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <dbus/dbus.h>

#include "config.h"
#include "dbus-dict.h"
#include "dhcpcd-dbus.h"
#include "dhcpcd.h"
#include "wpa.h"
#include "wpa-dbus.h"

#define S_EINVAL	DHCPCD_SERVICE ".InvalidArgument"

static const struct o_dbus const wpaos[] = {
	{ "bssid=", DBUS_TYPE_STRING, 0, "BSSID" },
	{ "freq=", DBUS_TYPE_INT32, 0, "Frequency" },
	{ "beacon_int=", DBUS_TYPE_INT32, 0, "BeaconInterval" },
	{ "capabilities=", DBUS_TYPE_UINT16, 0, "Capabilities" },
	{ "qual=", DBUS_TYPE_INT32, 0, "Quality" },
	{ "noise=", DBUS_TYPE_INT32, 0, "Noise" },
	{ "level=", DBUS_TYPE_INT32, 0, "Level" },
	{ "tsf=", DBUS_TYPE_STRING, 0, "TSF" },
	{ "ie=", DBUS_TYPE_STRING, 0, "IE" },
	{ "flags=", DBUS_TYPE_STRING, 0, "Flags" },
	{ "ssid=", DBUS_TYPE_STRING, 0, "SSID" },
	{ NULL, 0, 0, NULL}
};

static DBusHandlerResult
start_scan(DBusConnection *con, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusError err;
	char *s;

	dbus_error_init(&err);
	if (!dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, &s, DBUS_TYPE_INVALID))
		return return_dbus_error(con, msg, S_EINVAL,
					 "No interface specified");
	wpa_cmd(s, "SCAN", NULL, 0);
	reply = dbus_message_new_method_return(msg);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static int
attach_scan_results(const char *iface, DBusMessageIter *iter)
{
	DBusMessageIter array, dict;
	char buffer[2048], cmd[20], *p, *s;
	ssize_t bytes, i, l;
	const struct o_dbus *wpaop;
	int retval;

	dbus_message_iter_open_container(iter,
					 DBUS_TYPE_ARRAY,
					 DBUS_TYPE_ARRAY_AS_STRING
					 DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					 DBUS_TYPE_STRING_AS_STRING
					 DBUS_TYPE_VARIANT_AS_STRING
					 DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					 &array);
	for (i = 0; i < 1000; i++) {
		snprintf(cmd, sizeof(cmd), "BSS %d", i);
		bytes = wpa_cmd(iface, cmd, buffer, sizeof(buffer));
		if (bytes == -1 || bytes == 0 || strncmp(buffer, "FAIL", 4) == 0)
			break;
		dbus_message_iter_open_container(&array,
						 DBUS_TYPE_ARRAY,
						 DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
						 DBUS_TYPE_STRING_AS_STRING
						 DBUS_TYPE_VARIANT_AS_STRING
						 DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
						 &dict);
		p = buffer;
		while ((s = strsep(&p, "\n")) != NULL) {
			if (*s == '\0')
				continue;
			for (wpaop = wpaos; wpaop->var; wpaop++) {
				l = strlen(wpaop->var);
				if (strncmp(s, wpaop->var, l) == 0) {
					retval = dict_append_config_item(&dict,
									 wpaop,
									 s + l);
					break;
				}
			}
			if (retval == -1)
				break;
		}
		dbus_message_iter_close_container(&array, &dict);
	}

	dbus_message_iter_close_container(iter, &array);
	return i;
}

void
wpa_dbus_signal_scan_results(const char *iface)
{
	DBusMessage *msg;
	DBusMessageIter args;

	syslog(LOG_INFO, "scan results on interface %s", iface);
	msg = dbus_message_new_signal(DHCPCD_PATH, DHCPCD_SERVICE,
				      "ScanResults");
	if (msg == NULL) {
		syslog(LOG_ERR, "failed to make a scan results message");
		return;
	}
	dbus_message_iter_init_append(msg, &args);
	dbus_message_iter_append_basic(&args,
				       DBUS_TYPE_STRING,
				       &iface);
	if (!dbus_connection_send(connection, msg, NULL))
		syslog(LOG_ERR, "failed to send status to dbus");
	dbus_message_unref(msg);
}

static DBusHandlerResult
get_scan_results(DBusConnection *con, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter args;
	DBusError err;
	char *s;

	dbus_error_init(&err);
	if (!dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, &s, DBUS_TYPE_INVALID))
		return return_dbus_error(con, msg, S_EINVAL,
					 "No interface specified");

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &args);
	attach_scan_results(s, &args);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult
wpa_dbus_handler(DBusConnection *con, DBusMessage *msg)
{
	if (dbus_message_is_method_call(msg,
					     DHCPCD_SERVICE,
					     "StartScan"))
		return start_scan(con, msg);
	else if (dbus_message_is_method_call(msg,
					     DHCPCD_SERVICE,
					     "GetScanResults"))
		return get_scan_results(con, msg);
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
