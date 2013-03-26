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
#define S_WPA		DHCPCD_SERVICE ".WPASupplicantError"

const char wpa_introspection_xml[] =
    "    <method name=\"Scan\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "    </method>\n"
    "    <method name=\"ScanResults\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "      <arg name=\"results\" direction=\"out\" type=\"a(a{sv})\"/>\n"
    "    </method>\n"
    "    <method name=\"ListNetworks\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "      <arg name=\"ids\" direction=\"out\" type=\"aa(isss)\"/>\n"
    "    </method>\n"
    "    <method name=\"AddNetwork\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "      <arg name=\"id\" direction=\"out\" type=\"i\"/>\n"
    "    </method>\n"
    "    <method name=\"RemoveNetwork\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "      <arg name=\"id\" direction=\"in\" type=\"i\"/>\n"
    "    </method>\n"
    "    <method name=\"EnableNetwork\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "      <arg name=\"id\" direction=\"in\" type=\"i\"/>\n"
    "    </method>\n"
    "    <method name=\"DisableNetwork\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "      <arg name=\"id\" direction=\"in\" type=\"i\"/>\n"
    "    </method>\n"
    "    <method name=\"SelectNetwork\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "      <arg name=\"id\" direction=\"in\" type=\"i\"/>\n"
    "    </method>\n"
    "    <method name=\"GetNetwork\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "      <arg name=\"id\" direction=\"in\" type=\"i\"/>\n"
    "      <arg name=\"parameter\" direction=\"in\" type=\"s\"/>\n"
    "      <arg name=\"value\" direction=\"out\" type=\"s\"/>\n"
    "    </method>\n"
    "    <method name=\"SetNetwork\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "      <arg name=\"id\" direction=\"in\" type=\"i\"/>\n"
    "      <arg name=\"parameter\" direction=\"in\" type=\"s\"/>\n"
    "      <arg name=\"value\" direction=\"in\" type=\"s\"/>\n"
    "    </method>\n"
    "    <method name=\"SaveConfig\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "    </method>\n"
    "    <method name=\"Disconnect\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "    </method>\n"
    "    <method name=\"Reassociate\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "    </method>\n"
    "    <signal name=\"ScanResults\">\n"
    "      <arg name=\"interface\" direction=\"out\" type=\"s\"/>\n"
    "    </signal>\n";

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

static int
attach_scan_results(const char *iface, DBusMessageIter *iter)
{
	DBusMessageIter array, dict;
	char buffer[2048], cmd[20], *p, *s;
	ssize_t bytes, i, l;
	const struct o_dbus *wpaop;
	int retval;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
	    DBUS_TYPE_ARRAY_AS_STRING
	    DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
	    DBUS_TYPE_STRING_AS_STRING
	    DBUS_TYPE_VARIANT_AS_STRING
	    DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
	    &array);
	retval = 0;
	for (i = 0; i < 1000; i++) {
		snprintf(cmd, sizeof(cmd), "BSS %zd", i);
		bytes = wpa_cmd(iface, cmd, buffer, sizeof(buffer));
		if (bytes == -1 ||
		    bytes == 0 ||
		    strncmp(buffer, "FAIL", 4) == 0)
			break;
		dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
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
					    wpaop, s + l);
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
	if (connection == NULL) {
		syslog(LOG_WARNING,
		    "no DBus connection to notify of status change");
		return;
	}
	msg = dbus_message_new_signal(DHCPCD_PATH, DHCPCD_SERVICE,
	    "ScanResults");
	if (msg == NULL) {
		syslog(LOG_ERR, "failed to make a scan results message");
		return;
	}
	dbus_message_iter_init_append(msg, &args);
	dbus_message_iter_append_basic(&args,
	    DBUS_TYPE_STRING, &iface);
	if (!dbus_connection_send(connection, msg, NULL))
		syslog(LOG_ERR, "failed to send status to dbus");
	dbus_message_unref(msg);
}

static DBusHandlerResult
scan_results(DBusConnection *con, DBusMessage *msg)
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

static DBusHandlerResult
list_networks(DBusConnection *con, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter args, array, item;
	DBusError err;
	char *s, buffer[2048], *t, *ssid, *bssid, *flags;
	int id;

	dbus_error_init(&err);
	if (!dbus_message_get_args(msg, &err,
		DBUS_TYPE_STRING, &s, DBUS_TYPE_INVALID))
		return return_dbus_error(con, msg, S_EINVAL,
		    "No interface specified");
	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &args);
	dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY,
	    DBUS_STRUCT_BEGIN_CHAR_AS_STRING
	    DBUS_TYPE_INT32_AS_STRING
	    DBUS_TYPE_STRING_AS_STRING
	    DBUS_TYPE_STRING_AS_STRING
	    DBUS_TYPE_STRING_AS_STRING
	    DBUS_STRUCT_END_CHAR_AS_STRING,
	    &array);
	wpa_cmd(s, "LIST_NETWORKS", buffer, sizeof(buffer));
	s = strchr(buffer, '\n');
	if (s != NULL) {
		while ((t = strsep(&s, "\n")) != NULL) {
			if (*t == '\0')
				continue;
			ssid = strchr(t, '\t');
			if (ssid == NULL)
				break;
			*ssid++ = '\0';
			bssid = strchr(ssid, '\t');
			if (bssid == NULL)
				break;
			*bssid++ = '\0';
			flags = strchr(bssid, '\t');
			if (flags == NULL)
				break;
			*flags++ = '\0';
			id = strtoul(t, NULL, 0);
			dbus_message_iter_open_container(&array,
			    DBUS_TYPE_STRUCT, NULL, &item);
			dbus_message_iter_append_basic(&item,
			    DBUS_TYPE_INT32, &id);
			dbus_message_iter_append_basic(&item,
			    DBUS_TYPE_STRING, &ssid);
			dbus_message_iter_append_basic(&item,
			    DBUS_TYPE_STRING, &bssid);
			dbus_message_iter_append_basic(&item,
			    DBUS_TYPE_STRING, &flags);
			dbus_message_iter_close_container(&array, &item);
		}
	}
	dbus_message_iter_close_container(&args, &array);

	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
add_network(DBusConnection *con, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter args;
	DBusError err;
	char *s, buffer[2048];
	ssize_t bytes;
	int id;

	dbus_error_init(&err);
	if (!dbus_message_get_args(msg, &err,
		DBUS_TYPE_STRING, &s, DBUS_TYPE_INVALID))
		return return_dbus_error(con, msg, S_EINVAL,
		    "No interface specified");

	bytes = wpa_cmd(s, "ADD_NETWORK", buffer, sizeof(buffer));
	if (bytes == -1 || bytes == 0)
		return return_dbus_error(con, msg, S_WPA,
		    "Failed to add a new network");
	reply = dbus_message_new_method_return(msg);
	id = strtol(buffer, NULL, 0);
	dbus_message_iter_init_append(reply, &args);
	dbus_message_iter_append_basic(&args, DBUS_TYPE_INT32, &id);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
_cmd(DBusConnection *con, DBusMessage *msg, const char *c, const char *e)
{
	DBusMessage *reply;
	DBusError err;
	char *s, buffer[2048];
	ssize_t bytes;

	dbus_error_init(&err);
	if (!dbus_message_get_args(msg, &err,
		DBUS_TYPE_STRING, &s, 
		DBUS_TYPE_INVALID))
		return return_dbus_error(con, msg, S_EINVAL,
		    "No interface specified");

	bytes = wpa_cmd(s, c, buffer, sizeof(buffer));
	if (bytes == -1 || strcmp(buffer, "OK\n") != 0)
		return return_dbus_error(con, msg, S_WPA, "%s", e);
	reply = dbus_message_new_method_return(msg);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
_network(DBusConnection *con, DBusMessage *msg, const char *c, const char *e)
{
	DBusMessage *reply;
	DBusError err;
	char cmd[32], *s, buffer[2048];
	ssize_t bytes;
	int id;

	dbus_error_init(&err);
	if (!dbus_message_get_args(msg, &err,
		DBUS_TYPE_STRING, &s, 
		DBUS_TYPE_INT32, &id,
		DBUS_TYPE_INVALID))
		return return_dbus_error(con, msg, S_EINVAL,
		    "No interface or id specified");

	snprintf(cmd, sizeof(cmd), "%s %d", c, id);
	bytes = wpa_cmd(s, cmd, buffer, sizeof(buffer));
	if (bytes == -1 || strcmp(buffer, "OK\n") != 0)
		return return_dbus_error(con, msg, S_WPA, "%s", e);
	reply = dbus_message_new_method_return(msg);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
scan(DBusConnection *con, DBusMessage *msg)
{
	return _cmd(con, msg,
	    "SCAN", "Failed to save configuration");
}

static DBusHandlerResult
remove_network(DBusConnection *con, DBusMessage *msg)
{
	return _network(con, msg,
	    "REMOVE_NETWORK", "Failed to remove the network");
}

static DBusHandlerResult
enable_network(DBusConnection *con, DBusMessage *msg)
{
	return _network(con, msg,
	    "ENABLE_NETWORK", "Failed to enable the network");
}

static DBusHandlerResult
disable_network(DBusConnection *con, DBusMessage *msg)
{
	return _network(con, msg,
	    "DISABLE_NETWORK", "Failed to disable the network");
}

static DBusHandlerResult
select_network(DBusConnection *con, DBusMessage *msg)
{
	return _network(con, msg,
	    "SELECT_NETWORK", "Failed to select the network");
}

static DBusHandlerResult
save_config(DBusConnection *con, DBusMessage *msg)
{
	return _cmd(con, msg,
	    "SAVE_CONFIG", "Failed to save configuration");
}

static DBusHandlerResult
reassociate(DBusConnection *con, DBusMessage *msg)
{
	return _cmd(con, msg,
	    "REASSOCIATE", "Failed to reassociate");
}

static DBusHandlerResult
disconnect(DBusConnection *con, DBusMessage *msg)
{
	return _cmd(con, msg,
	    "DISCONNECT",
	    "Failed to disconnect");
}

static DBusHandlerResult
get_network(DBusConnection *con, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter args;
	DBusError err;
	char cmd[256], *s, *param, buffer[2048];
	ssize_t bytes;
	int id;

	dbus_error_init(&err);
	if (!dbus_message_get_args(msg, &err,
		DBUS_TYPE_STRING, &s, 
		DBUS_TYPE_INT32, &id,
		DBUS_TYPE_STRING, &param,
		DBUS_TYPE_INVALID))
		return return_dbus_error(con, msg, S_EINVAL,
		    "No interface, id or parameter"
		    " specified");

	snprintf(cmd, sizeof(cmd), "GET_NETWORK %d %s", id, param);
	bytes = wpa_cmd(s, cmd, buffer, sizeof(buffer));
	if (bytes == -1 || bytes == 0 || strcmp(buffer, "FAIL\n") == 0)
		return return_dbus_error(con, msg, S_WPA,
		    "Failed to get network parameter");
	reply = dbus_message_new_method_return(msg);
	s = buffer;
	dbus_message_iter_init_append(reply, &args);
	dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &s);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
set_network(DBusConnection *con, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusError err;
	char cmd[256], *s, *param, *value, buffer[2048];
	ssize_t bytes;
	int id;

	dbus_error_init(&err);
	if (!dbus_message_get_args(msg, &err,
		DBUS_TYPE_STRING, &s, 
		DBUS_TYPE_INT32, &id,
		DBUS_TYPE_STRING, &param,
		DBUS_TYPE_STRING, &value,
		DBUS_TYPE_INVALID))
		return return_dbus_error(con, msg, S_EINVAL,
		    "No interface, id, parameter or"
		    " value specified");

	snprintf(cmd, sizeof(cmd), "SET_NETWORK %d %s %s", id, param, value);
	bytes = wpa_cmd(s, cmd, buffer, sizeof(buffer));
	if (bytes == -1 || strcmp(buffer, "OK\n") != 0)
		return return_dbus_error(con, msg, S_WPA,
		    "Failed to set network parameter");
	reply = dbus_message_new_method_return(msg);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult
wpa_dbus_handler(DBusConnection *con, DBusMessage *msg)
{
	if (dbus_message_is_method_call(msg, DHCPCD_SERVICE, "Scan"))
		return scan(con, msg);
	if (dbus_message_is_method_call(msg, DHCPCD_SERVICE, "ScanResults"))
		return scan_results(con, msg);
	if (dbus_message_is_method_call(msg, DHCPCD_SERVICE, "ListNetworks"))
		return list_networks(con, msg);
	if (dbus_message_is_method_call(msg, DHCPCD_SERVICE, "AddNetwork"))
		return add_network(con, msg);
	if (dbus_message_is_method_call(msg, DHCPCD_SERVICE, "RemoveNetwork"))
		return remove_network(con, msg);
	if (dbus_message_is_method_call(msg, DHCPCD_SERVICE, "EnableNetwork"))
		return enable_network(con, msg);
	if (dbus_message_is_method_call(msg, DHCPCD_SERVICE, "DisableNetwork"))
		return disable_network(con, msg);
	if (dbus_message_is_method_call(msg, DHCPCD_SERVICE, "SelectNetwork"))
		return select_network(con, msg);
	if (dbus_message_is_method_call(msg, DHCPCD_SERVICE, "GetNetwork"))
		return get_network(con, msg);
	if (dbus_message_is_method_call(msg, DHCPCD_SERVICE, "SetNetwork"))
		return set_network(con, msg);
	if (dbus_message_is_method_call(msg, DHCPCD_SERVICE, "SaveConfig"))
		return save_config(con, msg);
	if (dbus_message_is_method_call(msg, DHCPCD_SERVICE, "Disconnect"))
		return disconnect(con, msg);
	if (dbus_message_is_method_call(msg, DHCPCD_SERVICE, "Reassociate"))
		return reassociate(con, msg);
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
