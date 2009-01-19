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

#include <arpa/inet.h>

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <dbus/dbus.h>

#include "config.h"
#include "dhcpcd-dbus.h"
#include "dhcpcd.h"

#define S_EINVAL	DHCPCD_SERVICE ".InvalidArgument"

#if defined(__GNUC__)
# define _printf(a, b)  __attribute__((__format__(__printf__, a, b)))
# define _unused __attribute__((__unused__))
#else
# define _printf(a, b)
# define _unused
#endif

static DBusConnection *connection;
struct watch {
	DBusWatch *watch;
	struct watch *next;
};
static struct watch *watches;

static const char *introspection_xml =
	"<!DOCTYPE node PUBLIC \"-//freedesktop//"
	"DTD D-BUS Object Introspection 1.0//EN\"\n"
	"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\";>\n"
	"<node name=\"" DHCPCD_PATH "\">\n"
	"  <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
	"    <method name=\"Introspect\">\n"
	"      <arg name=\"data\" direction=\"out\" type=\"s\"/>\n"
	"    </method>\n"
	"  </interface>\n"
	"  <interface name=\"" DHCPCD_SERVICE "\">\n"
	"    <method name=\"GetVersion\">\n"
	"      <arg name=\"version\" direction=\"out\" type=\"s\"/>\n"
	"    </method>\n"
	"    <method name=\"GetDhcpcdVersion\">\n"
	"      <arg name=\"version\" direction=\"out\" type=\"s\"/>\n"
	"    </method>\n"
	"    <method name=\"GetInterface\">\n"
	"      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
	"      <arg name=\"interfaces\" direction=\"out\" type=\"av\"/>\n"
	"    </method>\n"
	"    <method name=\"GetStatus\">\n"
	"      <arg name=\"Status\" direction=\"out\" type=\"s\"/>\n"
	"    </method>\n"
	"    <method name=\"Rebind\">\n"
	"      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
	"    </method>\n"
	"    <method name=\"Release\">\n"
	"      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
	"    </method>\n"
	"    <method name=\"Stop\">\n"
	"      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
	"    </method>\n"
	"    <signal name=\"Event\">\n"
	"      <arg name=\"configuration\" type=\"a\">\n"
	"    </signal>\n"
	"    <signal name=\"StatusChanged\">\n"
	"      <arg name=\"status\" type=\"s\">\n"
	"    </signal>\n"
	"  </interface>\n"
	"</node>\n";

struct dho_dbus {
	const char *var;
	int type;
	int sub_type;
	const char *name;
};

static const struct dho_dbus const dhos[] = {
	{ "interface=", DBUS_TYPE_STRING, 0, "Interface" },
	{ "reason=", DBUS_TYPE_STRING, 0, "Reason" },
	{ "interface_order=", DBUS_TYPE_STRING, 0, "InterfaceOrder" },
	{ "metric=", DBUS_TYPE_UINT16, 0, "Metric" },
	{ "ip_address=", DBUS_TYPE_UINT32, 0, "IPAddress" },
	{ "server_name=", DBUS_TYPE_STRING, 0, "ServerName"},
	{ "subnet_mask=", DBUS_TYPE_UINT32, 0, "SubnetMask" },
	{ "subnet_cidr=", DBUS_TYPE_BYTE, 0, "SubnetCIDR" },
	{ "network_number=", DBUS_TYPE_UINT32, 0, "NetworkNumber" },
	{ "classless_static_routes=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "ClasslessStaticRoutes" },
	{ "ms_classless_static_routes=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "MSClasslessStaticRoutes" },
	{ "static_routes=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "StaticRoutes"} ,
	{ "routers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "Routers" },
	{ "time_offset=", DBUS_TYPE_UINT32, 0, "TimeOffset" },
	{ "time_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "TimeServers" },
	{ "ien116_name_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "IEN116NameServers" },
	{ "domain_name_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "DomainNameServers" },
	{ "log_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "LogServers" },
	{ "cookie_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "CookieServers" },
	{ "lpr_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "LPRServers" },
	{ "impress_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "ImpressServers" },
	{ "resource_location_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "ResourceLocationServers" },
	{ "host_name=", DBUS_TYPE_STRING, 0, "Hostname" },
	{ "boot_size=", DBUS_TYPE_UINT16, 0, "BootSize" },
	{ "merit_dump=", DBUS_TYPE_STRING, 0, "MeritDump" },
	{ "domain_name=", DBUS_TYPE_STRING, 0, "DomainName" },
	{ "swap_server=", DBUS_TYPE_UINT32, 0, "SwapServer" },
	{ "root_path=", DBUS_TYPE_STRING, 0, "RootPath" },
	{ "extensions_path=", DBUS_TYPE_STRING, 0, "ExtensionsPath" },
	{ "ip_forwarding=", DBUS_TYPE_BOOLEAN, 0, "IPForwarding" },
	{ "non_local_source_routing=", DBUS_TYPE_BOOLEAN, 0, "NonLocalSourceRouting" },
	{ "policy_filter=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "PolicyFilter" },
	{ "max_dgram_reassembly=", DBUS_TYPE_INT16, 0, "MaxDatagramReassembly" },
	{ "default_ip_ttl=", DBUS_TYPE_UINT16, 0, "DefaultIPTTL" },
	{ "path_mtu_aging_timeout=", DBUS_TYPE_UINT32, 0, "PathMTUAgingTimeout" },
	{ "path_mtu_plateau_table=" ,DBUS_TYPE_ARRAY, DBUS_TYPE_UINT16, "PolicyFilter"} ,
	{ "interface_mtu=", DBUS_TYPE_UINT16, 0, "InterfaceMTU" },
	{ "all_subnets_local=", DBUS_TYPE_BOOLEAN, 0, "AllSubnetsLocal" },
	{ "broadcast_address=", DBUS_TYPE_UINT32, 0, "BroadcastAddress" },
	{ "perform_mask_discovery=", DBUS_TYPE_BOOLEAN, 0, "PerformMaskDiscovery" },
	{ "mask_supplier=", DBUS_TYPE_BOOLEAN, 0, "MaskSupplier" },
	{ "router_discovery=", DBUS_TYPE_BOOLEAN, 0, "RouterDiscovery" },
	{ "router_solicitiation_address=", DBUS_TYPE_UINT32, 0, "RouterSolicationAddress" },
	{ "trailer_encapsulation=", DBUS_TYPE_BOOLEAN, 0, "TrailerEncapsulation" },
	{ "arp_cache_timeout=", DBUS_TYPE_UINT32, 0, "ARPCacheTimeout" },
	{ "ieee802_3_encapsulation=", DBUS_TYPE_UINT16, 0, "IEEE8023Encapsulation" },
	{ "default_tcp_ttl=", DBUS_TYPE_BYTE, 0, "DefaultTCPTTL" },
	{ "tcp_keepalive_interval=", DBUS_TYPE_UINT32, 0, "TCPKeepAliveInterval" },
	{ "tcp_keepalive_garbage=", DBUS_TYPE_BOOLEAN, 0, "TCPKeepAliveGarbage" },
	{ "nis_domain=", DBUS_TYPE_STRING, 0, "NISDomain" },
	{ "nis_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "NISServers" },
	{ "ntp_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "NTPServers" },
	{ "vendor_encapsulated_optons=", DBUS_TYPE_STRING, 0, "VendorEncapsulatedOptions" },
	{ "netbios_name_servers=" ,DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "NetBIOSNameServers" },
	{ "netbios_dd_server=", DBUS_TYPE_UINT32, 0, "NetBIOSDDServer" },
	{ "netbios_node_type=", DBUS_TYPE_BYTE, 0, "NetBIOSNodeType" },
	{ "netbios_scope=", DBUS_TYPE_STRING, 0, "NetBIOSScope" },
	{ "font_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "FontServers" },
	{ "x_display_manager=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "XDisplayManager" },
	{ "dhcp_requested_address=", DBUS_TYPE_UINT32, 0, "DHCPRequestedAddress" },
	{ "dhcp_lease_time=", DBUS_TYPE_UINT32, 0, "DHCPLeaseTime" },
	{ "dhcp_option_overload=", DBUS_TYPE_BOOLEAN, 0, "DHCPOptionOverload" },
	{ "dhcp_message_type=", DBUS_TYPE_BYTE, 0, "DHCPMessageType" },
	{ "dhcp_server_identifier=", DBUS_TYPE_UINT32, 0, "DHCPServerIdentifier" },
	{ "dhcp_message=", DBUS_TYPE_STRING, 0, "DHCPMessage" },
	{ "dhcp_max_message_size=", DBUS_TYPE_UINT16, 0, "DHCPMaxMessageSize" },
	{ "dhcp_renewal_time=", DBUS_TYPE_UINT32, 0, "DHCPRenewalTime" },
	{ "dhcp_rebinding_time=", DBUS_TYPE_UINT32, 0, "DHCPRebindingTime" },
	{ "nisplus_domain=", DBUS_TYPE_STRING, 0, "NISPlusDomain" },
	{ "nisplus_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "NISPlusServers" },
	{ "tftp_server_name=", DBUS_TYPE_STRING, 0, "TFTPServerName" },
	{ "bootfile_name=", DBUS_TYPE_STRING, 0, "BootFileName" },
	{ "mobile_ip_home_agent=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "MobileIPHomeAgent" },
	{ "smtp_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "SMTPServer" },
	{ "pop_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "POPServer" },
	{ "nntp_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "NNTPServer" },
	{ "www_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "WWWServer" },
	{ "finger_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "FingerServer" },
	{ "irc_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "IRCServer" },
	{ "streettalk_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "StreetTalkServer" },
	{ "streettalk_directory_assistance_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "StreetTalkDirectoryAssistanceServer" },
	{ "user_class=", DBUS_TYPE_STRING, 0, "UserClass" },
	{ "new_fqdn_name=", DBUS_TYPE_STRING, 0, "FQDNName" },
	{ "nds_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "NDSServers" },
	{ "nds_tree_name=", DBUS_TYPE_STRING, 0, "NDSTreeName" },
	{ "nds_context=", DBUS_TYPE_STRING, 0, "NDSContext" },
	{ "bcms_controller_names=", DBUS_TYPE_STRING, 0, "BCMSControllerNames" },
	{ "client_last_transaction_time=", DBUS_TYPE_UINT32, 0, "ClientLastTransactionTime" },
	{ "associated_ip=", DBUS_TYPE_UINT32, 0, "AssociatedIP" },
	{ "uap_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "UAPServers" },
	{ "netinfo_server_address=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "NetinfoServerAddress" },
	{ "netinfo_server_tag=", DBUS_TYPE_STRING, 0, "NetinfoServerTag" },
	{ "default_url=", DBUS_TYPE_STRING, 0, "DefaultURL" },
	{ "subnet_selection=", DBUS_TYPE_UINT32, 0, "SubnetSelection" },
	{ "domain_search=", DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, "DomainSearch" },
	{ NULL, 0, 0, NULL }
};

static int
append_config_value(DBusMessageIter *entry, int type,
		    const char *data)
{
	int retval;
	DBusMessageIter var;
	unsigned char byte;
	dbus_uint16_t u16;
	dbus_uint32_t u32;
	struct in_addr in;

	retval = -1;
	switch (type) {
	case DBUS_TYPE_BYTE:
		byte = strtoul(data, NULL, 0);
		dbus_message_iter_open_container(entry,
						 DBUS_TYPE_VARIANT,
						 DBUS_TYPE_BYTE_AS_STRING,
						 &var);
		if (dbus_message_iter_append_basic(&var,
						   DBUS_TYPE_BYTE,
						   &byte))
			retval = 0;
		break;
	case DBUS_TYPE_STRING:
		dbus_message_iter_open_container(entry,
						 DBUS_TYPE_VARIANT,
						 DBUS_TYPE_STRING_AS_STRING,
						 &var);
		if (dbus_message_iter_append_basic(&var,
						   DBUS_TYPE_STRING,
						   &data))
			retval = 0;
		break;
	case DBUS_TYPE_UINT16:
		u16 = strtoul(data, NULL, 0);
		dbus_message_iter_open_container(entry,
						 DBUS_TYPE_VARIANT,
						 DBUS_TYPE_UINT16_AS_STRING,
						 &var);
		if (dbus_message_iter_append_basic(&var,
						   DBUS_TYPE_UINT16,
						   &u16))
			retval = 0;
		break;
	case DBUS_TYPE_UINT32:
		if (strchr(data, '.') != NULL && inet_aton(data, &in) == 1)
			u32 = in.s_addr;
		else
			u32 = strtoul(data, NULL, 0);
		dbus_message_iter_open_container(entry,
						 DBUS_TYPE_VARIANT,
						 DBUS_TYPE_UINT32_AS_STRING,
						 &var);
		if (dbus_message_iter_append_basic(&var,
						   DBUS_TYPE_UINT32,
						   &u32))
			retval = 0;
		break;
	default:
		retval = 1;
		break;
	}
	if (retval == 0)
		dbus_message_iter_close_container(entry, &var);
	else if (retval == 1)
		retval = 0;

	return retval;
}

static int
append_config_array(DBusMessageIter *entry, int type,
		    const char *data)
{
	int retval;
	char *ns, *p, *tok;
	const char *tsa, *ts;
	DBusMessageIter var, array;
	dbus_bool_t ok;
	dbus_uint32_t u32;
	struct in_addr in;

	switch (type) {
		case DBUS_TYPE_STRING:
			tsa = DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING;
			ts = DBUS_TYPE_STRING_AS_STRING;
			break;
		case DBUS_TYPE_UINT32:
			tsa = DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_UINT32_AS_STRING;
			ts = DBUS_TYPE_UINT32_AS_STRING;
			break;
		default:
			return -1;
	}

	ns = p = strdup(data);
	if (ns == NULL)
		return -1;
	retval = 0;

	dbus_message_iter_open_container(entry,
					 DBUS_TYPE_VARIANT,
					 tsa,
					 &var);
	dbus_message_iter_open_container(&var,
					 DBUS_TYPE_ARRAY,
					 ts,
					 &array);
	while ((tok = strsep(&p, " ")) != NULL) {
		if (*tok == '\0')
			continue;
		switch(type) {
		case DBUS_TYPE_STRING:
			ok = dbus_message_iter_append_basic(&array,
							    DBUS_TYPE_STRING,
							    &tok);
			break;
		case DBUS_TYPE_UINT32:
			if (strchr(data, '.') != NULL &&
			    inet_aton(data, &in) == 1)
				u32 = in.s_addr;
			else
				u32 = strtoul(tok, NULL, 0);
			ok = dbus_message_iter_append_basic(&array,
							    DBUS_TYPE_UINT32,
							    &u32);

			ok = dbus_message_iter_append_basic(&array,
							    DBUS_TYPE_UINT32,
							    &u32);
		default:
			ok = FALSE;
			break;
		}
		if (!ok)
			break;
	}
	dbus_message_iter_close_container(&var, &array);
	dbus_message_iter_close_container(entry, &var);
	free(ns);
	return retval;
}

static int
append_config_item(DBusMessageIter *iter, const struct dho_dbus *dhop,
		   const char *data)
{
	int retval;
	DBusMessageIter entry;

	retval = 0;
	dbus_message_iter_open_container(iter,
					 DBUS_TYPE_DICT_ENTRY,
					 NULL,
					 &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &dhop->name);
	if (dhop->type == DBUS_TYPE_ARRAY)
		retval = append_config_array(&entry, dhop->sub_type, data);
	else
		retval = append_config_value(&entry, dhop->type, data);
	dbus_message_iter_close_container(iter, &entry);
	return retval;
}

static int
append_config(DBusMessageIter *iter, const char *prefix, const struct config *c)
{
	char *p, *e;
	const struct dho_dbus *dhop;
	size_t l, lp;
	int retval;

	retval = 0;
	p = c->data;
	e = p + c->data_len;
	lp = strlen(prefix);
	while (p < e) {
		for (dhop = dhos; dhop->var; dhop++) {
			l = strlen(dhop->var);
			if (strncmp(p, dhop->var, l) == 0) {
				retval = append_config_item(iter, dhop, p + l);
				break;
			}
			if (strncmp(p, prefix, lp) == 0 &&
			    strncmp(p + lp, dhop->var, l - lp) == 0)
			{
				retval = append_config_item(iter, dhop, p + l + lp);
				break;
			}
		}
		if (retval == -1)
			break;
		l = strlen(p) + 1;
		p += l;
	}
	return retval;
}

static DBusHandlerResult _printf(4, 5)
return_dbus_error(DBusConnection *con, DBusMessage *msg,
	     const char *name, const char *fmt, ...)
{
	char buffer[1024];
	DBusMessage *reply;
	va_list args;

	va_start(args, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);
	reply = dbus_message_new_error(msg, name, buffer);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
return_status(DBusConnection *con, DBusMessage *msg)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	dbus_message_append_args(reply,
				 DBUS_TYPE_STRING,
				 &dhcpcd_status,
				 DBUS_TYPE_INVALID);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

void
signal_dhcpcd_status(const char *status)
{
	DBusMessage *msg;
	DBusMessageIter args;

	syslog(LOG_INFO, "status changed to %s", status);
	msg = dbus_message_new_signal(DHCPCD_PATH, DHCPCD_SERVICE, "StatusChanged");
	if (msg == NULL) {
		syslog(LOG_ERR, "failed to make a status changed message");
		return;
	}
	dbus_message_iter_init_append(msg, &args);
	dbus_message_iter_append_basic(&args,
				       DBUS_TYPE_STRING,
				       &status);
	if (!dbus_connection_send(connection, msg, NULL))
		syslog(LOG_ERR, "failed to send status to dbus");
	dbus_message_unref(msg);
}

void
configure_dbus(const struct config *c)
{
	int retval;
	DBusMessage* msg = NULL;
	DBusMessageIter args, dict;

	msg = dbus_message_new_signal(DHCPCD_PATH, DHCPCD_SERVICE, "Event");
	if (msg == NULL) {
		syslog(LOG_ERR, "failed to make a configure message");
		return;
	}

	syslog(LOG_INFO, "event on interface %s (%s)", c->iface, get_dhcp_config(c, "reason="));
	dbus_message_iter_init_append(msg, &args);
	dbus_message_iter_open_container(&args,
					 DBUS_TYPE_ARRAY,
					 DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					 DBUS_TYPE_STRING_AS_STRING
					 DBUS_TYPE_VARIANT_AS_STRING
					 DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					 &dict);
	if (get_dhcp_config(c, "new_ip_address"))
		retval = append_config(&dict, "new_", c);
	else
		retval = append_config(&dict, "old_", c);
	dbus_message_iter_close_container(&args, &dict);
	if (retval == 0) {
		if (!dbus_connection_send(connection, msg, NULL))
			syslog(LOG_ERR, "failed to send dhcp to dbus");
	} else
		syslog(LOG_ERR, "failed to construct dbus message");
	dbus_message_unref(msg);
}

static DBusHandlerResult
introspect(DBusConnection *con, DBusMessage *msg)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	dbus_message_append_args(reply,
				 DBUS_TYPE_STRING,
				 &introspection_xml,
				 DBUS_TYPE_INVALID);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
version(DBusConnection *con, DBusMessage *msg, const char *ver)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	dbus_message_append_args(reply,
				 DBUS_TYPE_STRING,
				 &ver,
				 DBUS_TYPE_INVALID);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
dhcpcd_get_interfaces(DBusConnection *con, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter ifaces, iface, entry, dict;
	struct config *c;

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &ifaces);

	dbus_message_iter_open_container(&ifaces,
					 DBUS_TYPE_ARRAY,
					 DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					 DBUS_TYPE_STRING_AS_STRING
					 DBUS_TYPE_ARRAY_AS_STRING
					 DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					 DBUS_TYPE_STRING_AS_STRING
					 DBUS_TYPE_VARIANT_AS_STRING
					 DBUS_DICT_ENTRY_END_CHAR_AS_STRING
					 DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					 &iface);

	for (c = configs; c; c = c->next) {
		dbus_message_iter_open_container(&iface,
						 DBUS_TYPE_DICT_ENTRY,
						 NULL,
						 &entry);
		dbus_message_iter_append_basic(&entry,
					       DBUS_TYPE_STRING,
					       &c->iface);
		dbus_message_iter_open_container(&entry,
				 		 DBUS_TYPE_ARRAY,
						 DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
						 DBUS_TYPE_STRING_AS_STRING
						 DBUS_TYPE_VARIANT_AS_STRING
						 DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
						 &dict);
		append_config(&dict, "new_", c);
		dbus_message_iter_close_container(&entry, &dict);
		dbus_message_iter_close_container(&iface, &entry);
	}

	dbus_message_iter_close_container(&ifaces, &iface);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
dhcpcd_iface_command(DBusConnection *con, DBusMessage *msg,
		     const char *command)
{
	DBusMessage *reply;
	DBusError err;
	char *s, cmd[128];

	dbus_error_init(&err);
	if (!dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, &s, DBUS_TYPE_INVALID))
		return return_dbus_error(con, msg, S_EINVAL,
					 "No interface specified");

	snprintf(cmd, sizeof(cmd), "dhcpcd %s %s", command, s);
	dhcpcd_command(cmd, NULL);

	reply = dbus_message_new_method_return(msg);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
msg_handler(DBusConnection *con, DBusMessage *msg, _unused void *data)
{
	if (dbus_message_is_method_call(msg,
					DBUS_INTERFACE_INTROSPECTABLE,
					"Introspect"))
		return introspect(con, msg);
	else if (dbus_message_is_method_call(msg,
					     DHCPCD_SERVICE,
					     "GetVersion"))
		return version(con, msg, VERSION);
	else if (dbus_message_is_method_call(msg,
				 	     DHCPCD_SERVICE,
					     "GetDhcpcdVersion"))
		return version(con, msg, dhcpcd_version);
	else if (dbus_message_is_method_call(msg,
					     DHCPCD_SERVICE,
					     "GetInterfaces"))
		return dhcpcd_get_interfaces(con, msg);
	else if (dbus_message_is_method_call(msg,
					     DHCPCD_SERVICE,
					     "GetStatus"))
		return return_status(con, msg);
	else if (dbus_message_is_method_call(msg,
					     DHCPCD_SERVICE,
					     "Rebind"))
		return dhcpcd_iface_command(con, msg, "--rebind");
	else if (dbus_message_is_method_call(msg,
					     DHCPCD_SERVICE,
					     "Release"))
		return dhcpcd_iface_command(con, msg, "--release");
	else if (dbus_message_is_method_call(msg,
					     DHCPCD_SERVICE,
					     "Stop"))
		return dhcpcd_iface_command(con, msg, "--exit");
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static dbus_bool_t
add_watch(DBusWatch *watch, _unused void *data)
{
	struct watch *w;

	for (w = watches; w; w = w->next)
		if (w->watch == watch)
			return TRUE;
	w = malloc(sizeof(*w));
	if (w == NULL)
		return FALSE;
	w->watch = watch;
	w->next = watches;
	watches = w;
	return TRUE;
}

static void
remove_watch(DBusWatch *watch, _unused void *data)
{
	struct watch *w, *l = NULL;

	for (w = watches; w; w = w->next) {
		if (w->watch == watch) {
			if (l == NULL)
				watches = w->next;
			else
				l->next = w->next;
			free(w);
			break;
		}
	}
}

size_t
add_dbus_listeners(struct pollfd *fds)
{
	struct watch *w;
	int flags;
	size_t n;

	n = 0;
	for (w = watches; w; w = w->next) {
		if (dbus_watch_get_enabled(w->watch)) {
			n++;
			if (fds != NULL) {
				fds->fd = dbus_watch_get_unix_fd(w->watch);
				fds->events = POLLHUP | POLLERR;
				flags = dbus_watch_get_flags(w->watch);
				if (flags & DBUS_WATCH_READABLE)
					fds->events |= POLLIN;
				if (flags & DBUS_WATCH_WRITABLE)
					fds->events |= POLLOUT;
				fds++;
			}
		}
	}
	return n;
}

void
check_dbus_listeners(struct pollfd *fds, size_t nfds)
{
	struct watch *w;
	int fd, flags;
	size_t i;

	for (w = watches; w; w = w->next) {
		if (!dbus_watch_get_enabled(w->watch))
			continue;
		fd = dbus_watch_get_unix_fd(w->watch);
		for (i = 0; i < nfds; i++) {
			if (fds[i].fd == fd) {
				flags = 0;
				if (fds[i].revents & POLLIN)
					flags |= DBUS_WATCH_READABLE;
				if (fds[i].revents & POLLOUT)
					flags |= DBUS_WATCH_WRITABLE;
				if (fds[i].revents & POLLHUP)
					flags |= DBUS_WATCH_HANGUP;
				if (fds[i].revents & POLLERR)
					flags |= DBUS_WATCH_ERROR;
				if (flags != 0)
					dbus_watch_handle(w->watch, flags);
				break;
			}
		}
	}

	if (connection != NULL) {
		dbus_connection_ref(connection);
		while (dbus_connection_dispatch(connection)
				== DBUS_DISPATCH_DATA_REMAINS)
			;
		dbus_connection_unref(connection);
	}
}

int
init_dbus(void)
{
	DBusObjectPathVTable vt = {NULL, &msg_handler, NULL, NULL, NULL, NULL };
	DBusError err;
	int ret;

	dbus_error_init(&err);
	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (connection == NULL) {
		if (dbus_error_is_set(&err))
			syslog(LOG_ERR, "%s", err.message);
		else
			syslog(LOG_ERR, "failed to get a dbus connection");
		return -1;
	}
			
	ret = dbus_bus_request_name(connection,
				    DHCPCD_SERVICE,
				    DBUS_NAME_FLAG_REPLACE_EXISTING,
				    &err);
	if (dbus_error_is_set(&err)) {
		syslog(LOG_ERR, "%s", err.message);
		return -1;
	}
	if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		syslog(LOG_ERR, "dbus: not primary owner");
		return -1;
	}
	if (!dbus_connection_set_watch_functions(connection,
						 add_watch, remove_watch,
						 NULL, NULL, NULL))
	{
		syslog(LOG_ERR, "dbus: failed to set watch functions");
		return -1;
	}
	if (!dbus_connection_register_object_path(connection,
						  DHCPCD_PATH, &vt, NULL))
	{
		syslog(LOG_ERR, "dbus: failed to register object path");
		return -1;
	}
	return 0;
}
