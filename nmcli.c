/* nmcli - command-line tool to control NetworkManager
 *
 * Jiri Klimes <jklimes@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2010 - 2011 Red Hat, Inc.
 */

/* Generated configuration file */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <locale.h>
#include <stdarg.h>

#include <glib.h>
#include <dbus/dbus-glib.h>

#include <glib/gi18n.h>
#include <nm-client.h>
#include <nm-setting-connection.h>
#include <nm-remote-settings.h>
#include <nm-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-gsm.h>
#include <nm-setting-ip4-config.h>
#include <NetworkManager.h>
#include <nm-utils.h>
#include <nm-setting-ppp.h>
#include <nm-setting-serial.h>

#include "nmcli.h"
#include "utils.h"
#include "connections.h"
#include "devices.h"
#include "network-manager.h"

#define DBUS_TYPE_G_MAP_OF_VARIANT          (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE))
#define DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT   (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, DBUS_TYPE_G_MAP_OF_VARIANT))

#define NOT_SET "not_set"

#if defined(NM_DIST_VERSION)
# define NMCLI_VERSION NM_DIST_VERSION
#else
# define NMCLI_VERSION VERSION
#endif


typedef struct {
	NmCli *nmc;
	int argc;
	char **argv;
} ArgsInfo;

/* --- Global variables --- */
GMainLoop *loop = NULL;


static void
usage (const char *prog_name)
{
	fprintf (stderr,
	         _("Usage: %s [OPTIONS] OBJECT { COMMAND | help }\n\n"
	         "OPTIONS\n"
	         "  -t[erse]                                   terse output\n"
	         "  -p[retty]                                  pretty output\n"
	         "  -m[ode] tabular|multiline                  output mode\n"
	         "  -f[ields] <field1,field2,...>|all|common   specify fields to output\n"
	         "  -e[scape] yes|no                           escape columns separators in values\n"
	         "  -n[ocheck]                                 don't check nmcli and NetworkManager versions\n"
	         "  -v[ersion]                                 show program version\n"
	         "  -h[elp]                                    print this help\n\n"
	         "OBJECT\n"
	         "  nm                          NetworkManager status\n"
	         "  add                         add new connection via NetworkManager\n"
	         "  con                         NetworkManager connections\n"
	         "  dev                         devices managed by NetworkManager\n\n"),
	          prog_name);
}

static NMCResultCode 
do_help (NmCli *nmc, int argc, char **argv)
{
	usage ("nmcli");
	return NMC_RESULT_SUCCESS;
}

static void
usage_add (void)
{
	fprintf (stderr,
	         _("Usage: nmcli add { help | COMMAND }\n"
	         "  COMMAND := id <id> param1 <param1> param2 <value2> ... param_n <value_n>\n"
	         "  Available parameters: \n"
	         " \t<id>         [has to be specified]\n"
	         " \t<auto>       [autoconnect] default: true (T/F)\n"
	         " \t<APN>\n"
	         " \t<PIN>\n"
	         " \t<username>\n"
	         " \t<password>\n"
	         " \t<ntype>      [network type]\n"
	         " \t             -1 : any | 0 : 3G only | 1: GPRS/EDGE only\n"
	         " \t             2: prefer 3G | 3: prefer 2G\n"
	         " \t             Note: not all devices allow network preference control!\n"
	         " \t<uuid>\n"
	         " \t<auth>       [autenthication]\n"
	         " \t             Allowed methods: EAP (T/F) | PAP (T/F) | CHAP (T/F) |\n"
	         " \t             MSCHAPv2 (T/F) | MSCHAP (T/F)\n"
	         " \t<comp>       [compression]\n" 
	         " \t             Allow BSD data compression (T/F)\n"
	         " \t             Allow Deflate data compression (T/F)\n"
	         " \t             Use TCP header compression (T/F)\n"
	         " \t<echo>       Send PPP echo packets (T/F)\n"
	         " \t<enc>        [Use point-to-point encryption MPPE]:\n"
	         " \t             Require 128-bit encryption (T/F)\n"
	         " \t             Use stateful MPPE (T/F)\n"
	         " \t-Input example: nmcli add id MyTestConnection APN sample.apn PIN my_pin auth TTTTF\n\n"));
}

static int
add_connection (DBusGProxy *proxy, char *con_name, char *apn, char *pin, 
				char *username, char *password, int ntype, char *number,
				char *auth, char *comp, char *aut)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMSettingGsm *s_gsm;
	NMSettingPPP *s_ppp;
	NMSettingSerial *s_serial;
	
	char *uuid, *new_con_path = NULL;
	GHashTable *hash;
	GError *error = NULL;
	
	int autoconnect = 1;
	
	if ((aut != NULL) && (aut[0] != 'T'))
		autoconnect = 0;
	
	connection = (NMConnection *)nm_connection_new ();
	if (connection == NULL){
		printf("Unable to allocate new connection... Sorry.\n");
		return NMC_RESULT_ERROR_CON_ADD;
	}

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	if (s_con == NULL){
		printf("Failed to allocate new %s setting... Sorry.\n",NM_SETTING_CONNECTION_SETTING_NAME);
		return NMC_RESULT_ERROR_CON_ADD;
	}
	 
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	uuid = nm_utils_uuid_generate ();
	
	/*global settings*/
	              
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, con_name,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, (autoconnect == 0) ? TRUE : FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_GSM_SETTING_NAME,
	              NULL);
	g_free (uuid);
    
	/* GSM setting */
	s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
	
	if (s_gsm == NULL){
		printf("Failed to allocate new %s setting...Sorry.\n",NM_SETTING_GSM_SETTING_NAME);
		return NMC_RESULT_ERROR_CON_ADD;
	}
	
	nm_connection_add_setting (connection, NM_SETTING (s_gsm));

	/*Network type
					    Network preference to force the device to only use 
					    specific network technologies.  The permitted values
					    are: -1: any, 0: 3G only, 1: GPRS/EDGE only, 
					    2: prefer 3G, and 3: prefer 2G.  Note that not all 
					    devices allow network preference control.,
	*/ 
					   
	g_object_set (s_gsm, 
	              NM_SETTING_GSM_NUMBER, (number == NULL) ? "*99#" : number,
	              NM_SETTING_GSM_APN, apn,
	              NM_SETTING_GSM_USERNAME, username,
	              NM_SETTING_GSM_PASSWORD, password,
	              NM_SETTING_GSM_PIN, pin,
	              NM_SETTING_GSM_NETWORK_TYPE, ntype, 
	              NULL);

	/* Serial setting */
	s_serial = (NMSettingSerial *) nm_setting_serial_new ();
	
	if (s_serial == NULL){
		printf("Failed to allocate new %s setting...Sorry.\n",NM_SETTING_SERIAL_SETTING_NAME);
		return NMC_RESULT_ERROR_CON_ADD;
	}
	
	nm_connection_add_setting (connection, NM_SETTING (s_serial));

	g_object_set (s_serial,
	              NM_SETTING_SERIAL_BAUD, 115200,
	              NM_SETTING_SERIAL_BITS, 8,
	              NM_SETTING_SERIAL_PARITY, 'n',
	              NM_SETTING_SERIAL_STOPBITS, 1,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	
	if (s_ip4 == NULL){
		printf("Failed to allocate new %s setting... Sorry.\n",NM_SETTING_IP4_CONFIG_SETTING_NAME);
		return NMC_RESULT_ERROR_CON_ADD;
	}
	
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* PPP setting */
	s_ppp = (NMSettingPPP *) nm_setting_ppp_new ();
	
	if (s_ppp == NULL){
		printf("Failed to allocate new %s setting... Sorry.\n", NM_SETTING_PPP_SETTING_NAME);
		return NMC_RESULT_ERROR_CON_ADD;
	}
	
	
	g_object_set(s_ppp,
				NM_SETTING_PPP_REFUSE_EAP, (auth[0] == 'T') ? TRUE : FALSE,
				NM_SETTING_PPP_REFUSE_PAP, (auth[1] == 'T') ? TRUE : FALSE,
				NM_SETTING_PPP_REFUSE_CHAP, (auth[2] == 'T') ? TRUE : FALSE,
				NM_SETTING_PPP_REFUSE_MSCHAP, (auth[3] == 'T') ? TRUE : FALSE,
				NM_SETTING_PPP_REFUSE_MSCHAPV2, (auth[4] == 'T') ? TRUE : FALSE,
				NM_SETTING_PPP_NOBSDCOMP, (comp[0] == 'T') ? TRUE : FALSE,
				NM_SETTING_PPP_NODEFLATE, (comp[1] == 'T') ? TRUE : FALSE,
				NM_SETTING_PPP_NO_VJ_COMP,(comp[2] == 'T') ? TRUE : FALSE, //tcp header compression
				NM_SETTING_PPP_REQUIRE_MPPE, FALSE,
				NM_SETTING_PPP_MPPE_STATEFUL, FALSE,
				NM_SETTING_PPP_REQUIRE_MPPE_128, FALSE,
				NULL);

	nm_connection_add_setting (connection, NM_SETTING (s_ppp));

	
	hash = nm_connection_to_hash (connection, NM_SETTING_HASH_FLAG_ALL);

	/* Call AddConnection with the hash as argument */
	if (!dbus_g_proxy_call (proxy, "AddConnection", &error,
	                        DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, hash,
	                        G_TYPE_INVALID,
	                        DBUS_TYPE_G_OBJECT_PATH, &new_con_path,
	                        G_TYPE_INVALID)) {
		g_print ("Error adding connection: %s %s",
		         dbus_g_error_get_name (error),
		         error->message);
		g_clear_error (&error);
	} else {
		g_print ("\n\tConnection added successfully at: %s \n\tUse: nmcli con list id %s to see connection detailed info \n\tor con delete id %s to delete connection.\n\n", 
		         new_con_path, con_name, con_name);
		g_free (new_con_path);
	}

	g_hash_table_destroy (hash);
	g_object_unref (connection);
	
	return 0;
}
	

/*ovo mijenjaj za sad ne ono iznad!*/


static NMCResultCode
do_add (NmCli *nmc, int argc, char **argv)
{
	DBusGConnection *bus;
	DBusGProxy *proxy;
	char *apn;
	char *pin;
	char *username;
	char *password;
	char *number; 
	char *ntype;
	char *auth;
	char *comp;
	char *aut;
	
	int i;
	
	apn = NULL;
	pin = NULL;
	username = NULL;
	password = NULL;
	ntype = NULL;
	number = NULL;
	auth = NULL;
	comp = NULL;
	aut = NULL;
	
	
	if ((*argv == NULL) || strcmp(argv[0],"help") == 0 || strcmp(argv[0],"-help") == 0){
		usage_add();
	}
		
	else{
		
		if (matches(argv[0],"id") != 0){
			g_string_printf (nmc->return_text, _("Error: id has to be specified."));
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			return nmc->return_value;
		}
		else if (matches(argv[0],"id") == 0){
			if(argc == 1){
				g_string_printf (nmc->return_text, _("Error: argument missing for parameter id."));	
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			else if (argc % 2!=0){
				g_string_printf (nmc->return_text, _("Error: Some arguments are missing."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
		}
		
		
		printf("%d ovoliko nas ima\n", argc);
		
		for (i=0; i<argc; i=i+2){
			
			(matches(argv[i], "APN") == 0) ? apn = argv[i + 1] : NOT_SET;	
			(matches(argv[i], "PIN") == 0) ? pin = argv[i + 1] : NOT_SET;
			(matches(argv[i], "username") == 0) ? username = argv[i + 1] : NOT_SET;
			(matches(argv[i], "password") == 0) ? password = argv[i + 1] : NOT_SET;
			(matches(argv[i], "ntype") == 0) ? ntype = argv[i + 1] : NOT_SET;
			(matches(argv[i], "number") == 0) ? number = argv[i + 1] : NOT_SET;
			(matches(argv[i], "auth") == 0) ? auth = argv[i + 1] : NOT_SET;
			(matches(argv[i], "comp") == 0) ? comp = argv[i + 1] : NOT_SET;
			(matches(argv[i], "aut") == 0) ? comp = argv[i + 1] : NOT_SET;
			
		}
		
		printf ("%s %s %s %s\n", apn, pin, username, ntype);
			
		g_type_init ();

		bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, NULL);

		proxy = dbus_g_proxy_new_for_name (bus,
										   NM_DBUS_SERVICE,
	                                       NM_DBUS_PATH_SETTINGS,
	                                       NM_DBUS_IFACE_SETTINGS);
	                                   
		//printf("%s | %s | %s | %s \n", argv[0], argv[1], argv[2], argv[3]);

		if (add_connection (proxy, argv[1], apn, pin, username, password, ((ntype == NULL) ? -1 : atoi(ntype)), 
		                    number, ((auth == NULL) ? "FFFFF" : auth), ((comp == NULL) ? "FFF" : comp), aut) == 10){
			g_string_printf (nmc->return_text, _("Error: id has to be specified."));
			nmc->return_value = NMC_RESULT_ERROR_CON_ADD;
			return nmc->return_value;
		}

		g_object_unref (proxy);
		dbus_g_connection_unref (bus);
	}

	
	return NMC_RESULT_SUCCESS;
}


static const struct cmd {
	const char *cmd;
	NMCResultCode (*func) (NmCli *nmc, int argc, char **argv);
} nmcli_cmds[] = {
	{ "nm",         do_network_manager },
	{ "con",        do_connections },
	{ "dev",        do_devices },
	{ "help",       do_help },
	{ "add",        do_add },
	{ 0 }
};

static NMCResultCode
do_cmd (NmCli *nmc, const char *argv0, int argc, char **argv)
{
	const struct cmd *c;

	for (c = nmcli_cmds; c->cmd; ++c) {
		if (matches (argv0, c->cmd) == 0)
			return c->func (nmc, argc-1, argv+1);
	}

	g_string_printf (nmc->return_text, _("Error: Object '%s' is unknown, try 'nmcli help'."), argv0);
	nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
	return nmc->return_value;
}

static NMCResultCode
parse_command_line (NmCli *nmc, int argc, char **argv)
{
	char *base;

	base = strrchr (argv[0], '/');
	if (base == NULL)
		base = argv[0];
	else
		base++;

	/* parse options */
	while (argc > 1) {
		char *opt = argv[1];
		/* '--' ends options */
		if (strcmp (opt, "--") == 0) {
			argc--; argv++;
			break;
		}
		if (opt[0] != '-')
			break;
		if (opt[1] == '-')
			opt++;
		if (matches (opt, "-terse") == 0) {
			if (nmc->print_output == NMC_PRINT_TERSE) {
				g_string_printf (nmc->return_text, _("Error: Option '--terse' is specified the second time."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			else if (nmc->print_output == NMC_PRINT_PRETTY) {
				g_string_printf (nmc->return_text, _("Error: Option '--terse' is mutually exclusive with '--pretty'."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			else
				nmc->print_output = NMC_PRINT_TERSE;
		} else if (matches (opt, "-pretty") == 0) {
			if (nmc->print_output == NMC_PRINT_PRETTY) {
				g_string_printf (nmc->return_text, _("Error: Option '--pretty' is specified the second time."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			else if (nmc->print_output == NMC_PRINT_TERSE) {
				g_string_printf (nmc->return_text, _("Error: Option '--pretty' is mutually exclusive with '--terse'."));
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			else
				nmc->print_output = NMC_PRINT_PRETTY;
		} else if (matches (opt, "-mode") == 0) {
			nmc->mode_specified = TRUE;
			next_arg (&argc, &argv);
			if (argc <= 1) {
		 		g_string_printf (nmc->return_text, _("Error: missing argument for '%s' option."), opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			if (!strcmp (argv[1], "tabular"))
				nmc->multiline_output = FALSE;
			else if (!strcmp (argv[1], "multiline"))
				nmc->multiline_output = TRUE;
			else {
		 		g_string_printf (nmc->return_text, _("Error: '%s' is not valid argument for '%s' option."), argv[1], opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
		} else if (matches (opt, "-escape") == 0) {
			next_arg (&argc, &argv);
			if (argc <= 1) {
		 		g_string_printf (nmc->return_text, _("Error: missing argument for '%s' option."), opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			if (!strcmp (argv[1], "yes"))
				nmc->escape_values = TRUE;
			else if (!strcmp (argv[1], "no"))
				nmc->escape_values = FALSE;
			else {
		 		g_string_printf (nmc->return_text, _("Error: '%s' is not valid argument for '%s' option."), argv[1], opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
		} else if (matches (opt, "-fields") == 0) {
			next_arg (&argc, &argv);
			if (argc <= 1) {
		 		g_string_printf (nmc->return_text, _("Error: fields for '%s' options are missing."), opt);
				nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
				return nmc->return_value;
			}
			nmc->required_fields = g_strdup (argv[1]);
		} else if (matches (opt, "-nocheck") == 0) {
			nmc->nocheck_ver = TRUE;
		} else if (matches (opt, "-version") == 0) {
			printf (_("nmcli tool, version %s\n"), NMCLI_VERSION);
			return NMC_RESULT_SUCCESS;
		} else if (matches (opt, "-help") == 0) {
			usage (base);
			return NMC_RESULT_SUCCESS;
		} else {
			g_string_printf (nmc->return_text, _("Error: Option '%s' is unknown, try 'nmcli -help'."), opt);
			nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
			return nmc->return_value;
		}
		argc--;
		argv++;
	}

	if (argc > 1)
		return do_cmd (nmc, argv[1], argc-1, argv+1);

	usage (base);
	return nmc->return_value;
}

static void
signal_handler (int signo)
{
	if (signo == SIGINT || signo == SIGTERM) {
		g_message (_("Caught signal %d, shutting down..."), signo);
		g_main_loop_quit (loop);
	}
}

static void
setup_signals (void)
{
	struct sigaction action;
	sigset_t mask;

	sigemptyset (&mask);
	action.sa_handler = signal_handler;
	action.sa_mask = mask;
	action.sa_flags = 0;
	sigaction (SIGTERM,  &action, NULL);
	sigaction (SIGINT,  &action, NULL);
}

static NMClient *
nmc_get_client (NmCli *nmc)
{
	if (!nmc->client) {
		nmc->client = nm_client_new ();
		if (!nmc->client) {
			g_critical (_("Error: Could not create NMClient object."));
			exit (NMC_RESULT_ERROR_UNKNOWN);
		}
	}

	return nmc->client;
}

/* Initialize NmCli structure - set default values */
static void
nmc_init (NmCli *nmc)
{
	nmc->client = NULL;
	nmc->get_client = &nmc_get_client;

	nmc->return_value = NMC_RESULT_SUCCESS;
	nmc->return_text = g_string_new (_("Success"));

	nmc->timeout = 10;

	nmc->system_settings = NULL;
	nmc->system_settings_running = FALSE;
	nmc->system_connections = NULL;

	nmc->should_wait = FALSE;
	nmc->nowait_flag = TRUE;
	nmc->print_output = NMC_PRINT_NORMAL;
	nmc->multiline_output = FALSE;
	nmc->mode_specified = FALSE;
	nmc->escape_values = TRUE;
	nmc->required_fields = NULL;
	nmc->allowed_fields = NULL;
	memset (&nmc->print_fields, '\0', sizeof (NmcPrintFields));
	nmc->nocheck_ver = FALSE;
}

static void
nmc_cleanup (NmCli *nmc)
{
	if (nmc->client) g_object_unref (nmc->client);

	g_string_free (nmc->return_text, TRUE);

	if (nmc->system_settings) g_object_unref (nmc->system_settings);
	g_slist_free (nmc->system_connections);

	g_free (nmc->required_fields);
	if (nmc->print_fields.indices)
		g_array_free (nmc->print_fields.indices, TRUE);
}

static gboolean
start (gpointer data)
{
	ArgsInfo *info = (ArgsInfo *) data;
	info->nmc->return_value = parse_command_line (info->nmc, info->argc, info->argv);

	if (!info->nmc->should_wait)
		g_main_loop_quit (loop);

	return FALSE;
}


int
main (int argc, char *argv[])
{
	NmCli nmc;
	ArgsInfo args_info = { &nmc, argc, argv };

	/* Set locale to use environment variables */
	setlocale (LC_ALL, "");

#ifdef GETTEXT_PACKAGE
	/* Set i18n stuff */
	bindtextdomain (GETTEXT_PACKAGE, NMCLI_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);
#endif

	g_type_init ();

	nmc_init (&nmc);
	g_idle_add (start, &args_info);

	loop = g_main_loop_new (NULL, FALSE);  /* create main loop */
	setup_signals ();                      /* setup UNIX signals */
	g_main_loop_run (loop);                /* run main loop */

	/* Print result descripting text */
	if (nmc.return_value != NMC_RESULT_SUCCESS) {
		fprintf (stderr, "%s\n", nmc.return_text->str);
	}

	g_main_loop_unref (loop);
	nmc_cleanup (&nmc);

	return nmc.return_value;
}
