#include "ac.h"
#include "ac_soap.h"
#include "ac_session.h"
#include "capwap_dtls.h"
#include "capwap_socket.h"

#include <libconfig.h>

#ifndef CAPWAP_MULTITHREADING_ENABLE
#error "AC request multithreading\n"
#endif

struct ac_t g_ac;

#define AC_STANDARD_NAME				"Unknown AC"

/* Local param */
static char g_configurationfile[260] = AC_DEFAULT_CONFIGURATION_FILE;

/* */
static unsigned long ac_stations_item_gethash(const void* key, unsigned long keysize, unsigned long hashsize) {
	uint8_t* macaddress = (uint8_t*)key;

	ASSERT(keysize == MACADDRESS_EUI48_LENGTH);

	return ((((unsigned long)macaddress[4] << 8) | (unsigned long)macaddress[5]) ^ ((unsigned long)macaddress[3] << 4));
}

/* Alloc AC */
static int ac_init(void) {
	g_ac.standalone = 1;

	/* Sessions message queue */
	if (!ac_msgqueue_init()) {
		return 0;
	}

	/* Network */
	capwap_network_init(&g_ac.net);
	g_ac.mtu = CAPWAP_MTU_DEFAULT;
	g_ac.binding = capwap_array_create(sizeof(uint16_t), 0, 0);
	g_ac.net.bind_sock_ctrl_port = CAPWAP_CONTROL_PORT;

	/* Standard name */
	g_ac.acname.name = (uint8_t*)capwap_duplicate_string(AC_STANDARD_NAME);

	/* Descriptor */
	g_ac.descriptor.stationlimit = AC_DEFAULT_MAXSTATION;
	g_ac.descriptor.maxwtp = AC_DEFAULT_MAXSESSIONS;
	g_ac.descriptor.security = 0;
	g_ac.descriptor.rmacfield = CAPWAP_ACDESC_RMACFIELD_NOTSUPPORTED;
	g_ac.descriptor.dtlspolicy = CAPWAP_ACDESC_CLEAR_DATA_CHANNEL_ENABLED;
	g_ac.descriptor.descsubelement = capwap_array_create(sizeof(struct capwap_acdescriptor_desc_subelement), 0, 1);

	/* */
	g_ac.dfa.ecn.flag = CAPWAP_LIMITED_ECN_SUPPORT;
	g_ac.dfa.transport.type = CAPWAP_UDP_TRANSPORT;

	/* */
	g_ac.dfa.timers.discovery = AC_DISCOVERY_INTERVAL / 1000;
	g_ac.dfa.timers.echorequest = AC_ECHO_INTERVAL / 1000;
	g_ac.dfa.decrypterrorreport_interval = AC_DECRYPT_ERROR_PERIOD_INTERVAL / 1000;
	g_ac.dfa.idletimeout.timeout = AC_IDLE_TIMEOUT_INTERVAL / 1000;
	g_ac.dfa.wtpfallback.mode = AC_WTP_FALLBACK_MODE;

	/* */
	g_ac.dfa.acipv4list.addresses = capwap_array_create(sizeof(struct in_addr), 0, 0);
	g_ac.dfa.acipv6list.addresses = capwap_array_create(sizeof(struct in6_addr), 0, 0);

	/* Sessions */
	g_ac.sessions = capwap_list_create();
	g_ac.sessionsdata = capwap_list_create();
	g_ac.sessionsthread = capwap_list_create();
	capwap_rwlock_init(&g_ac.sessionslock);

	/* Stations */
	g_ac.stations = capwap_hash_create(AC_STATIONS_HASH_SIZE, AC_STATIONS_KEY_SIZE, ac_stations_item_gethash, NULL, NULL);
	capwap_rwlock_init(&g_ac.stationslock);

	/* Backend */
	g_ac.availablebackends = capwap_array_create(sizeof(struct ac_http_soap_server*), 0, 0);

	return 1;
}

/* Destroy AC */
static void ac_destroy(void) {
	int i;

	/* Dtls */
	capwap_crypt_freecontext(&g_ac.dtlscontext);

	/* */
	for (i = 0; i < g_ac.descriptor.descsubelement->count; i++) {
		struct capwap_acdescriptor_desc_subelement* desc = (struct capwap_acdescriptor_desc_subelement*)capwap_array_get_item_pointer(g_ac.descriptor.descsubelement, i);

		if (desc->data) {
			capwap_free(desc->data);
		}
	}

	/* */
	capwap_array_free(g_ac.descriptor.descsubelement);
	capwap_array_free(g_ac.binding);
	capwap_free(g_ac.acname.name);

	/* */
	capwap_array_free(g_ac.dfa.acipv4list.addresses);
	capwap_array_free(g_ac.dfa.acipv6list.addresses);

	/* Sessions */
	capwap_list_free(g_ac.sessions);
	capwap_list_free(g_ac.sessionsdata);
	capwap_list_free(g_ac.sessionsthread);
	capwap_rwlock_destroy(&g_ac.sessionslock);
	ac_msgqueue_free();

	/* Stations */
	ASSERT(g_ac.stations->count == 0);
	capwap_hash_free(g_ac.stations);
	capwap_rwlock_destroy(&g_ac.stationslock);

	/* Backend */
	if (g_ac.backendacid) {
		capwap_free(g_ac.backendacid);
	}

	if (g_ac.backendversion) {
		capwap_free(g_ac.backendversion);
	}

	for (i = 0; i < g_ac.availablebackends->count; i++) {
		ac_soapclient_free_server(*(struct ac_http_soap_server**)capwap_array_get_item_pointer(g_ac.availablebackends, i));
	}

	capwap_array_free(g_ac.availablebackends);
}

/* Help */
static void ac_print_usage(void) {
}

/* Parsing configuration */
static int ac_parsing_configuration_1_0(config_t* config) {
	int i;
	int configBool;
	int configIPv4;
	int configIPv6;
	LIBCONFIG_LOOKUP_INT_ARG configInt;
	const char* configString;
	config_setting_t* configSetting;

	/* Logging configuration */
	if (config_lookup_bool(config, "logging.enable", &configBool) == CONFIG_TRUE) {
		if (!configBool) {
			capwap_logging_verboselevel(CAPWAP_LOGGING_NONE);
			capwap_logging_disable_allinterface();
		} else {
			if (config_lookup_string(config, "logging.level", &configString) == CONFIG_TRUE) {
				if (!strcmp(configString, "fatal")) {
					capwap_logging_verboselevel(CAPWAP_LOGGING_FATAL);
				} else if (!strcmp(configString, "error")) {
					capwap_logging_verboselevel(CAPWAP_LOGGING_ERROR);
				} else if (!strcmp(configString, "warning")) {
					capwap_logging_verboselevel(CAPWAP_LOGGING_WARNING);
				} else if (!strcmp(configString, "info")) {
					capwap_logging_verboselevel(CAPWAP_LOGGING_INFO);
				} else if (!strcmp(configString, "debug")) {
					capwap_logging_verboselevel(CAPWAP_LOGGING_DEBUG);
				} else {
					capwap_logging_error("Invalid configuration file, unknown logging.level value");
					return 0;
				}
			}

			/* Logging output interface */
			configSetting = config_lookup(config, "logging.output");
			if (configSetting != NULL) {
				int count = config_setting_length(configSetting);

				/* Disable output interface */
				capwap_logging_disable_allinterface();

				/* Enable selected interface */
				for (i = 0; i < count; i++) {
					config_setting_t* configElement = config_setting_get_elem(configSetting, i);
					if ((configElement != NULL) && (config_setting_lookup_string(configElement, "mode", &configString) == CONFIG_TRUE)) {
						if (!strcmp(configString, "stdout")) {
							capwap_logging_enable_console(0);
						} else if (!strcmp(configString, "stderr")) {
							capwap_logging_enable_console(1);
						} else {
							capwap_logging_error("Invalid configuration file, unknown logging.output value");
							return 0;
						}
					}
				}
			}
		}
	}

	/* Set running mode */
	if (config_lookup_bool(config, "application.standalone", &configBool) == CONFIG_TRUE) {
		g_ac.standalone = ((configBool != 0) ? 1 : 0);
	}

	/* Set name of AC */
	if (config_lookup_string(config, "application.name", &configString) == CONFIG_TRUE) {
		if (strlen(configString) > CAPWAP_ACNAME_MAXLENGTH) {
			capwap_logging_error("Invalid configuration file, application.name string length exceeded");
			return 0;
		}

		capwap_free(g_ac.acname.name);
		g_ac.acname.name = (uint8_t*)capwap_duplicate_string(configString);
	}

	/* Set binding of AC */
	configSetting = config_lookup(config, "application.binding");
	if (configSetting != NULL) {
		int count = config_setting_length(configSetting);
		
		for (i = 0; i < count; i++) {
			const char* bindingName = config_setting_get_string_elem(configSetting, i);
			if (bindingName != NULL) {
				unsigned short* binding = (unsigned short*)capwap_array_get_item_pointer(g_ac.binding, g_ac.binding->count);

				if (!strcmp(bindingName, "802.11")) {
					*binding = CAPWAP_WIRELESS_BINDING_IEEE80211;
				} else if (!strcmp(bindingName, "EPCGlobal")) {
					*binding = CAPWAP_WIRELESS_BINDING_EPCGLOBAL;
				} else {
					capwap_logging_error("Invalid configuration file, unknown application.binding value");
					return 0;
				}
			}
		}
	}

	/* Set max stations of AC */
	if (config_lookup_int(config, "application.descriptor.maxstations", &configInt) == CONFIG_TRUE) {
		if ((configInt > 0) && (configInt < 65536)) {
			g_ac.descriptor.stationlimit = (unsigned short)configInt;
		} else {
			capwap_logging_error("Invalid configuration file, unknown application.descriptor.maxstations value");
			return 0;
		}
	}

	/* Set max wtp of AC */
	if (config_lookup_int(config, "application.descriptor.maxwtp", &configInt) == CONFIG_TRUE) {
		if ((configInt > 0) && (configInt < 65536)) {
			g_ac.descriptor.maxwtp = (unsigned short)configInt;
		} else {
			capwap_logging_error("Invalid configuration file, unknown application.descriptor.maxwtp value");
			return 0;
		}
	}

	/* Set security of AC */
	if (config_lookup(config, "application.descriptor.security") != NULL) {
		g_ac.descriptor.security = 0;
		if (config_lookup_bool(config, "application.descriptor.security.presharedkey", &configBool) == CONFIG_TRUE) {
			if (configBool != 0) {
				g_ac.descriptor.security |= CAPWAP_ACDESC_SECURITY_PRESHARED_KEY;
			}
		}

		if (config_lookup_bool(config, "application.descriptor.security.x509", &configBool) == CONFIG_TRUE) {
			if (configBool != 0) {
				g_ac.descriptor.security |= CAPWAP_ACDESC_SECURITY_X509_CERT;
			}
		}
	}

	/* Set rmacfiled of AC */
	if (config_lookup_bool(config, "application.descriptor.rmacfiled.supported", &configBool) == CONFIG_TRUE) {
		g_ac.descriptor.rmacfield = ((configBool != 0) ? CAPWAP_ACDESC_RMACFIELD_SUPPORTED : CAPWAP_ACDESC_RMACFIELD_NOTSUPPORTED);
	}

	/* Set DTLS policy of AC */
	if (config_lookup(config, "application.descriptor.dtlspolicy") != NULL) {
		g_ac.descriptor.dtlspolicy = 0;
		if (config_lookup_bool(config, "application.descriptor.dtlspolicy.cleardatachannel", &configBool) == CONFIG_TRUE) {
			if (configBool != 0) {
				g_ac.descriptor.dtlspolicy |= CAPWAP_ACDESC_CLEAR_DATA_CHANNEL_ENABLED;
			}
		}

		if (config_lookup_bool(config, "application.descriptor.dtlspolicy.dtlsdatachannel", &configBool) == CONFIG_TRUE) {
			if (configBool != 0) {
				g_ac.descriptor.dtlspolicy |= CAPWAP_ACDESC_DTLS_DATA_CHANNEL_ENABLED;
			}
		}
	}

	/* Set info descriptor of AC */
	configSetting = config_lookup(config, "application.descriptor.info");
	if (configSetting != NULL) {
		int count = config_setting_length(configSetting);

		for (i = 0; i < count; i++) {
			config_setting_t* configElement = config_setting_get_elem(configSetting, i);
			if (configElement != NULL) {
				LIBCONFIG_LOOKUP_INT_ARG configVendor;
				if (config_setting_lookup_int(configElement, "idvendor", &configVendor) == CONFIG_TRUE) {
					const char* configType;
					if (config_setting_lookup_string(configElement, "type", &configType) == CONFIG_TRUE) {
						const char* configValue;
						if (config_setting_lookup_string(configElement, "value", &configValue) == CONFIG_TRUE) {
							int lengthValue = strlen(configValue);
							if (lengthValue < CAPWAP_ACDESC_SUBELEMENT_MAXDATA) {
								unsigned short type;
								struct capwap_acdescriptor_desc_subelement* desc;

								if (!strcmp(configType, "hardware")) {
									type = CAPWAP_ACDESC_SUBELEMENT_HARDWAREVERSION;
								} else if (!strcmp(configType, "software")) {
									type = CAPWAP_ACDESC_SUBELEMENT_SOFTWAREVERSION;
								} else {
									capwap_logging_error("Invalid configuration file, unknown application.descriptor.info.type value");
									return 0;
								}

								desc = (struct capwap_acdescriptor_desc_subelement*)capwap_array_get_item_pointer(g_ac.descriptor.descsubelement, g_ac.descriptor.descsubelement->count);
								desc->vendor = (unsigned long)configVendor;
								desc->type = type;
								desc->length = lengthValue;

								desc->data = (uint8_t*)capwap_alloc(desc->length + 1);
								strcpy((char*)desc->data, configValue);
								desc->data[desc->length] = 0;
							} else {
								capwap_logging_error("Invalid configuration file, application.descriptor.info.value string length exceeded");
								return 0;
							}
						} else {
							capwap_logging_error("Invalid configuration file, element application.descriptor.info.value not found");
							return 0;
						}
					} else {
						capwap_logging_error("Invalid configuration file, element application.descriptor.info.type not found");
						return 0;
					}
				} else {
					capwap_logging_error("Invalid configuration file, element application.descriptor.info.idvendor not found");
					return 0;
				}
			}
		}
	}

	/* Set ECN of AC */
	if (config_lookup_string(config, "application.ecn", &configString) == CONFIG_TRUE) {
		if (!strcmp(configString, "full")) {
			g_ac.dfa.ecn.flag = CAPWAP_FULL_ECN_SUPPORT;
		} else if (!strcmp(configString, "limited")) {
			g_ac.dfa.ecn.flag = CAPWAP_LIMITED_ECN_SUPPORT;
		} else {
			capwap_logging_error("Invalid configuration file, unknown application.ecn value");
			return 0;
		}
	}

	/* Set Timer of AC */
	if (config_lookup_int(config, "application.timer.discovery", &configInt) == CONFIG_TRUE) {
		configInt *= 1000;		/* Set timeout in ms */
		if ((configInt >= AC_MIN_DISCOVERY_INTERVAL) && (configInt <= AC_MAX_DISCOVERY_INTERVAL)) {
			g_ac.dfa.timers.discovery = (unsigned char)(configInt / 1000);
		} else {
			capwap_logging_error("Invalid configuration file, invalid application.timer.discovery value");
			return 0;
		}
	}

	if (config_lookup_int(config, "application.timer.echorequest", &configInt) == CONFIG_TRUE) {
		configInt *= 1000;
		if ((configInt >= AC_MIN_ECHO_INTERVAL) && (configInt <= AC_MAX_ECHO_INTERVAL)) {
			g_ac.dfa.timers.echorequest = (unsigned char)(configInt / 1000);
		} else {
			capwap_logging_error("Invalid configuration file, invalid application.timer.echorequest value");
			return 0;
		}
	}

	if (config_lookup_int(config, "application.timer.decrypterrorreport", &configInt) == CONFIG_TRUE) {
		if ((configInt > 0) && (configInt < 65536)) {
			g_ac.dfa.decrypterrorreport_interval = (unsigned short)configInt;
		} else {
			capwap_logging_error("Invalid configuration file, invalid application.timer.decrypterrorreport value");
			return 0;
		}
	}

	if (config_lookup_int(config, "application.timer.idletimeout", &configInt) == CONFIG_TRUE) {
		if (configInt > 0) {
			g_ac.dfa.idletimeout.timeout = (unsigned long)configInt;
		} else {
			capwap_logging_error("Invalid configuration file, invalid application.timer.idletimeout value");
			return 0;
		}
	}

	/* Set wtpfallback of AC */
	if (config_lookup_bool(config, "application.wtpfallback", &configBool) == CONFIG_TRUE) {
		g_ac.dfa.wtpfallback.mode = ((configBool != 0) ? CAPWAP_WTP_FALLBACK_ENABLED : CAPWAP_WTP_FALLBACK_DISABLED);
	}

	/* Set DTLS of WTP */
	if (config_lookup_bool(config, "application.dtls.enable", &configBool) == CONFIG_TRUE) {
		if (configBool != 0) {
			struct capwap_dtls_param dtlsparam;

			/* Init dtls param */
			memset(&dtlsparam, 0, sizeof(struct capwap_dtls_param));
			dtlsparam.type = CAPWAP_DTLS_SERVER;

			/* Set DTLS type of AC */
			if (config_lookup_string(config, "application.dtls.type", &configString) == CONFIG_TRUE) {
				if (!strcmp(configString, "x509")) {
					dtlsparam.mode = CAPWAP_DTLS_MODE_CERTIFICATE;
				} else if (!strcmp(configString, "presharedkey")) {
					dtlsparam.mode = CAPWAP_DTLS_MODE_PRESHAREDKEY;
				} else {
					capwap_logging_error("Invalid configuration file, unknown application.dtls.type value");
					return 0;
				}
			}

			/* Set DTLS configuration of AC */
			if (dtlsparam.mode == CAPWAP_DTLS_MODE_CERTIFICATE) {
				if (config_lookup_string(config, "application.dtls.x509.calist", &configString) == CONFIG_TRUE) {
					if (strlen(configString) > 0) {
						dtlsparam.cert.fileca = capwap_duplicate_string(configString);
					}
				}

				if (config_lookup_string(config, "application.dtls.x509.certificate", &configString) == CONFIG_TRUE) {
					if (strlen(configString) > 0) {
						dtlsparam.cert.filecert = capwap_duplicate_string(configString);
					}
				}

				if (config_lookup_string(config, "application.dtls.x509.privatekey", &configString) == CONFIG_TRUE) {
					if (strlen(configString) > 0) {
						dtlsparam.cert.filekey = capwap_duplicate_string(configString);
					}
				}

				if (dtlsparam.cert.fileca && dtlsparam.cert.filecert && dtlsparam.cert.filekey) {
					if (capwap_crypt_createcontext(&g_ac.dtlscontext, &dtlsparam)) {
						g_ac.enabledtls = 1;
					}
				}

				/* Free dtls param */
				if (dtlsparam.cert.fileca) {
					capwap_free(dtlsparam.cert.fileca);
				}
				
				if (dtlsparam.cert.filecert) {
					capwap_free(dtlsparam.cert.filecert);
				}
				
				if (dtlsparam.cert.filekey) {
					capwap_free(dtlsparam.cert.filekey);
				}
			} else if (dtlsparam.mode == CAPWAP_DTLS_MODE_PRESHAREDKEY) {
				if (config_lookup_string(config, "application.dtls.presharedkey.hint", &configString) == CONFIG_TRUE) {
					if (strlen(configString) > 0) {
						dtlsparam.presharedkey.hint = capwap_duplicate_string(configString);
					}
				}

				if (config_lookup_string(config, "application.dtls.presharedkey.identity", &configString) == CONFIG_TRUE) {
					if (strlen(configString) > 0) {
						dtlsparam.presharedkey.identity = capwap_duplicate_string(configString);
					}
				}

				if (config_lookup_string(config, "application.dtls.presharedkey.pskkey", &configString) == CONFIG_TRUE) {
					if (strlen(configString) > 0) {
						/* TODO controllare se è un valore hex */
						dtlsparam.presharedkey.pskkey = capwap_duplicate_string(configString);
					}
				}

				/* */
				if (dtlsparam.presharedkey.identity && dtlsparam.presharedkey.pskkey) {
					if (capwap_crypt_createcontext(&g_ac.dtlscontext, &dtlsparam)) {
						g_ac.enabledtls = 1;
					}
				}

				/* Free dtls param */
				if (dtlsparam.presharedkey.hint) {
					capwap_free(dtlsparam.presharedkey.hint);
				}

				if (dtlsparam.presharedkey.identity) {
					capwap_free(dtlsparam.presharedkey.identity);
				}

				if (dtlsparam.presharedkey.pskkey) {
					capwap_free(dtlsparam.presharedkey.pskkey);
				}
			}

			if (!g_ac.enabledtls) {
				return 0;
			}
		}
	}

	/* Set interface binding of AC */
	if (config_lookup_string(config, "application.network.binding", &configString) == CONFIG_TRUE) {
		if (strlen(configString) > (IFNAMSIZ - 1)) {
			capwap_logging_error("Invalid configuration file, application.network.binding string length exceeded");
			return 0;
		}			
			
		strcpy(g_ac.net.bind_interface, configString);
	}

	/* Set mtu of AC */
	if (config_lookup_int(config, "application.network.mtu", &configInt) == CONFIG_TRUE) {
		if ((configInt > 0) && (configInt < 65536)) {
			g_ac.mtu = (unsigned short)configInt;
		} else {
			capwap_logging_error("Invalid configuration file, invalid application.network.mtu value");
			return 0;
		}
	}

	/* Set network port of WTP */
	if (config_lookup_int(config, "application.network.port", &configInt) == CONFIG_TRUE) {
		if ((configInt > 0) && (configInt < 65535)) {
			g_ac.net.bind_sock_ctrl_port = (unsigned short)configInt;
		} else {
			capwap_logging_error("Invalid configuration file, invalid application.network.port value");
			return 0;
		}
	}

	/* Set transport of AC */
	if (config_lookup_string(config, "application.network.transport", &configString) == CONFIG_TRUE) {
		if (!strcmp(configString, "udp")) {
			g_ac.dfa.transport.type = CAPWAP_UDP_TRANSPORT;
		} else if (!strcmp(configString, "udplite")) {
			g_ac.dfa.transport.type = CAPWAP_UDPLITE_TRANSPORT;
		} else {
			capwap_logging_error("Invalid configuration file, unknown application.network.transport value");
			return 0;
		}
	}

	/* Set ipv4 & ipv6 of AC */
	if (config_lookup_bool(config, "application.network.ipv4", &configIPv4) != CONFIG_TRUE) {
		configIPv4 = 1;
	}

	if (config_lookup_bool(config, "application.network.ipv6", &configIPv6) != CONFIG_TRUE) {
		configIPv6 = 1;
	}
	
	if (configIPv4 && configIPv6) {
		g_ac.net.sock_family = AF_UNSPEC;
	} else if (!configIPv4 && !configIPv6) {
		capwap_logging_error("Invalid configuration file, request enable application.network.ipv4 or application.network.ipv6");
		return 0;
	} else {
		g_ac.net.sock_family = (configIPv4 ? AF_INET : AF_INET6);
	}

	/* Set ip dual stack of WTP */
	if (config_lookup_bool(config, "application.network.ipdualstack", &configBool) == CONFIG_TRUE) {
		if (!configBool) {
			g_ac.net.bind_ctrl_flags |= CAPWAP_IPV6ONLY_FLAG;
			g_ac.net.bind_data_flags |= CAPWAP_IPV6ONLY_FLAG;
		} else {
			g_ac.net.bind_ctrl_flags &= ~CAPWAP_IPV6ONLY_FLAG;
			g_ac.net.bind_data_flags &= ~CAPWAP_IPV6ONLY_FLAG;
		}
	}

	/* Backend */
	if (config_lookup_string(config, "backend.id", &configString) == CONFIG_TRUE) {
		if (strlen(configString) > 0) {
			g_ac.backendacid = capwap_duplicate_string(configString);
		}
	}

	if (config_lookup_string(config, "backend.version", &configString) == CONFIG_TRUE) {
		if (strlen(configString) > 0) {
			g_ac.backendversion = capwap_duplicate_string(configString);
		}
	}

	configSetting = config_lookup(config, "backend.server");
	if (configSetting) {
		int count = config_setting_length(configSetting);

		/* Retrieve server */
		for (i = 0; i < count; i++) {
			config_setting_t* configServer = config_setting_get_elem(configSetting, i);
			if (configServer != NULL) {
				if (config_setting_lookup_string(configServer, "url", &configString) == CONFIG_TRUE) {
					struct ac_http_soap_server* server;
					struct ac_http_soap_server** itemserver;

					/* */
					server = ac_soapclient_create_server(configString);
					if (!server) {
						capwap_logging_error("Invalid configuration file, invalid backend.server value");
						return 0;
					}

					/* HTTPS params */
					if (server->protocol == SOAP_HTTPS_PROTOCOL) {
						char* calist = NULL;
						char* certificate = NULL;
						char* privatekey = NULL;
						config_setting_t* configSSL;

						/* */
						configSSL = config_setting_get_member(configServer, "x509");
						if (!configSSL) {
							capwap_logging_error("Invalid configuration file, invalid backend.server.x509 value");
							return 0;
						}

						if (config_setting_lookup_string(configSSL, "calist", &configString) == CONFIG_TRUE) {
							if (strlen(configString) > 0) {
								calist = capwap_duplicate_string(configString);
							}
						}

						if (config_setting_lookup_string(configSSL, "certificate", &configString) == CONFIG_TRUE) {
							if (strlen(configString) > 0) {
								certificate = capwap_duplicate_string(configString);
							}
						}

						if (config_setting_lookup_string(configSSL, "privatekey", &configString) == CONFIG_TRUE) {
							if (strlen(configString) > 0) {
								privatekey = capwap_duplicate_string(configString);
							}
						}

						/* */
						if (calist && certificate && privatekey) {
							server->sslcontext = capwap_socket_crypto_createcontext(calist, certificate, privatekey);
							if (!server->sslcontext) {
								capwap_logging_error("Invalid configuration file, unable to initialize crypto library");
								return 0;
							}
						} else {
							capwap_logging_error("Invalid configuration file, invalid backend.server.x509 value");
							return 0;
						}

						/* Free SSL param */
						capwap_free(calist);
						capwap_free(certificate);
						capwap_free(privatekey);
					}

					/* Add item */
					itemserver = (struct ac_http_soap_server**)capwap_array_get_item_pointer(g_ac.availablebackends, g_ac.availablebackends->count);
					*itemserver= server;
				}
			}
		}
	}

	return 1;
}

/* Parsing configuration */
static int ac_parsing_configuration(config_t* config) {
	const char* configString;
	
	if (config_lookup_string(config, "version", &configString) == CONFIG_TRUE) {
		if (strcmp(configString, "1.0") == 0) {
			return ac_parsing_configuration_1_0(config);
		}
		
		capwap_logging_error("Invalid configuration file, '%s' is not supported", configString);
	} else {
		capwap_logging_error("Invalid configuration file, unable to found version tag");
	}

	return 0;
}


/* Load configuration */
static int ac_load_configuration(int argc, char** argv) {
	int c;
	int result = 0;
	config_t config;
	
	ASSERT(argc >= 0);
	ASSERT(argv != NULL);
	
	/* Parsing command line */
	opterr = 0;
	while ((c = getopt(argc, argv, "hc:")) != -1) {
		switch (c) {
			case 'h': {
				ac_print_usage();
				return 0;
			}
			
			case 'c': {
				if (strlen(optarg) < sizeof(g_configurationfile)) {
					strcpy(g_configurationfile, optarg);
				} else {
					capwap_logging_error("Invalid -%c argument", optopt);
					return -1;
				}
				
				break;
			}
				
			case '?': {
				if (optopt == 'c') {
					capwap_logging_error("Option -%c requires an argument", optopt);
				} else {
					capwap_logging_error("Unknown option character `\\x%x'", optopt);
				}
				
				ac_print_usage();
				return -1;
			}
		}
	}

	/* Init libconfig */
	config_init(&config);

	/* Load configuration */
	if (config_read_file(&config, g_configurationfile) == CONFIG_TRUE) {
		result = ac_parsing_configuration(&config);
	} else {
		result = -1;
		capwap_logging_error("Unable load the configuration file '%s': %s (%d)", g_configurationfile, config_error_text(&config), config_error_line(&config));
	}

	/* Free libconfig */
	config_destroy(&config);
	return result;	
}

/* Init AC */
static int ac_configure(void) {
	/* Bind to any address */
	if (!capwap_bind_sockets(&g_ac.net)) {
		capwap_logging_fatal("Cannot bind address");
		return AC_ERROR_NETWORK;
	}

	return CAPWAP_SUCCESSFUL;
}

/* Close AC */
static void ac_close(void) {
	ASSERT(g_ac.sessions->count == 0);
	
	/* Close socket */
	capwap_close_sockets(&g_ac.net);
}

/* Check is valid binding */
int ac_valid_binding(unsigned short binding) {
	int i;
	
	for (i = 0; i < g_ac.binding->count; i++) {
		if (binding == *(unsigned short*)capwap_array_get_item_pointer(g_ac.binding, i)) {
			return 1;
		}
	}
	
	return 0;
}

/* Main*/
int main(int argc, char** argv) {
	int value;
	int result = CAPWAP_SUCCESSFUL;

	/* Init logging */
	capwap_logging_init();
	capwap_logging_verboselevel(CAPWAP_LOGGING_ERROR);
	capwap_logging_enable_console(1);

	/* Init capwap */
	if (geteuid() != 0) {
		capwap_logging_fatal("Request root privileges");
		return CAPWAP_REQUEST_ROOT;
	}
	
	/* Init random generator */
	capwap_init_rand();

	/* Init crypt */
	if (capwap_crypt_init()) {
		capwap_logging_fatal("Error to init crypt engine");
		return CAPWAP_CRYPT_ERROR;
	}

	/* Init soap module */
	ac_soapclient_init();

	/* Alloc AC */
	if (!ac_init()) {
		return AC_ERROR_SYSTEM_FAILER;
	}

	/* Read configuration file */
	value = ac_load_configuration(argc, argv);
	if (value < 0) {
		result = AC_ERROR_LOAD_CONFIGURATION;
	} else if (value > 0) {
		if (!g_ac.standalone) {
			capwap_daemon();

			/* Console logging is disabled in daemon mode */
			capwap_logging_disable_console();
			capwap_logging_info("Running AC in daemon mode");
		}

		/* Complete configuration AC */
		result = ac_configure();
		if (result == CAPWAP_SUCCESSFUL) {
			/* Connect AC to kernel module */
			value = ac_kmod_init();
			if (!value || !g_ac.kmodrequest) {
				if (ac_kmod_isconnected()) {
					capwap_logging_info("SmartCAPWAP kernel module connected");
				}

				/* Running AC */
				result = ac_execute();

				/* Close connection */
				ac_close();

				/* Disconnect kernel module */
				ac_kmod_free();
			} else {
				capwap_logging_fatal("Unable to connect to kernel module");
			}
		}
	}

	/* Free memory */
	ac_destroy();

	/* Free soap */
	ac_soapclient_free();

	/* Free crypt */
	capwap_crypt_free();

	/* Check memory leak */
	if (capwap_check_memory_leak(1)) {
		if (result == CAPWAP_SUCCESSFUL)
			result = AC_ERROR_MEMORY_LEAK;
	}
	
	/* Close logging */
	capwap_logging_close();

	return result;
}
