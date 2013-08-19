#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"
#include <json/json.h>
#include <arpa/inet.h>

/* */
static struct ac_soap_response* ac_dfa_state_configure_parsing_request(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	int i;
	const char* jsonmessage;
	char* base64confstatus;
	struct json_object* jsonarray;
	struct json_object* jsonparam;
	struct json_object* jsonhash;
	struct capwap_array* elemarray;
	struct capwap_statisticstimer_element* statisticstimer;
	struct capwap_wtprebootstat_element* wtprebootstat;
	struct capwap_wtpstaticipaddress_element* wtpstaticipaddress;
	struct ac_soap_response* response;

	/* Create SOAP request with JSON param
		{
			RadioAdministrativeState: [
				{
					RadioID: [int],
					AdminState: [int]
				}
			],
			StatisticsTimer: {
				StatisticsTimer: [int]
			},
			WTPRebootStatistics: {
				RebootCount: [int],
				ACInitiatedCount: [int],
				LinkFailureCount: [int],
				SWFailureCount: [int],
				HWFailureCount: [int],
				OtherFailureCount: [int],
				UnknownFailureCount: [int],
				LastFailureType: [int]
			},
			ACNamePriority: [
				{
					Priority: [int],
					ACName: [string]
				}
			],
			WTPStaticIPAddressInformation: {
				IPAddress: [string],
				Netmask: [string],
				Gateway: [string],
				Static: [int]
			}
		}
	*/

	/* */
	jsonparam = json_object_new_object();

	/* RadioAdministrativeState */
	jsonarray = json_object_new_array();
	elemarray = (struct capwap_array*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RADIOADMSTATE);
	for (i = 0; i < elemarray->count; i++) {
		struct json_object* jsonradioadm;
		struct capwap_radioadmstate_element* radioadm = *(struct capwap_radioadmstate_element**)capwap_array_get_item_pointer(elemarray, i);

		/* */
		jsonradioadm = json_object_new_object();
		json_object_object_add(jsonradioadm, "RadioID", json_object_new_int((int)radioadm->radioid));
		json_object_object_add(jsonradioadm, "AdminState", json_object_new_int((int)radioadm->state));
		json_object_array_add(jsonarray, jsonradioadm);
	}

	json_object_object_add(jsonparam, "RadioAdministrativeState", jsonarray);

	/* StatisticsTimer */
	statisticstimer = (struct capwap_statisticstimer_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_STATISTICSTIMER);

	jsonhash = json_object_new_object();
	json_object_object_add(jsonhash, "StatisticsTimer", json_object_new_int((int)statisticstimer->timer));
	json_object_object_add(jsonparam, "StatisticsTimer", jsonhash);

	/* WTPRebootStatistics */
	wtprebootstat = (struct capwap_wtprebootstat_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_WTPREBOOTSTAT);

	jsonhash = json_object_new_object();
	json_object_object_add(jsonhash, "RebootCount", json_object_new_int((int)wtprebootstat->rebootcount));
	json_object_object_add(jsonhash, "ACInitiatedCount", json_object_new_int((int)wtprebootstat->acinitiatedcount));
	json_object_object_add(jsonhash, "LinkFailureCount", json_object_new_int((int)wtprebootstat->linkfailurecount));
	json_object_object_add(jsonhash, "SWFailureCount", json_object_new_int((int)wtprebootstat->swfailurecount));
	json_object_object_add(jsonhash, "HWFailureCount", json_object_new_int((int)wtprebootstat->hwfailurecount));
	json_object_object_add(jsonhash, "OtherFailureCount", json_object_new_int((int)wtprebootstat->otherfailurecount));
	json_object_object_add(jsonhash, "UnknownFailureCount", json_object_new_int((int)wtprebootstat->unknownfailurecount));
	json_object_object_add(jsonhash, "LastFailureType", json_object_new_int((int)wtprebootstat->lastfailuretype));
	json_object_object_add(jsonparam, "WTPRebootStatistics", jsonhash);

	/* ACNamePriority */
	elemarray = (struct capwap_array*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_ACNAMEPRIORITY);
	if (elemarray && elemarray->count) {
		jsonarray = json_object_new_array();
		for (i = 0; i < elemarray->count; i++) {
			json_object* jacname;
			struct capwap_acnamepriority_element* acname = *(struct capwap_acnamepriority_element**)capwap_array_get_item_pointer(elemarray, i);

			/* */
			jacname = json_object_new_object();
			json_object_object_add(jacname, "Priority", json_object_new_int((int)acname->priority));
			json_object_object_add(jacname, "ACName", json_object_new_string((char*)acname->name));
			json_object_array_add(jsonarray, jacname);
		}

		json_object_object_add(jsonparam, "ACNamePriority", jsonarray);
	}

	/* WTPStaticIPAddressInformation */
	wtpstaticipaddress = (struct capwap_wtpstaticipaddress_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_WTPSTATICIPADDRESS);
	if (wtpstaticipaddress) {
		char ipbuffer[INET_ADDRSTRLEN];

		/* */
		jsonhash = json_object_new_object();
		json_object_object_add(jsonhash, "IPAddress", json_object_new_string(inet_ntop(AF_INET, (void*)&wtpstaticipaddress->address, ipbuffer, INET_ADDRSTRLEN)));
		json_object_object_add(jsonhash, "Netmask", json_object_new_string(inet_ntop(AF_INET, (void*)&wtpstaticipaddress->netmask, ipbuffer, INET_ADDRSTRLEN)));
		json_object_object_add(jsonhash, "Gateway", json_object_new_string(inet_ntop(AF_INET, (void*)&wtpstaticipaddress->gateway, ipbuffer, INET_ADDRSTRLEN)));
		json_object_object_add(jsonhash, "Static", json_object_new_int((int)wtpstaticipaddress->staticip));
		json_object_object_add(jsonparam, "WTPStaticIPAddressInformation", jsonhash);
	}

	/* Get JSON param and convert base64 */
	jsonmessage = json_object_to_json_string(jsonparam);
	base64confstatus = capwap_alloc(AC_BASE64_ENCODE_LENGTH(strlen(jsonmessage)));
	ac_base64_string_encode(jsonmessage, base64confstatus);

	/* Send message */
	response = ac_soap_configurestatusevent(session, session->wtpid, base64confstatus);

	/* Free JSON */
	json_object_put(jsonparam);
	capwap_free(base64confstatus);

	return response;
}

/* */
static uint32_t ac_dfa_state_configure_create_response(struct ac_session_t* session, struct capwap_parsed_packet* packet, struct ac_soap_response* response, struct capwap_packet_txmng* txmngpacket) {
	int length;
	char* json;
	unsigned long i;
	xmlChar* xmlResult;
	struct json_object* jsonroot;
	struct json_object* jsonelement;
	struct capwap_array* radioadmstate;
	struct capwap_timers_element responsetimers;
	struct capwap_idletimeout_element responseidletimeout;
	struct capwap_wtpfallback_element responsewtpfallback;

	if ((response->responsecode != HTTP_RESULT_OK) || !response->xmlResponseReturn) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Receive SOAP response with JSON result
		{
			CAPWAPTimers: {
				Discovery: [int],
				EchoRequest: [int]
			},
			DecryptionErrorReportPeriod: [
				{
					RadioID: [int],
					ReportInterval: [int]
				}
			],
			IdleTimeout: {
				Timeout: [int]
			},
			WTPFallback: {
				Mode: [int]
			}
			ACIPv4List: [
				{
					ACIPAddress: [string]
				}
			],
			ACIPv6List: [
				{
					ACIPAddress: [string]
				}
			]
			WTPStaticIPAddressInformation: {
				IPAddress: [string],
				Netmask: [string],
				Gateway: [string],
				Static: [int]
			}
		}
	*/

	/* Decode base64 result */
	xmlResult = xmlNodeGetContent(response->xmlResponseReturn);
	if (!xmlResult) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	length = xmlStrlen(xmlResult);
	if (!length) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	json = (char*)capwap_alloc(AC_BASE64_DECODE_LENGTH(length));
	ac_base64_string_decode((const char*)xmlResult, json);

	xmlFree(xmlResult);

	/* Parsing JSON result */
	jsonroot = json_tokener_parse(json);
	capwap_free(json);

	/* Add message elements response, every local value can be overwrite from backend server */

	/* CAPWAP Timers */
	memcpy(&responsetimers, &session->dfa.timers, sizeof(struct capwap_timers_element));
	if (jsonroot) {
		jsonelement = json_object_object_get(jsonroot, "CAPWAPTimers");
		if (jsonelement && (json_object_get_type(jsonelement) == json_type_object)) {
			struct json_object* jsonitem;

			/* Discovery */
			jsonitem = json_object_object_get(jsonelement, "Discovery");
			if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
				int value = json_object_get_int(jsonitem);
				if ((value > 0) && (value < 256)) {
					responsetimers.discovery = (uint8_t)value;
				}
			}

			/* EchoRequest */
			jsonitem = json_object_object_get(jsonelement, "EchoRequest");
			if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
				int value = json_object_get_int(jsonitem);
				if ((value > 0) && (value < 256)) {
					responsetimers.echorequest = (uint8_t)value;
				}
			}
		}
	}

	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_TIMERS, &responsetimers);

	/* Decryption Error Report Period */
	jsonelement = NULL;
	if (jsonroot) {
		jsonelement = json_object_object_get(jsonroot, "DecryptionErrorReportPeriod");
		if (jsonelement && (json_object_get_type(jsonelement) == json_type_array)) {
			length = json_object_array_length(jsonelement);
		} else {
			jsonelement = NULL;
		}
	}

	/* Build Decryption Error Report Period List with elements of Radio Administration State */
	radioadmstate = (struct capwap_array*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RADIOADMSTATE);
	for (i = 0; i < radioadmstate->count; i++) {
		struct capwap_decrypterrorreportperiod_element report;
		struct capwap_radioadmstate_element* radioadm = *(struct capwap_radioadmstate_element**)capwap_array_get_item_pointer(radioadmstate, i);

		report.radioid = radioadm->radioid;
		report.interval = session->dfa.decrypterrorreport_interval;

		/* Search for JSON overwrite value */
		if (jsonelement) {
			int j;

			for (j = 0; j < length; j++) {
				struct json_object* jsonvalue = json_object_array_get_idx(jsonelement, i);
				if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_object)) {
					struct json_object* jsonitem;
		
					/* RadioID */
					jsonitem = json_object_object_get(jsonvalue, "RadioID");
					if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
						int value = json_object_get_int(jsonitem);
						if ((value > 0) && (value < 256) && ((uint8_t)value == report.radioid)) {
							/* Get ReportInterval value */
							jsonitem = json_object_object_get(jsonvalue, "ReportInterval");
							if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
								value = json_object_get_int(jsonitem);
								if ((value > 0) && (value < 65536)) {
									report.interval = (uint16_t)value;
									break;
								}
							}
						}
					}
				}
			}
		}

		/* */
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD, &report);
	}

	/* IdleTimeout */
	memcpy(&responseidletimeout, &session->dfa.idletimeout, sizeof(struct capwap_idletimeout_element));
	if (jsonroot) {
		jsonelement = json_object_object_get(jsonroot, "IdleTimeout");
		if (jsonelement && (json_object_get_type(jsonelement) == json_type_object)) {
			struct json_object* jsonitem;

			/* Timeout */
			jsonitem = json_object_object_get(jsonelement, "Timeout");
			if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
				int value = json_object_get_int(jsonitem);
				if (value > 0) {
					responseidletimeout.timeout = (uint32_t)value;
				}
			}
		}
	}

	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_IDLETIMEOUT, &responseidletimeout);

	/* WTPFallback */
	memcpy(&responsewtpfallback, &session->dfa.wtpfallback, sizeof(struct capwap_wtpfallback_element));
	if (jsonroot) {
		jsonelement = json_object_object_get(jsonroot, "WTPFallback");
		if (jsonelement && (json_object_get_type(jsonelement) == json_type_object)) {
			struct json_object* jsonitem;

			/* Mode */
			jsonitem = json_object_object_get(jsonelement, "Mode");
			if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
				int value = json_object_get_int(jsonitem);
				if ((value > 0) && (value < 256)) {
					responsewtpfallback.mode = (uint8_t)value;
				}
			}
		}
	}

	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPFALLBACK, &responsewtpfallback);

	/* ACIPv4List */
	jsonelement = NULL;
	if (jsonroot) {
		jsonelement = json_object_object_get(jsonroot, "ACIPv4List");
		if (jsonelement && (json_object_get_type(jsonelement) == json_type_array)) {
			length = json_object_array_length(jsonelement);
		} else {
			jsonelement = NULL;
		}
	}

	if (jsonelement) {
		int j;
		struct capwap_acipv4list_element* responseacipv4list;

		responseacipv4list = (struct capwap_acipv4list_element*)capwap_alloc(sizeof(struct capwap_acipv4list_element));
		responseacipv4list->addresses = capwap_array_create(sizeof(struct in_addr), 0, 0);

		for (j = 0; j < length; j++) {
			struct json_object* jsonvalue = json_object_array_get_idx(jsonelement, i);
			if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_object)) {
				struct json_object* jsonitem;
	
				/* ACIPAddress */
				jsonitem = json_object_object_get(jsonvalue, "ACIPAddress");
				if (jsonitem && (json_object_get_type(jsonitem) == json_type_string)) {
					const char* value = json_object_get_string(jsonitem);
					if (value) {
						struct sockaddr_storage address;
						if (capwap_address_from_string(value, &address)) {
							/* Accept only IPv4 address */
							if (address.ss_family == AF_INET) {
								struct sockaddr_in* address_in = (struct sockaddr_in*)&address;
								struct in_addr* responseaddress_in = (struct in_addr*)capwap_array_get_item_pointer(responseacipv4list->addresses, responseacipv4list->addresses->count);
								memcpy(responseaddress_in, &address_in->sin_addr, sizeof(struct in_addr));
							}
						}
					}
				}
			}
		}

		if (responseacipv4list->addresses->count > 0) {
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ACIPV4LIST, responseacipv4list);
		}

		capwap_array_free(responseacipv4list->addresses);
		capwap_free(responseacipv4list);
	} else if (session->dfa.acipv4list.addresses->count > 0) {
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ACIPV4LIST, &session->dfa.acipv4list);
	}

	/* ACIPv6List */
	jsonelement = NULL;
	if (jsonroot) {
		jsonelement = json_object_object_get(jsonroot, "ACIPv6List");
		if (jsonelement && (json_object_get_type(jsonelement) == json_type_array)) {
			length = json_object_array_length(jsonelement);
		} else {
			jsonelement = NULL;
		}
	}

	if (jsonelement) {
		int j;
		struct capwap_acipv6list_element* responseacipv6list;

		responseacipv6list = (struct capwap_acipv6list_element*)capwap_alloc(sizeof(struct capwap_acipv6list_element));
		responseacipv6list->addresses = capwap_array_create(sizeof(struct in6_addr), 0, 0);

		for (j = 0; j < length; j++) {
			struct json_object* jsonvalue = json_object_array_get_idx(jsonelement, i);
			if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_object)) {
				struct json_object* jsonitem;
	
				/* ACIPAddress */
				jsonitem = json_object_object_get(jsonvalue, "ACIPAddress");
				if (jsonitem && (json_object_get_type(jsonitem) == json_type_string)) {
					const char* value = json_object_get_string(jsonitem);
					if (value) {
						struct sockaddr_storage address;
						if (capwap_address_from_string(value, &address)) {
							/* Accept only IPv6 address */
							if (address.ss_family == AF_INET6) {
								struct sockaddr_in6* address_in6 = (struct sockaddr_in6*)&address;
								struct in6_addr* responseaddress_in6 = (struct in6_addr*)capwap_array_get_item_pointer(responseacipv6list->addresses, responseacipv6list->addresses->count);
								memcpy(responseaddress_in6, &address_in6->sin6_addr, sizeof(struct in6_addr));
							}
						}
					}
				}
			}
		}

		if (responseacipv6list->addresses->count > 0) {
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ACIPV6LIST, responseacipv6list);
		}

		capwap_array_free(responseacipv6list->addresses);
		capwap_free(responseacipv6list);
	} else if (session->dfa.acipv6list.addresses->count > 0) {
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ACIPV6LIST, &session->dfa.acipv6list);
	}

	/* WTPStaticIPAddressInformation */
	if (jsonroot) {
		jsonelement = json_object_object_get(jsonroot, "WTPStaticIPAddressInformation");
		if (jsonelement && (json_object_get_type(jsonelement) == json_type_object)) {
			struct json_object* jsonitem;

			/* IPAddress */
			jsonitem = json_object_object_get(jsonelement, "IPAddress");
			if (jsonitem && (json_object_get_type(jsonitem) == json_type_string)) {
				struct sockaddr_storage address;
				const char* addressvalue = json_object_get_string(jsonitem);

				if (capwap_address_from_string(addressvalue, &address)) {
					if (address.ss_family == AF_INET) {
						/* Netmask */
						jsonitem = json_object_object_get(jsonelement, "Netmask");
						if (jsonitem && (json_object_get_type(jsonitem) == json_type_string)) {
							struct sockaddr_storage netmask;
							const char* netmaskvalue = json_object_get_string(jsonitem);

							if (capwap_address_from_string(netmaskvalue, &netmask)) {
								if (netmask.ss_family == AF_INET) {
									/* Gateway */
									jsonitem = json_object_object_get(jsonelement, "Gateway");
									if (jsonitem && (json_object_get_type(jsonitem) == json_type_string)) {
										struct sockaddr_storage gateway;
										const char* gatewayvalue = json_object_get_string(jsonitem);

										if (capwap_address_from_string(gatewayvalue, &gateway)) {
											if (gateway.ss_family == AF_INET) {
												/* Static */
												jsonitem = json_object_object_get(jsonelement, "Static");
												if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
													int value = json_object_get_int(jsonitem);
													struct capwap_wtpstaticipaddress_element responsewtpstaticipaddress;

													memcpy(&responsewtpstaticipaddress.address, &((struct sockaddr_in*)&address)->sin_addr, sizeof(struct in_addr));
													memcpy(&responsewtpstaticipaddress.netmask, &((struct sockaddr_in*)&netmask)->sin_addr, sizeof(struct in_addr));
													memcpy(&responsewtpstaticipaddress.gateway, &((struct sockaddr_in*)&gateway)->sin_addr, sizeof(struct in_addr));
													responsewtpstaticipaddress.staticip = (uint8_t)value;

													capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPSTATICIPADDRESS, &responsewtpstaticipaddress);
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */		/* TODO */

	if (jsonroot) {
		json_object_put(jsonroot);
	}

	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
int ac_dfa_state_configure(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);
	
	if (packet) {
		struct ac_soap_response* response;
		uint32_t result = CAPWAP_RESULTCODE_FAILURE;

		/* Create response */
		capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, GET_WBID_HEADER(packet->rxmngpacket->header));
		txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_CONFIGURATION_STATUS_RESPONSE, packet->rxmngpacket->ctrlmsg.seq, session->mtu);

		/* Parsing request and add message element for respone message */
		response = ac_dfa_state_configure_parsing_request(session, packet);
		if (response) {
			result = ac_dfa_state_configure_create_response(session, packet, response, txmngpacket);
			ac_soapclient_free_response(response);
		}

		/* With error add result code message element */
		if (!CAPWAP_RESULTCODE_OK(result)) {
			struct capwap_resultcode_element resultcode = { .code = result };
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RESULTCODE, &resultcode);

			/* */
			if (result == CAPWAP_RESULTCODE_FAILURE) {
				/* TODO: Add AC List Message Elements */
			}
		}

		/* Configure response complete, get fragment packets */
		ac_free_reference_last_response(session);
		capwap_packet_txmng_get_fragment_packets(txmngpacket, session->responsefragmentpacket, session->fragmentid);
		if (session->responsefragmentpacket->count > 1) {
			session->fragmentid++;
		}

		/* Free packets manager */
		capwap_packet_txmng_free(txmngpacket);

		/* Save remote sequence number */
		session->remoteseqnumber = packet->rxmngpacket->ctrlmsg.seq;
		capwap_get_packet_digest(packet->rxmngpacket, packet->connection, session->lastrecvpackethash);

		/* Send Configure response to WTP */
		if (!capwap_crypt_sendto_fragmentpacket(&session->ctrldtls, session->ctrlsocket.socket[session->ctrlsocket.type], session->responsefragmentpacket, &session->acctrladdress, &session->wtpctrladdress)) {
			/* Response is already created and saved. When receive a re-request, DFA autoresponse */
			capwap_logging_debug("Warning: error to send configuration status response packet");
		}

		/* Change state */
		if (CAPWAP_RESULTCODE_OK(result)) {
			ac_dfa_change_state(session, CAPWAP_DATA_CHECK_STATE);
			capwap_set_timeout(session->dfa.rfcChangeStatePendingTimer, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		} else {
			ac_dfa_change_state(session, CAPWAP_CONFIGURE_TO_DTLS_TEARDOWN_STATE);
			status = AC_DFA_NO_PACKET;
		}
	} else {
		/* Configure timeout */
		ac_dfa_change_state(session, CAPWAP_CONFIGURE_TO_DTLS_TEARDOWN_STATE);
		status = AC_DFA_NO_PACKET;
	}

	return status;
}

/* */
int ac_dfa_state_configure_to_dtlsteardown(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	return ac_session_teardown_connection(session);
}
