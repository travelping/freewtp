#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "capwap_array.h"
#include "ac_session.h"
#include "ac_wlans.h"

/* */
static int receive_echo_request(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	int validsession = 0;
	struct ac_soap_response* response;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;

	/* Check session */
	response = ac_soap_checkwtpsession(session, session->wtpid);
	if (response) {
		if ((response->responsecode == HTTP_RESULT_OK) && response->xmlResponseReturn) {
			xmlChar* xmlResult = xmlNodeGetContent(response->xmlResponseReturn);
			if (xmlResult) {
				if (!xmlStrcmp(xmlResult, (const xmlChar *)"true")) {
					validsession = 1;
				}

				xmlFree(xmlResult);
			}
		}

		ac_soapclient_free_response(response);
	}

	if (!validsession) {
		return -1;
	}

	/* Create response */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, GET_WBID_HEADER(packet->rxmngpacket->header));
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_ECHO_RESPONSE, packet->rxmngpacket->ctrlmsg.seq, session->mtu);

	/* Add message element */
	/* CAPWAP_ELEMENT_VENDORPAYLOAD */				/* TODO */

	/* Echo response complete, get fragment packets */
	ac_free_reference_last_response(session);
	capwap_packet_txmng_get_fragment_packets(txmngpacket, session->responsefragmentpacket, session->fragmentid);
	if (session->responsefragmentpacket->count > 1) {
		session->fragmentid++;
	}

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Save remote sequence number */
	session->remotetype = packet->rxmngpacket->ctrlmsg.type;
	session->remoteseqnumber = packet->rxmngpacket->ctrlmsg.seq;

#ifdef DEBUG
	{
		char sessionname[33];
		capwap_sessionid_printf(&session->sessionid, sessionname);
		capwap_logging_debug("Send Echo Response to %s", sessionname);
	}
#endif

	/* Send Configure response to WTP */
	if (!capwap_crypt_sendto_fragmentpacket(&session->dtls, session->responsefragmentpacket)) {
		/* Response is already created and saved. When receive a re-request, DFA autoresponse */
		capwap_logging_debug("Warning: error to send echo response packet");
	}

	return 0;
}

/* */
static void execute_ieee80211_wlan_configuration_addwlan(struct ac_session_t* session, struct capwap_parsed_packet* packet, struct capwap_parsed_packet* requestpacket) {
	struct ac_wlan* wlan;
	struct capwap_80211_addwlan_element* addwlan;
	struct capwap_80211_assignbssid_element* assignbssid;

	/* */
	addwlan = (struct capwap_80211_addwlan_element*)capwap_get_message_element_data(requestpacket, CAPWAP_ELEMENT_80211_ADD_WLAN);

	/* Get BSSID */
	assignbssid = (struct capwap_80211_assignbssid_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_ASSIGN_BSSID);
	if (assignbssid && (assignbssid->radioid == addwlan->radioid) && (assignbssid->wlanid == addwlan->wlanid)) {
		if (!ac_kmod_addwlan(&session->sessionid, assignbssid->radioid, assignbssid->wlanid, assignbssid->bssid, addwlan->macmode, addwlan->tunnelmode)) {
			wlan = ac_wlans_create_bssid(&session->wlans->devices[assignbssid->radioid - 1], assignbssid->wlanid, assignbssid->bssid, addwlan);

			/* Assign BSSID to session */
			if (ac_wlans_assign_bssid(session, wlan)) {
				capwap_logging_warning("Unable to add new wlan with radioid: %d, wlanid: %d", (int)assignbssid->radioid, (int)assignbssid->wlanid);
				ac_wlans_free_bssid(wlan);

				/* TODO: add remove wlan from wtp */
			}
		} else {
			/* TODO: add remove wlan from wtp */
		}
	}
}

/* */
static void execute_ieee80211_wlan_configuration_updatewlan(struct ac_session_t* session, struct capwap_parsed_packet* packet, struct capwap_parsed_packet* requestpacket) {
	//struct capwap_80211_updatewlan_element* updatewlan;

	/* */
	//updatewlan = (struct capwap_80211_updatewlan_element*)capwap_get_message_element_data(requestpacket, CAPWAP_ELEMENT_80211_UPDATE_WLAN);
}

/* */
static void execute_ieee80211_wlan_configuration_deletewlan(struct ac_session_t* session, struct capwap_parsed_packet* packet, struct capwap_parsed_packet* requestpacket) {
	//struct capwap_80211_deletewlan_element* deletewlan;

	/* */
	//deletewlan = (struct capwap_80211_deletewlan_element*)capwap_get_message_element_data(requestpacket, CAPWAP_ELEMENT_80211_DELETE_WLAN);
}

/* */
static void receive_ieee80211_wlan_configuration_response(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	struct capwap_parsed_packet requestpacket;
	struct capwap_packet_rxmng* rxmngrequestpacket;
	struct capwap_resultcode_element* resultcode;

	/* Check the success of the Request */
	resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
	if (CAPWAP_RESULTCODE_OK(resultcode->code)) {
		rxmngrequestpacket = capwap_packet_rxmng_create_from_requestfragmentpacket(session->requestfragmentpacket);
		if (rxmngrequestpacket) {
			if (capwap_parsing_packet(rxmngrequestpacket, &requestpacket) == PARSING_COMPLETE) {
				/* Detect type of IEEE802.11 WLAN Configuration Request */
				if (capwap_get_message_element(&requestpacket, CAPWAP_ELEMENT_80211_ADD_WLAN)) {
					execute_ieee80211_wlan_configuration_addwlan(session, packet, &requestpacket);
				} else if (capwap_get_message_element(&requestpacket, CAPWAP_ELEMENT_80211_UPDATE_WLAN)) {
					execute_ieee80211_wlan_configuration_updatewlan(session, packet, &requestpacket);
				} else if (capwap_get_message_element_data(&requestpacket, CAPWAP_ELEMENT_80211_DELETE_WLAN)) {
					execute_ieee80211_wlan_configuration_deletewlan(session, packet, &requestpacket);
				}
			}

			/* */
			capwap_free_parsed_packet(&requestpacket);
			capwap_packet_rxmng_free(rxmngrequestpacket);
		}
	} else {
		capwap_logging_warning("Receive IEEE802.11 WLAN Configuration Response with error: %d", (int)resultcode->code);
	}

	/* */
	ac_free_reference_last_request(session);
}

/* */
static void execute_ieee80211_station_configuration_response_addstation(struct ac_session_t* session, struct capwap_parsed_packet* packet, struct capwap_parsed_packet* requestpacket) {
	struct ac_wlan* wlan;
	struct ac_station* station;
	struct capwap_addstation_element* addstation;
	struct capwap_80211_station_element* station80211;
	struct capwap_resultcode_element* resultcode;

	/* */
	resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
	addstation = (struct capwap_addstation_element*)capwap_get_message_element_data(requestpacket, CAPWAP_ELEMENT_ADDSTATION);

	/* */
	if (GET_WBID_HEADER(packet->rxmngpacket->header) == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		station80211 = (struct capwap_80211_station_element*)capwap_get_message_element_data(requestpacket, CAPWAP_ELEMENT_80211_STATION);
		if (station80211) {
			wlan = ac_wlans_get_bssid_with_wlanid(session, station80211->radioid, station80211->wlanid);
			if (wlan) {
				station = ac_stations_get_station(session, station80211->radioid, wlan->address, addstation->address);
				if (station) {
					if (CAPWAP_RESULTCODE_OK(resultcode->code)) {
						capwap_logging_info("Authorized station: %s", station->addrtext);

						/* */
						station->flags |= AC_STATION_FLAGS_AUTHORIZED;
						capwap_timeout_deletetimer(session->timeout, station->idtimeout);
						station->idtimeout = CAPWAP_TIMEOUT_INDEX_NO_SET;
					} else {
						ac_stations_delete_station(session, station);
					}
				}
			}
		}
	}
}

/* */
static void execute_ieee80211_station_configuration_response_deletestation(struct ac_session_t* session, struct capwap_parsed_packet* packet, struct capwap_parsed_packet* requestpacket) {
	struct ac_station* station;
	struct capwap_resultcode_element* resultcode;
	struct capwap_deletestation_element* deletestation;

	/* */
	resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
	deletestation = (struct capwap_deletestation_element*)capwap_get_message_element_data(requestpacket, CAPWAP_ELEMENT_DELETESTATION);

	/* */
	station = ac_stations_get_station(session, deletestation->radioid, NULL, deletestation->address);
	if (station) {
		capwap_logging_info("Deauthorized station: %s with %d result code", station->addrtext, (int)resultcode->code);

		/* */
		ac_stations_delete_station(session, station);
	}
}

/* */
static void receive_ieee80211_station_configuration_response(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	struct capwap_packet_rxmng* rxmngrequestpacket;
	struct capwap_parsed_packet requestpacket;

	/* Parsing request message */
	rxmngrequestpacket = capwap_packet_rxmng_create_from_requestfragmentpacket(session->requestfragmentpacket);
	if (capwap_parsing_packet(rxmngrequestpacket, &requestpacket) == PARSING_COMPLETE) {
		if (capwap_get_message_element(&requestpacket, CAPWAP_ELEMENT_ADDSTATION)) {
			execute_ieee80211_station_configuration_response_addstation(session, packet, &requestpacket);
		} else if (capwap_get_message_element_data(&requestpacket, CAPWAP_ELEMENT_DELETESTATION)) {
			execute_ieee80211_station_configuration_response_deletestation(session, packet, &requestpacket);
		}
	}

	/* */
	capwap_free_parsed_packet(&requestpacket);
	capwap_packet_rxmng_free(rxmngrequestpacket);
	ac_free_reference_last_request(session);
}

/* */
void ac_dfa_state_run(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	ASSERT(session != NULL);
	ASSERT(packet != NULL);

	if (capwap_is_request_type(packet->rxmngpacket->ctrlmsg.type) || (session->localseqnumber == packet->rxmngpacket->ctrlmsg.seq)) {
		/* Update sequence number */
		if (!capwap_is_request_type(packet->rxmngpacket->ctrlmsg.type)) {
			session->localseqnumber++;
		}

		/* Parsing message */
		switch (packet->rxmngpacket->ctrlmsg.type) {
			case CAPWAP_CONFIGURATION_UPDATE_RESPONSE: {
				/* TODO */

				/* */
				capwap_timeout_set(session->timeout, session->idtimercontrol, AC_MAX_ECHO_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
				break;
			}

			case CAPWAP_CHANGE_STATE_EVENT_REQUEST: {
				/* TODO */
				capwap_timeout_set(session->timeout, session->idtimercontrol, AC_MAX_ECHO_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
				break;
			}

			case CAPWAP_ECHO_REQUEST: {
#ifdef DEBUG
				{
					char sessionname[33];
					capwap_sessionid_printf(&session->sessionid, sessionname);
					capwap_logging_debug("Receive Echo Request from %s", sessionname);
				}
#endif

				if (!receive_echo_request(session, packet)) {
					capwap_timeout_set(session->timeout, session->idtimercontrol, AC_MAX_ECHO_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
				} else {
					ac_session_teardown(session);
				}

				break;
			}

			case CAPWAP_CLEAR_CONFIGURATION_RESPONSE: {
				/* TODO */

				/* */
				capwap_timeout_set(session->timeout, session->idtimercontrol, AC_MAX_ECHO_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
				break;
			}

			case CAPWAP_WTP_EVENT_REQUEST: {
				/* TODO */
				capwap_timeout_set(session->timeout, session->idtimercontrol, AC_MAX_ECHO_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
				break;
			}

			case CAPWAP_DATA_TRANSFER_REQUEST: {
				/* TODO */
				capwap_timeout_set(session->timeout, session->idtimercontrol, AC_MAX_ECHO_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
				break;
			}

			case CAPWAP_DATA_TRANSFER_RESPONSE: {
				/* TODO */

				/* */
				capwap_timeout_set(session->timeout, session->idtimercontrol, AC_MAX_ECHO_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
				break;
			}

			case CAPWAP_STATION_CONFIGURATION_RESPONSE: {
				receive_ieee80211_station_configuration_response(session, packet);
				capwap_timeout_set(session->timeout, session->idtimercontrol, AC_MAX_ECHO_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
				break;
			}

			case CAPWAP_IEEE80211_WLAN_CONFIGURATION_RESPONSE: {
				receive_ieee80211_wlan_configuration_response(session, packet);
				capwap_timeout_set(session->timeout, session->idtimercontrol, AC_MAX_ECHO_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
				break;
			}
		}
	}
}
