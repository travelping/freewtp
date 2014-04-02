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
	session->remoteseqnumber = packet->rxmngpacket->ctrlmsg.seq;
	capwap_get_packet_digest(packet->rxmngpacket, packet->connection, session->lastrecvpackethash);

	/* Send Configure response to WTP */
	if (!capwap_crypt_sendto_fragmentpacket(&session->dtls, session->connection.socket.socket[session->connection.socket.type], session->responsefragmentpacket, &session->connection.localaddr, &session->connection.remoteaddr)) {
		/* Response is already created and saved. When receive a re-request, DFA autoresponse */
		capwap_logging_debug("Warning: error to send echo response packet");
	}

	return 0;
}

/* */
static void execute_ieee80211_wlan_configuration_addwlan(struct ac_session_t* session, struct capwap_parsed_packet* packet, struct capwap_80211_addwlan_element* addwlan, struct capwap_parsed_packet* requestpacket) {
	char buffer[18];
	struct ac_wlan* wlan;
	struct capwap_80211_assignbssid_element* assignbssid;

	/* Get BSSID */
	assignbssid = (struct capwap_80211_assignbssid_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_ASSIGN_BSSID);
	if (assignbssid && (assignbssid->radioid == addwlan->radioid) && (assignbssid->wlanid == addwlan->wlanid)) {
		if (!ac_wlans_get_bssid(session->wlans, assignbssid->radioid, assignbssid->bssid)) {
			wlan = ac_wlans_create_bssid(session->wlans, assignbssid->radioid, assignbssid->wlanid, assignbssid->bssid);
			wlan->session = session;
			wlan->sessiondata = session->sessiondata;

			/* Set capability */
			ac_wlans_set_bssid_capability(wlan, addwlan);

			/* */
			capwap_logging_info("Added new wlan with radioid: %d, wlanid: %d, bssid: %s", (int)assignbssid->radioid, (int)assignbssid->wlanid, capwap_printf_macaddress(buffer, assignbssid->bssid, MACADDRESS_EUI48_LENGTH));
		}
	}
}

/* */
static void execute_ieee80211_wlan_configuration_updatewlan(struct ac_session_t* session, struct capwap_parsed_packet* packet, struct capwap_80211_updatewlan_element* updatewlan, struct capwap_parsed_packet* requestpacket) {
}

/* */
static void execute_ieee80211_wlan_configuration_deletewlan(struct ac_session_t* session, struct capwap_parsed_packet* packet, struct capwap_80211_deletewlan_element* deletewlan, struct capwap_parsed_packet* requestpacket) {
}

/* */
static void receive_ieee80211_wlan_configuration_response(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	struct capwap_80211_addwlan_element* addwlan;
	struct capwap_80211_updatewlan_element* updatewlan;
	struct capwap_80211_deletewlan_element* deletewlan;
	struct capwap_parsed_packet requestpacket;
	struct capwap_packet_rxmng* rxmngrequestpacket;
	struct capwap_resultcode_element* resultcode;

	/* Check the success of the Request */
	resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
	if (CAPWAP_RESULTCODE_OK(resultcode->code)) {
		rxmngrequestpacket = capwap_packet_rxmng_create_from_requestfragmentpacket(session->requestfragmentpacket);
		if (rxmngrequestpacket) {
			if (capwap_parsing_packet(rxmngrequestpacket, NULL, &requestpacket) == PARSING_COMPLETE) {
				/* Detect type of IEEE802.11 WLAN Configuration Request */
				addwlan = (struct capwap_80211_addwlan_element*)capwap_get_message_element_data(&requestpacket, CAPWAP_ELEMENT_80211_ADD_WLAN);
				if (addwlan) {
					execute_ieee80211_wlan_configuration_addwlan(session, packet, addwlan, &requestpacket);
				} else {
					updatewlan = (struct capwap_80211_updatewlan_element*)capwap_get_message_element_data(&requestpacket, CAPWAP_ELEMENT_80211_UPDATE_WLAN);
					if (updatewlan) {
						execute_ieee80211_wlan_configuration_updatewlan(session, packet, updatewlan, &requestpacket);
					} else {
						deletewlan = (struct capwap_80211_deletewlan_element*)capwap_get_message_element_data(&requestpacket, CAPWAP_ELEMENT_80211_DELETE_WLAN);
						if (deletewlan) {
							execute_ieee80211_wlan_configuration_deletewlan(session, packet, deletewlan, &requestpacket);
						}
					}
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
void ac_dfa_state_run(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	ASSERT(session != NULL);
	ASSERT(packet != NULL);

	if (capwap_is_request_type(packet->rxmngpacket->ctrlmsg.type) || ((session->localseqnumber - 1) == packet->rxmngpacket->ctrlmsg.seq)) {
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
				/* TODO */

				/* */
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
