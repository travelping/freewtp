#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

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
static void receive_ieee80211_wlan_configuration_response(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	struct capwap_resultcode_element* resultcode;

	/* Check the success of the Request */
	resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
	if (resultcode && !CAPWAP_RESULTCODE_OK(resultcode->code)) {
		capwap_logging_warning("Receive IEEE802.11 WLAN Configuration Response with error: %d", (int)resultcode->code);
	}

	/* */
	ac_free_reference_last_request(session);
}

/* */
void ac_dfa_state_run(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	ASSERT(session != NULL);

	if (packet) {
		if (capwap_is_request_type(packet->rxmngpacket->ctrlmsg.type) || ((session->localseqnumber - 1) == packet->rxmngpacket->ctrlmsg.seq)) {
			switch (packet->rxmngpacket->ctrlmsg.type) {
				case CAPWAP_CONFIGURATION_UPDATE_RESPONSE: {
					/* TODO */

					/* */
					capwap_timeout_set(AC_MAX_ECHO_INTERVAL, session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
					break;
				}

				case CAPWAP_CHANGE_STATE_EVENT_REQUEST: {
					/* TODO */
					capwap_timeout_set(AC_MAX_ECHO_INTERVAL, session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
					break;
				}

				case CAPWAP_ECHO_REQUEST: {
					if (!receive_echo_request(session, packet)) {
						capwap_timeout_set(AC_MAX_ECHO_INTERVAL, session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
					} else {
						ac_session_teardown(session);
					}

					break;
				}

				case CAPWAP_CLEAR_CONFIGURATION_RESPONSE: {
					/* TODO */

					/* */
					capwap_timeout_set(AC_MAX_ECHO_INTERVAL, session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
					break;
				}

				case CAPWAP_WTP_EVENT_REQUEST: {
					/* TODO */
					capwap_timeout_set(AC_MAX_ECHO_INTERVAL, session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
					break;
				}

				case CAPWAP_DATA_TRANSFER_REQUEST: {
					/* TODO */
					capwap_timeout_set(AC_MAX_ECHO_INTERVAL, session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
					break;
				}

				case CAPWAP_DATA_TRANSFER_RESPONSE: {
					/* TODO */

					/* */
					capwap_timeout_set(AC_MAX_ECHO_INTERVAL, session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
					break;
				}

				case CAPWAP_STATION_CONFIGURATION_RESPONSE: {
					/* TODO */

					/* */
					capwap_timeout_set(AC_MAX_ECHO_INTERVAL, session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
					break;
				}

				case CAPWAP_IEEE80211_WLAN_CONFIGURATION_RESPONSE: {
					receive_ieee80211_wlan_configuration_response(session, packet);
					capwap_timeout_set(AC_MAX_ECHO_INTERVAL, session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
					break;
				}
			}
		}
	} else if ((session->requestfragmentpacket->count > 0)) {
		/* No response received */
		session->dfa.rfcRetransmitCount++;
		if (session->dfa.rfcRetransmitCount >= session->dfa.rfcMaxRetransmit) {
			/* Timeout */
			ac_free_reference_last_request(session);
			ac_session_teardown(session);
		} else {
			/* Retransmit request */
			if (!capwap_crypt_sendto_fragmentpacket(&session->dtls, session->connection.socket.socket[session->connection.socket.type], session->requestfragmentpacket, &session->connection.localaddr, &session->connection.remoteaddr)) {
				capwap_logging_debug("Warning: error to resend request packet");
			}

			/* Update timeout */
			capwap_timeout_set(session->dfa.rfcRetransmitInterval, session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		}
	} else {
		ac_session_teardown(session);
	}
}
