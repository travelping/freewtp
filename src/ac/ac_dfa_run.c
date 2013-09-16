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

	ASSERT(session != NULL);
	ASSERT(packet != NULL);

	/* Check session */
	response = ac_soap_checkwtpsession(session, session->wtpid);
	if (response) {
		if ((response->responsecode == HTTP_RESULT_OK) && response->xmlResponseReturn) {
			xmlChar* xmlResult = xmlNodeGetContent(response->xmlResponseReturn);
			if (!xmlStrcmp(xmlResult, (const xmlChar *)"true")) {
				validsession = 1;
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
	if (!capwap_crypt_sendto_fragmentpacket(&session->ctrldtls, session->ctrlsocket.socket[session->ctrlsocket.type], session->responsefragmentpacket, &session->acctrladdress, &session->wtpctrladdress)) {
		/* Response is already created and saved. When receive a re-request, DFA autoresponse */
		capwap_logging_debug("Warning: error to send echo response packet");
	}

	return 0;
}

/* */
static int ac_send_data_keepalive(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	struct capwap_list* txfragpacket;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	int result = -1;

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, GET_WBID_HEADER(packet->rxmngpacket->header));
	capwap_header_set_keepalive_flag(&capwapheader, 1);
	txmngpacket = capwap_packet_txmng_create_data_message(&capwapheader, session->mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_SESSIONID, &session->sessionid);

	/* Data keepalive complete, get fragment packets into local list */
	txfragpacket = capwap_list_create();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, txfragpacket, 0);
	if (txfragpacket->count == 1) {
		/* Send Data keepalive to WTP */
		if (capwap_crypt_sendto_fragmentpacket(&session->datadtls, session->datasocket.socket[session->datasocket.type], txfragpacket, &session->acdataaddress, &session->wtpdataaddress)) {
			result = 0;
		} else {
			capwap_logging_debug("Warning: error to send data channel keepalive packet");
		}
	} else {
		capwap_logging_debug("Warning: error to send data channel keepalive packet, fragment packet");
	}

	/* Free packets manager */
	capwap_list_free(txfragpacket);
	capwap_packet_txmng_free(txmngpacket);

	return result;
}

/* */
int ac_dfa_state_run(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);

	if (packet) {
		if (packet->rxmngpacket->isctrlpacket) {
			if (capwap_is_request_type(packet->rxmngpacket->ctrlmsg.type) || ((session->localseqnumber - 1) == packet->rxmngpacket->ctrlmsg.seq)) {
				switch (packet->rxmngpacket->ctrlmsg.type) {
					case CAPWAP_CONFIGURATION_UPDATE_RESPONSE: {
						/* TODO */
						capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
						break;
					}

					case CAPWAP_CHANGE_STATE_EVENT_REQUEST: {
						/* TODO */
						capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
						break;
					}

					case CAPWAP_ECHO_REQUEST: {
						if (!receive_echo_request(session, packet)) {
							capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
						} else {
							ac_dfa_change_state(session, CAPWAP_RUN_TO_DTLS_TEARDOWN_STATE);
							status = AC_DFA_NO_PACKET;
						}

						break;
					}

					case CAPWAP_CLEAR_CONFIGURATION_RESPONSE: {
						/* TODO */
						capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
						break;
					}

					case CAPWAP_WTP_EVENT_REQUEST: {
						/* TODO */
						capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
						break;
					}

					case CAPWAP_DATA_TRANSFER_REQUEST: {
						/* TODO */
						capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
						break;
					}

					case CAPWAP_DATA_TRANSFER_RESPONSE: {
						/* TODO */
						capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
						break;
					}

					case CAPWAP_STATION_CONFIGURATION_RESPONSE: {
						/* TODO */
						capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
						break;
					}
				}
			}
		} else {
			if (IS_FLAG_K_HEADER(packet->rxmngpacket->header)) {
				if (!memcmp(capwap_get_message_element_data(packet, CAPWAP_ELEMENT_SESSIONID), &session->sessionid, sizeof(struct capwap_sessionid_element))) {
					if (ac_send_data_keepalive(session, packet)) {
						ac_dfa_change_state(session, CAPWAP_RUN_TO_DTLS_TEARDOWN_STATE);
						status = AC_DFA_NO_PACKET;
					}
				}
			} else {
				/* TODO */
			}
		}
	} else {
		ac_dfa_change_state(session, CAPWAP_RUN_TO_DTLS_TEARDOWN_STATE);
		status = AC_DFA_NO_PACKET;
	}

	return status;
}

/* */
int ac_dfa_state_run_to_reset(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	int status = AC_DFA_NO_PACKET;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;

	ASSERT(session != NULL);
	ASSERT(packet == NULL);

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, session->binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_RESET_REQUEST, session->localseqnumber++, session->mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_IMAGEIDENTIFIER, &session->startupimage);
	/* CAPWAP_ELEMENT_VENDORPAYLOAD */				/* TODO */

	/* Reset request complete, get fragment packets */
	ac_free_reference_last_request(session);
	capwap_packet_txmng_get_fragment_packets(txmngpacket, session->requestfragmentpacket, session->fragmentid);
	if (session->requestfragmentpacket->count > 1) {
		session->fragmentid++;
	}

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send Configure response to WTP */
	if (capwap_crypt_sendto_fragmentpacket(&session->ctrldtls, session->ctrlsocket.socket[session->ctrlsocket.type], session->requestfragmentpacket, &session->acctrladdress, &session->wtpctrladdress)) {
		session->dfa.rfcRetransmitCount = 0;
		capwap_killall_timeout(&session->timeout);
		capwap_set_timeout(session->dfa.rfcRetransmitInterval, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		ac_dfa_change_state(session, CAPWAP_RESET_STATE);
		status = AC_DFA_ACCEPT_PACKET;
	} else {
		capwap_logging_debug("Warning: error to send reset request packet");
		ac_free_reference_last_request(session);
		ac_dfa_change_state(session, CAPWAP_RESET_TO_DTLS_TEARDOWN_STATE);
	}

	return status;
}

/* */
int ac_dfa_state_run_to_dtlsteardown(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	return ac_session_teardown_connection(session);
}
