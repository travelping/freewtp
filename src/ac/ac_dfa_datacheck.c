#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
int ac_dfa_state_datacheck(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	unsigned short binding;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);
	
	if (packet) {
		binding = GET_WBID_HEADER(packet->rxmngpacket->header);
		/* TODO: gestione richiesta */

		/* Create response */
		capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, binding);
		txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_CHANGE_STATE_EVENT_RESPONSE, packet->rxmngpacket->ctrlmsg.seq, session->mtu);

		/* Add message element */
		/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */		/* TODO */

		/* Change event response complete, get fragment packets */
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

		/* Send Change event response to WTP */
		if (!capwap_crypt_sendto_fragmentpacket(&session->ctrldtls, session->ctrlsocket.socket[session->ctrlsocket.type], session->responsefragmentpacket, &session->acctrladdress, &session->wtpctrladdress)) {
			/* Response is already created and saved. When receive a re-request, DFA autoresponse */
			capwap_logging_debug("Warning: error to send change event response packet");
		}

		/* Change state */
		ac_dfa_change_state(session, CAPWAP_DATA_CHECK_TO_RUN_STATE);
		capwap_set_timeout(session->dfa.rfcDataCheckTimer, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
	} else {
		/* Configure timeout */
		ac_dfa_change_state(session, CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
		status = AC_DFA_NO_PACKET;
	}

	return status;
}

/* */
int ac_dfa_state_datacheck_to_run(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	struct capwap_list* txfragpacket;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);
	
	if (packet) {
		/* Wait Data Channel Keep-Alive packet */
		if (!packet->rxmngpacket->isctrlpacket && IS_FLAG_K_HEADER(packet->rxmngpacket->header)) {
			if (!memcmp(capwap_get_message_element_data(packet, CAPWAP_ELEMENT_SESSIONID), &session->sessionid, sizeof(struct capwap_sessionid_element))) {
				int result = 0;

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
						result = 1;
					} else {
						capwap_logging_debug("Warning: error to send data channel keepalive packet");
					}
				} else {
					capwap_logging_debug("Warning: error to send data channel keepalive packet, fragment packet");
				}

				/* Free packets manager */
				capwap_list_free(txfragpacket);
				capwap_packet_txmng_free(txmngpacket);

				if (result) {
					/* Capwap handshake complete */
					ac_dfa_change_state(session, CAPWAP_RUN_STATE);
					capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
				} else {
					ac_dfa_change_state(session, CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
					status = AC_DFA_NO_PACKET;
				}
			}
		}
	} else {
		/* Configure timeout */
		ac_dfa_change_state(session, CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
		status = AC_DFA_NO_PACKET;
	}

	return status;
}

/* */
int ac_dfa_state_datacheck_to_dtlsteardown(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	return ac_session_teardown_connection(session);
}
