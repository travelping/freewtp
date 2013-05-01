#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
int ac_dfa_state_reset(struct ac_session_t* session, struct capwap_packet* packet) {
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);

	if (packet) {
		if (!capwap_compare_ip(&session->wtpctrladdress, &packet->remoteaddr)) {
			struct capwap_build_packet* buildpacket;

			/* Parsing packet */
			buildpacket = capwap_rx_packet_create((void*)packet->header, packet->packetsize, packet->socket.isctrlsocket);
			if (buildpacket) {
				if (!capwap_build_packet_validate(buildpacket, NULL)) {
					unsigned short binding;
					
					/* */
					binding = GET_WBID_HEADER(&buildpacket->header);
					if ((binding == session->binding) && (ntohl(buildpacket->ctrlmsg.type) == CAPWAP_RESET_RESPONSE) && ((session->localseqnumber - 1) == buildpacket->ctrlmsg.seq)) {
						struct capwap_element_reset_response resetresponse;
						
						/* Valid packet, free request packet */
						ac_free_reference_last_request(session);
						
						/* Configuration status response info */
						capwap_init_element_reset_response(&resetresponse, binding);
	
						/* Parsing elements list */
						if (capwap_parsing_element_reset_response(&resetresponse, buildpacket->elementslist->first)) {
							ac_dfa_change_state(session, CAPWAP_RESET_TO_DTLS_TEARDOWN_STATE);
							status = AC_DFA_NO_PACKET;
						}
						
						/* Free join response */
						capwap_free_element_reset_response(&resetresponse, binding);
					}
				}

				/* Free */				
				capwap_build_packet_free(buildpacket);
			}
		}
	} else {
		int i;
		
		/* No Configuration status response received */
		session->dfa.rfcRetransmitCount++;
		if (session->dfa.rfcRetransmitCount >= session->dfa.rfcMaxRetransmit) {
			/* Timeout join state */
			ac_free_reference_last_request(session);
			ac_dfa_change_state(session, CAPWAP_RESET_TO_DTLS_TEARDOWN_STATE);
			status = AC_DFA_NO_PACKET;
		} else {
			/* Retransmit configuration request */	
			for (i = 0; i < session->requestfragmentpacket->count; i++) {
				struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(session->requestfragmentpacket, i);
				ASSERT(txpacket != NULL);
				
				if (!capwap_crypt_sendto(&session->ctrldtls, session->ctrlsocket.socket[session->ctrlsocket.type], txpacket->header, txpacket->packetsize, &session->acctrladdress, &session->wtpctrladdress)) {
					capwap_logging_debug("Warning: error to send configuration status request packet");
					break;
				}
			}
	
			/* Update timeout */
			capwap_set_timeout(session->dfa.rfcRetransmitInterval, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		}
	}

	return status;
}

/* */
int ac_dfa_state_reset_to_dtlsteardown(struct ac_session_t* session, struct capwap_packet* packet) {
	return ac_session_teardown_connection(session);
}
