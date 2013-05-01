#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
int ac_dfa_state_datacheck(struct ac_session_t* session, struct capwap_packet* packet) {
	unsigned long i;
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);
	
	if (packet) {
		struct capwap_build_packet* buildpacket;
	
		buildpacket = capwap_rx_packet_create((void*)packet->header, packet->packetsize, packet->socket.isctrlsocket);
		if (buildpacket) {
			if (!capwap_build_packet_validate(buildpacket, NULL)) {
				unsigned short binding;

				/* */
				binding = GET_WBID_HEADER(&buildpacket->header);
				if (ac_valid_binding(binding) && (ntohl(buildpacket->ctrlmsg.type) == CAPWAP_CHANGE_STATE_EVENT_REQUEST) && IS_SEQUENCE_SMALLER(session->remoteseqnumber, buildpacket->ctrlmsg.seq)) {
					struct capwap_element_changestateevent_request changeeventrequest;
					
					/* Change event request info */
					capwap_init_element_changestateevent_request(&changeeventrequest, binding);
					
					/* Parsing elements list */
					if (capwap_parsing_element_changestateevent_request(&changeeventrequest, buildpacket->elementslist->first)) {
						struct capwap_build_packet* responsepacket;

						/* TODO: gestione richiesta */

						/* Create response */
						responsepacket = capwap_tx_packet_create(CAPWAP_RADIOID_NONE, binding);
						responsepacket->isctrlmsg = 1;

						/* Prepare change event response */
						capwap_build_packet_set_control_message_type(responsepacket, CAPWAP_CHANGE_STATE_EVENT_RESPONSE, buildpacket->ctrlmsg.seq);
						/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */		/* TODO */

						if (!capwap_build_packet_validate(responsepacket, NULL)) {
							int result;
							
							/* Free old reference for this request */
							ac_free_reference_last_response(session);
			
							/* Send change event response to WTP */
							result = capwap_fragment_build_packet(responsepacket, session->responsefragmentpacket, session->mtu, session->fragmentid);
							if (result >= 0) {
								if (result == 1) {
									session->fragmentid++;
								}
			
								/* Save remote sequence number */
								session->remoteseqnumber = buildpacket->ctrlmsg.seq;
								capwap_get_packet_digest((void*)packet->header, packet->packetsize, session->lastrecvpackethash);
			
								/* Send */
								for (i = 0; i < session->responsefragmentpacket->count; i++) {
									struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(session->responsefragmentpacket, i);
									ASSERT(txpacket != NULL);
									
									if (!capwap_crypt_sendto(&session->ctrldtls, session->ctrlsocket.socket[session->ctrlsocket.type], txpacket->header, txpacket->packetsize, &session->acctrladdress, &session->wtpctrladdress)) {
										/* Response is already created and saved. When receive a re-request, DFA autoresponse */
										capwap_logging_debug("Warning: error to send change event response packet");
										break;
									}
								}

								/* Change status */
								ac_dfa_change_state(session, CAPWAP_DATA_CHECK_TO_RUN_STATE);
								capwap_set_timeout(session->dfa.rfcDataCheckTimer, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
							}
						} else {
							capwap_logging_debug("Warning: build invalid configuration status response packet");
						}
						
						/* Free memory */
						capwap_build_packet_free(responsepacket);
					} 
					
					/* Free */
					capwap_free_element_changestateevent_request(&changeeventrequest, binding);
				}
			}

			/* Free */
			capwap_build_packet_free(buildpacket);
		}
	} else {
		/* Configure timeout */
		ac_dfa_change_state(session, CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
		status = AC_DFA_NO_PACKET;
	}

	return status;
}

/* */
int ac_dfa_state_datacheck_to_run(struct ac_session_t* session, struct capwap_packet* packet) {
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);
	
	if (packet) {
		/* Wait Data Channel Keep-Alive packet */
		if (!packet->socket.isctrlsocket) {
			struct capwap_build_packet* buildpacket;
		
			buildpacket = capwap_rx_packet_create((void*)packet->header, packet->packetsize, packet->socket.isctrlsocket);
			if (buildpacket) {
				struct capwap_sessionid_element sessionid;
				
				if (capwap_get_sessionid_from_keepalive(buildpacket, &sessionid)) {
					if (!memcmp(&sessionid, &session->sessionid, sizeof(struct capwap_sessionid_element))) {
						int result;
						capwap_fragment_packet_array* txfragpacket;
						
						/* Receive data packet keepalive, response with same packet */
						txfragpacket = capwap_array_create(sizeof(struct capwap_packet), 0);
						result = capwap_fragment_build_packet(buildpacket, txfragpacket, CAPWAP_DONT_FRAGMENT, 0);
						if (!result) {
							struct capwap_packet* txpacket;
							
							ASSERT(txfragpacket->count == 1);
							
							txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(txfragpacket, 0);
							ASSERT(txpacket != NULL);
							
							if (!capwap_crypt_sendto(&session->datadtls, session->datasocket.socket[session->datasocket.type], txpacket->header, txpacket->packetsize, &session->acdataaddress, &session->wtpdataaddress)) {
								capwap_logging_debug("Warning: error to send data channel keepalive packet");
								result = -1;
							}
						}
					
						/* */
						capwap_fragment_free(txfragpacket);
						capwap_array_free(txfragpacket);
						
						if (!result) {
							/* Capwap handshake complete */
							ac_dfa_change_state(session, CAPWAP_RUN_STATE);
							capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
						} else {
							ac_dfa_change_state(session, CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
							status = AC_DFA_NO_PACKET;
						}
					}
				}
				
				/* Free */
				capwap_build_packet_free(buildpacket);
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
int ac_dfa_state_datacheck_to_dtlsteardown(struct ac_session_t* session, struct capwap_packet* packet) {
	return ac_session_teardown_connection(session);
}
