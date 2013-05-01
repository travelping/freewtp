#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
static int receive_echo_request(struct ac_session_t* session, struct capwap_build_packet* buildpacket, struct capwap_packet* packet) {
	unsigned long i;
	unsigned short binding;

	ASSERT(session != NULL);
	ASSERT(buildpacket != NULL);
	ASSERT(packet != NULL);

	/* */
	binding = GET_WBID_HEADER(&buildpacket->header);
	if (ac_valid_binding(binding) && IS_SEQUENCE_SMALLER(session->remoteseqnumber, buildpacket->ctrlmsg.seq)) {
		struct capwap_element_echo_request echorequest;
		
		/* Echo request info*/
		capwap_init_element_echo_request(&echorequest, binding);
		
		/* Parsing elements list */
		if (capwap_parsing_element_echo_request(&echorequest, buildpacket->elementslist->first)) {
			struct capwap_build_packet* responsepacket;

			/* Create response */
			responsepacket = capwap_tx_packet_create(CAPWAP_RADIOID_NONE, binding);
			responsepacket->isctrlmsg = 1;

			/* Prepare echo response */
			capwap_build_packet_set_control_message_type(responsepacket, CAPWAP_ECHO_RESPONSE, buildpacket->ctrlmsg.seq);
			/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */		/* TODO */

			if (!capwap_build_packet_validate(responsepacket, NULL)) {
				int result;
				
				/* Free old reference for this request */
				ac_free_reference_last_response(session);

				/* Send echo response to WTP */
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
							capwap_logging_debug("Warning: error to send echo response packet");
							break;
						}
					}
				}
			}
			
			/* Free memory */
			capwap_build_packet_free(responsepacket);
		} 
		
		/* Free */
		capwap_free_element_echo_request(&echorequest, binding);
	}

	return 0;
}

/* */
int ac_dfa_state_run(struct ac_session_t* session, struct capwap_packet* packet) {
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);

	if (packet) {
		struct capwap_build_packet* buildpacket;

		buildpacket = capwap_rx_packet_create((void*)packet->header, packet->packetsize, packet->socket.isctrlsocket);
		if (buildpacket) {
			if (!capwap_build_packet_validate(buildpacket, NULL)) {
				if (packet->socket.isctrlsocket) {
					unsigned long typemsg = ntohl(buildpacket->ctrlmsg.type);
					
					if (capwap_is_request_type(typemsg) || ((session->localseqnumber - 1) == buildpacket->ctrlmsg.seq)) {
						switch (typemsg) {
							case CAPWAP_CONFIGURATION_UPDATE_REQUEST: {
								/* TODO */
								capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
								break;
							}
							
							case CAPWAP_CHANGE_STATE_EVENT_RESPONSE: {
								/* TODO */
								capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
								break;
							}
							
							case CAPWAP_ECHO_REQUEST: {
								if (!receive_echo_request(session, buildpacket, packet)) {
									capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
								} else {
									ac_dfa_change_state(session, CAPWAP_RUN_TO_DTLS_TEARDOWN_STATE);
									status = AC_DFA_NO_PACKET;
								}
								
								break;
							}
							
							case CAPWAP_CLEAR_CONFIGURATION_REQUEST: {
								/* TODO */
								capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
								break;
							}
							
							case CAPWAP_WTP_EVENT_RESPONSE: {
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
						}
					}
				} else {
					if (IS_FLAG_K_HEADER(&buildpacket->header)) {
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
								
								if (result) {
									ac_dfa_change_state(session, CAPWAP_RUN_TO_DTLS_TEARDOWN_STATE);
									status = AC_DFA_NO_PACKET;
								}
							}
						}
					} else {
						/* TODO */
					}
				}
			}
			
			/* Free */
			capwap_build_packet_free(buildpacket);
		}
	} else {
		ac_dfa_change_state(session, CAPWAP_RUN_TO_DTLS_TEARDOWN_STATE);
		status = AC_DFA_NO_PACKET;
	}

	return status;
}

/* */
int ac_dfa_state_run_to_reset(struct ac_session_t* session, struct capwap_packet* packet) {
	int status = AC_DFA_NO_PACKET;
	struct capwap_build_packet* buildpacket;

	ASSERT(session != NULL);
	ASSERT(packet == NULL);

	/* Build packet */
	buildpacket = capwap_tx_packet_create(CAPWAP_RADIOID_NONE, session->binding);
	buildpacket->isctrlmsg = 1;
	
	/* Prepare reset request */
	capwap_build_packet_set_control_message_type(buildpacket, CAPWAP_RESET_REQUEST, session->localseqnumber++);
	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_IMAGEIDENTIFIER_ELEMENT(&session->startupimage));
	/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */	/* TODO */

	if (!capwap_build_packet_validate(buildpacket, NULL)) {
		int i;
		int result;
		
		/* Free old reference for this request */
		ac_free_reference_last_request(session);

		/* Send reset request to WTP */
		result = capwap_fragment_build_packet(buildpacket, session->requestfragmentpacket, session->mtu, session->fragmentid);
		if (result >= 0) {
			if (result == 1) {
				session->fragmentid++;
			}

			/* Send */
			for (i = 0; i < session->requestfragmentpacket->count; i++) {
				struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(session->requestfragmentpacket, i);
				ASSERT(txpacket != NULL);
				
				if (!capwap_crypt_sendto(&session->ctrldtls, session->ctrlsocket.socket[session->ctrlsocket.type], txpacket->header, txpacket->packetsize, &session->acctrladdress, &session->wtpctrladdress)) {
					capwap_logging_debug("Warning: error to send reset request packet");
					result = -1;
					break;
				}
			}
		}

		if (result == -1) {
			/* Error to send packets */
			ac_free_reference_last_request(session);
			ac_dfa_change_state(session, CAPWAP_RESET_TO_DTLS_TEARDOWN_STATE);
		} else {
			session->dfa.rfcRetransmitCount = 0;

			capwap_killall_timeout(&session->timeout);
			capwap_set_timeout(session->dfa.rfcRetransmitInterval, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);

			ac_dfa_change_state(session, CAPWAP_RESET_STATE);
			status = AC_DFA_ACCEPT_PACKET;
		}
	}
	
	/* Free memory */
	capwap_build_packet_free(buildpacket);

	return status;
}

/* */
int ac_dfa_state_run_to_dtlsteardown(struct ac_session_t* session, struct capwap_packet* packet) {
	return ac_session_teardown_connection(session);
}
