#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "wtp_dfa.h"

/* */
static int send_echo_request() {
	int i;
	int result = -1;
	struct capwap_build_packet* buildpacket;

	/* Build packet */
	buildpacket = capwap_tx_packet_create(CAPWAP_RADIOID_NONE, g_wtp.binding);
	buildpacket->isctrlmsg = 1;
	
	/* Prepare echo request */
	capwap_build_packet_set_control_message_type(buildpacket, CAPWAP_ECHO_REQUEST, g_wtp.localseqnumber++);
	/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */	/* TODO */

	/* Create echo request packet */
	if (!capwap_build_packet_validate(buildpacket, NULL)) {
		wtp_free_reference_last_request();
		result = capwap_fragment_build_packet(buildpacket, g_wtp.requestfragmentpacket, g_wtp.mtu, g_wtp.fragmentid);
		if (result == 1) {
			g_wtp.fragmentid++;
		}
	} else {
		capwap_logging_debug("Warning: build invalid echo request packet");
	}

	capwap_build_packet_free(buildpacket);

	/* Send echo request to AC */
	if (result >= 0) {
		for (i = 0; i < g_wtp.requestfragmentpacket->count; i++) {
			struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(g_wtp.requestfragmentpacket, i);
			ASSERT(txpacket != NULL);
			
			if (!capwap_crypt_sendto(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], txpacket->header, txpacket->packetsize, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
				capwap_logging_debug("Warning: error to send echo request packet");
				result = -1;
				break;
			}
		}

		if (result == -1) {
			wtp_free_reference_last_request();	/* Error to send packets */
		}
	}
	
	return result;
}

/* */
static int receive_echo_response(struct capwap_build_packet* buildpacket) {
	unsigned short binding;
	struct capwap_element_echo_response echoresponse;

	ASSERT(buildpacket != NULL);
	
	/* Valid packet, free request packet */
	wtp_free_reference_last_request();

	/* Echo response info */
	binding = GET_WBID_HEADER(&buildpacket->header);
	capwap_init_element_echo_response(&echoresponse, binding);

	/* Parsing elements list */
	if (capwap_parsing_element_echo_response(&echoresponse, buildpacket->elementslist->first)) {
		/* TODO */
	}
							
	/* Free join response */
	capwap_free_element_echo_response(&echoresponse, binding);
	return 0;
}

/* */
static void receive_reset_request(struct capwap_build_packet* buildpacket, struct capwap_packet* packet) {
	unsigned long i;
	unsigned short binding;

	ASSERT(buildpacket != NULL);

	/* */
	binding = GET_WBID_HEADER(&buildpacket->header);
	if ((binding == g_wtp.binding) && IS_SEQUENCE_SMALLER(g_wtp.remoteseqnumber, buildpacket->ctrlmsg.seq)) {
		struct capwap_element_reset_request resetrequest;
		
		/* Reset request info*/
		capwap_init_element_reset_request(&resetrequest, binding);
		
		/* Parsing elements list */
		if (capwap_parsing_element_reset_request(&resetrequest, buildpacket->elementslist->first)) {
			struct capwap_build_packet* responsepacket;
			struct capwap_resultcode_element resultcode = { CAPWAP_RESULTCODE_SUCCESS };

			/* Create response */
			responsepacket = capwap_tx_packet_create(CAPWAP_RADIOID_NONE, binding);
			responsepacket->isctrlmsg = 1;

			/* Prepare echo response */
			capwap_build_packet_set_control_message_type(responsepacket, CAPWAP_RESET_RESPONSE, buildpacket->ctrlmsg.seq);
			capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_RESULTCODE_ELEMENT(&resultcode));
			/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */		/* TODO */

			if (!capwap_build_packet_validate(responsepacket, NULL)) {
				int result;

				wtp_free_reference_last_response();

				/* Send reset response to AC */
				result = capwap_fragment_build_packet(responsepacket, g_wtp.responsefragmentpacket, g_wtp.mtu, g_wtp.fragmentid);
				if (result >= 0) {
					if (result == 1) {
						g_wtp.fragmentid++;
					}

					/* Save remote sequence number */
					g_wtp.remoteseqnumber = buildpacket->ctrlmsg.seq;
					capwap_get_packet_digest((void*)packet->header, packet->packetsize, g_wtp.lastrecvpackethash);

					/* Send */
					for (i = 0; i < g_wtp.responsefragmentpacket->count; i++) {
						struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(g_wtp.responsefragmentpacket, i);
						ASSERT(txpacket != NULL);

						if (!capwap_crypt_sendto(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], txpacket->header, txpacket->packetsize, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
							/* Response is already created and saved. When receive a re-request, DFA autoresponse */
							capwap_logging_debug("Warning: error to send reset response packet");
							break;
						}
					}
				}
			}
			
			/* Free memory */
			capwap_build_packet_free(responsepacket);
		} 
		
		/* Free */
		capwap_free_element_reset_request(&resetrequest, binding);
	}
}

/* */
int wtp_dfa_state_run(struct capwap_packet* packet, struct timeout_control* timeout) {
	int status = WTP_DFA_ACCEPT_PACKET;
	
	ASSERT(timeout != NULL);

	if (packet) {
		struct capwap_build_packet* buildpacket;

		buildpacket = capwap_rx_packet_create((void*)packet->header, packet->packetsize, packet->socket.isctrlsocket);
		if (buildpacket) {
			if (!capwap_build_packet_validate(buildpacket, NULL)) {
				if (packet->socket.isctrlsocket) {
					unsigned long typemsg = ntohl(buildpacket->ctrlmsg.type);
					
					if (capwap_is_request_type(typemsg) || ((g_wtp.localseqnumber - 1) == buildpacket->ctrlmsg.seq)) {
						switch (typemsg) {
							case CAPWAP_CONFIGURATION_UPDATE_RESPONSE: {
								/* TODO */
								break;
							}
							
							case CAPWAP_CHANGE_STATE_EVENT_REQUEST: {
								/* TODO */
								break;
							}
							
							case CAPWAP_ECHO_RESPONSE: {
								if (!receive_echo_response(buildpacket)) {
									capwap_kill_timeout(timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
									capwap_set_timeout(g_wtp.dfa.rfcEchoInterval, timeout, CAPWAP_TIMER_CONTROL_ECHO);
								}
								
								break;
							}
							
							case CAPWAP_CLEAR_CONFIGURATION_RESPONSE: {
								/* TODO */
								break;
							}
							
							case CAPWAP_WTP_EVENT_REQUEST: {
								/* TODO */
								break;
							}
							
							case CAPWAP_DATA_TRANSFER_REQUEST: {
								/* TODO */
								break;
							}
							
							case CAPWAP_DATA_TRANSFER_RESPONSE: {
								/* TODO */
								break;
							}
							
							case CAPWAP_RESET_REQUEST: {
								receive_reset_request(buildpacket, packet);
								wtp_dfa_change_state(CAPWAP_RESET_STATE);
								status = WTP_DFA_NO_PACKET;
								break;
							}
						}
					}
				} else {
					if (IS_FLAG_K_HEADER(&buildpacket->header) && capwap_is_enable_timeout(timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD)) {
						struct capwap_sessionid_element sessionid;

						if (capwap_get_sessionid_from_keepalive(buildpacket, &sessionid)) {
							if (!memcmp(&sessionid, &g_wtp.sessionid, sizeof(struct capwap_sessionid_element))) {
								/* Receive Data Keep-Alive, wait for next packet */
								capwap_kill_timeout(timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD);
								capwap_set_timeout(g_wtp.dfa.rfcDataChannelKeepAlive, timeout, CAPWAP_TIMER_DATA_KEEPALIVE);
							}
						}
					} else {
						/* TODO */
						
						/* Update data keep-alive timeout */
						if (!capwap_is_enable_timeout(timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD)) {
							capwap_set_timeout(g_wtp.dfa.rfcDataChannelKeepAlive, timeout, CAPWAP_TIMER_DATA_KEEPALIVE);
						}
					}
				}
			}
			
			/* Free */
			capwap_build_packet_free(buildpacket);
		}
	} else {
		if (capwap_is_timeout(timeout, CAPWAP_TIMER_CONTROL_CONNECTION)) {
			int i;

			/* No response received */
			g_wtp.dfa.rfcRetransmitCount++;
			if (g_wtp.dfa.rfcRetransmitCount >= g_wtp.dfa.rfcMaxRetransmit) {
				/* Timeout run state */
				wtp_free_reference_last_request();
				wtp_dfa_change_state(CAPWAP_RUN_TO_DTLS_TEARDOWN_STATE);
				status = WTP_DFA_NO_PACKET;
			} else {
				/* Retransmit request */
				for (i = 0; i < g_wtp.requestfragmentpacket->count; i++) {
					struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(g_wtp.requestfragmentpacket, i);
					ASSERT(txpacket != NULL);
					
					if (!capwap_crypt_sendto(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], txpacket->header, txpacket->packetsize, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
						capwap_logging_debug("Warning: error to send request packet");
						break;
					}
				}
		
				/* Update timeout */
				capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
			}
		} else if (capwap_is_timeout(timeout, CAPWAP_TIMER_CONTROL_ECHO)) {
			/* Disable echo timer */
			capwap_kill_timeout(timeout, CAPWAP_TIMER_CONTROL_ECHO);

			if (!send_echo_request()) {
				g_wtp.dfa.rfcRetransmitCount = 0;
				capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
			} else {
				wtp_dfa_change_state(CAPWAP_RUN_TO_DTLS_TEARDOWN_STATE);
				status = WTP_DFA_NO_PACKET;
			}
		} else if (capwap_is_timeout(timeout, CAPWAP_TIMER_DATA_KEEPALIVE)) {
			int result;
			struct capwap_build_packet* buildpacket;
			capwap_fragment_packet_array* txfragpacket;

			/* Build packet Data Keep-Alive*/
			buildpacket = capwap_tx_packet_create(CAPWAP_RADIOID_NONE, CAPWAP_WIRELESS_BINDING_NONE);
			buildpacket->isctrlmsg = 0;
			
			/* */
			SET_FLAG_K_HEADER(&buildpacket->header, 1);
			capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_SESSIONID_ELEMENT(&g_wtp.sessionid));
		
			txfragpacket = capwap_array_create(sizeof(struct capwap_packet), 0);
			result = capwap_fragment_build_packet(buildpacket, txfragpacket, CAPWAP_DONT_FRAGMENT, 0);
			if (!result) {
				struct capwap_packet* txpacket;
				
				ASSERT(txfragpacket->count == 1);
				
				txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(txfragpacket, 0);
				ASSERT(txpacket != NULL);
				
				if (!capwap_crypt_sendto(&g_wtp.datadtls, g_wtp.acdatasock.socket[g_wtp.acdatasock.type], txpacket->header, txpacket->packetsize, &g_wtp.wtpdataaddress, &g_wtp.acdataaddress)) {
					capwap_logging_debug("Warning: error to send data channel keepalive packet");
					result = -1;
				}
			}
		
			capwap_fragment_free(txfragpacket);
			capwap_array_free(txfragpacket);
			capwap_build_packet_free(buildpacket);
		
			/* Send Configuration Status request to AC */
			if (!result) {		
				capwap_kill_timeout(timeout, CAPWAP_TIMER_DATA_KEEPALIVE);
				capwap_set_timeout(g_wtp.dfa.rfcDataChannelDeadInterval, timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD);
			} else {
				wtp_dfa_change_state(CAPWAP_RUN_TO_DTLS_TEARDOWN_STATE);
				status = WTP_DFA_NO_PACKET;
			}
		} else if (capwap_is_timeout(timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD)) {
			/* Data Keep-Alive timeout */
			capwap_kill_timeout(timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD);
			wtp_dfa_change_state(CAPWAP_RUN_TO_DTLS_TEARDOWN_STATE);
			status = WTP_DFA_NO_PACKET;
		}
	}

	return status;
}

/* */
int wtp_dfa_state_run_to_dtlsteardown(struct capwap_packet* packet, struct timeout_control* timeout) {
	ASSERT(packet == NULL);
	ASSERT(timeout != NULL);

	return wtp_teardown_connection(timeout);
}
