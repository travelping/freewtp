#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "wtp_dfa.h"

/* */
static unsigned long wtp_datacheck_ac(struct capwap_element_changestateevent_response* changestateresponse) {
	/* TODO: gestione richiesta */

	return CAPWAP_DATA_CHECK_TO_RUN_STATE;
}

/* */
int wtp_dfa_state_datacheck(struct capwap_packet* packet, struct timeout_control* timeout) {
	int status = WTP_DFA_ACCEPT_PACKET;
	
	ASSERT(timeout != NULL);

	if (packet) {
		if (!capwap_compare_ip(&g_wtp.acctrladdress, &packet->remoteaddr)) {
			struct capwap_build_packet* buildpacket;

			/* Parsing packet */
			buildpacket = capwap_rx_packet_create((void*)packet->header, packet->packetsize, packet->socket.isctrlsocket);
			if (buildpacket) {
				if (!capwap_build_packet_validate(buildpacket, NULL)) {
					unsigned short binding;
					
					/* */
					binding = GET_WBID_HEADER(&buildpacket->header);
					if ((binding == g_wtp.binding) && (ntohl(buildpacket->ctrlmsg.type) == CAPWAP_CHANGE_STATE_EVENT_RESPONSE) && ((g_wtp.localseqnumber - 1) == buildpacket->ctrlmsg.seq)) {
						struct capwap_element_changestateevent_response changestateresponse;
						
						/* Valid packet, free request packet */
						wtp_free_reference_last_request();
						
						/* Configuration status response info */
						capwap_init_element_changestateevent_response(&changestateresponse, binding);
	
						/* Parsing elements list */
						if (capwap_parsing_element_changestateevent_response(&changestateresponse, buildpacket->elementslist->first)) {
							wtp_dfa_change_state(wtp_datacheck_ac(&changestateresponse));
							status = WTP_DFA_NO_PACKET;
						}
						
						/* Free join response */
						capwap_free_element_changestateevent_response(&changestateresponse, binding);
					}
				}

				/* Free */				
				capwap_build_packet_free(buildpacket);
			}
		}
	} else {
		int i;
		
		/* No change state response received */
		g_wtp.dfa.rfcRetransmitCount++;
		if (g_wtp.dfa.rfcRetransmitCount >= g_wtp.dfa.rfcMaxRetransmit) {
			/* Timeout join state */
			wtp_free_reference_last_request();
			wtp_dfa_change_state(CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
			status = WTP_DFA_NO_PACKET;
		} else {
			/* Retransmit change state request */	
			for (i = 0; i < g_wtp.requestfragmentpacket->count; i++) {
				struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(g_wtp.requestfragmentpacket, i);
				ASSERT(txpacket != NULL);
				
				if (!capwap_crypt_sendto(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], txpacket->header, txpacket->packetsize, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
					capwap_logging_debug("Warning: error to send change state request packet");
					break;
				}
			}
	
			/* Update timeout */
			capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		}
	}

	return status;
}

/* */
int wtp_dfa_state_datacheck_to_run(struct capwap_packet* packet, struct timeout_control* timeout) {
	int result;
	int status = WTP_DFA_ACCEPT_PACKET;
	struct capwap_build_packet* buildpacket;
	capwap_fragment_packet_array* txfragpacket;
	
	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);

	/* If need, create DTLS Data channel crypted */
	if (g_wtp.dtlsdatapolicy & CAPWAP_ACDESC_DTLS_DATA_CHANNEL_ENABLED) {
		if (!g_wtp.datadtls.enable) {
			/* Create DTLS data session before send data keepalive */
			if (capwap_crypt_createsession(&g_wtp.datadtls, CAPWAP_DTLS_DATA_SESSION, &g_wtp.dtlscontext, wtp_bio_send, NULL)) {
				if (capwap_crypt_open(&g_wtp.datadtls, &g_wtp.acdataaddress) == CAPWAP_HANDSHAKE_CONTINUE) {
					/* Wait complete dtls handshake */
					capwap_set_timeout(g_wtp.dfa.rfcWaitDTLS, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
					return WTP_DFA_ACCEPT_PACKET;
				} else {
					/* TODO error */
				}
			} else {
				/* TODO error */
			}
		} else if (g_wtp.datadtls.action != CAPWAP_DTLS_ACTION_DATA) {
			wtp_dfa_change_state(CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
			return WTP_DFA_NO_PACKET;
		}
	}
	
	/* Build packet */
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
		capwap_kill_timeout(timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		capwap_set_timeout(g_wtp.dfa.rfcEchoInterval, timeout, CAPWAP_TIMER_CONTROL_ECHO);
		capwap_set_timeout(g_wtp.dfa.rfcDataChannelDeadInterval, timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD);
		wtp_dfa_change_state(CAPWAP_RUN_STATE);
	} else {
		wtp_dfa_change_state(CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
		status = WTP_DFA_NO_PACKET;
	}

	/* */
	return status;
}

/* */
int wtp_dfa_state_datacheck_to_dtlsteardown(struct capwap_packet* packet, struct timeout_control* timeout) {
	ASSERT(packet == NULL);
	ASSERT(timeout != NULL);

	return wtp_teardown_connection(timeout);
}
