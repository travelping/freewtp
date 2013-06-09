#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "wtp_dfa.h"

/* */
static unsigned long wtp_datacheck_ac(struct capwap_parsed_packet* packet) {
	/* TODO: gestione richiesta */

	return CAPWAP_DATA_CHECK_TO_RUN_STATE;
}

/* */
int wtp_dfa_state_datacheck(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	int status = WTP_DFA_ACCEPT_PACKET;

	ASSERT(timeout != NULL);

	if (packet) {
		unsigned short binding;

		/* */
		binding = GET_WBID_HEADER(packet->rxmngpacket->header);

		if (packet->rxmngpacket->isctrlpacket) {
			if (binding == g_wtp.binding) {
				if (packet->rxmngpacket->ctrlmsg.type == CAPWAP_CHANGE_STATE_EVENT_RESPONSE) {
					if ((g_wtp.localseqnumber - 1) == packet->rxmngpacket->ctrlmsg.seq) {
						if (packet->rxmngpacket->packetlength > 0) {
							int a = packet->rxmngpacket->packetlength;
							a++;
						}
					}
				}
			}
		}

		if (packet->rxmngpacket->isctrlpacket && (binding == g_wtp.binding) && (packet->rxmngpacket->ctrlmsg.type == CAPWAP_CHANGE_STATE_EVENT_RESPONSE) && ((g_wtp.localseqnumber - 1) == packet->rxmngpacket->ctrlmsg.seq)) {
			/* Valid packet, free request packet */
			wtp_free_reference_last_request();

			/* Parsing response values */
			wtp_dfa_change_state(wtp_datacheck_ac(packet));
			status = WTP_DFA_NO_PACKET;
		}
	} else {
		/* No change state response received */
		g_wtp.dfa.rfcRetransmitCount++;
		if (g_wtp.dfa.rfcRetransmitCount >= g_wtp.dfa.rfcMaxRetransmit) {
			/* Timeout join state */
			wtp_free_reference_last_request();
			wtp_dfa_change_state(CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
			status = WTP_DFA_NO_PACKET;
		} else {
			/* Retransmit change state request */	
			if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], g_wtp.requestfragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
				capwap_logging_debug("Warning: error to send change state request packet");
			}

			/* Update timeout */
			capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		}
	}

	return status;
}

/* */
int wtp_dfa_state_datacheck_to_run(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	struct capwap_list* txfragpacket;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	int status = WTP_DFA_ACCEPT_PACKET;

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
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
	capwap_header_set_keepalive_flag(&capwapheader, 1);
	txmngpacket = capwap_packet_txmng_create_data_message(&capwapheader, g_wtp.mtu);		/* CAPWAP_DONT_FRAGMENT */

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_SESSIONID, &g_wtp.sessionid);

	/* Data keepalive complete, get fragment packets into local list */
	txfragpacket = capwap_list_create();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, txfragpacket, 0);
	if (txfragpacket->count == 1) {
		/* Send Data keepalive to AC */
		if (capwap_crypt_sendto_fragmentpacket(&g_wtp.datadtls, g_wtp.acdatasock.socket[g_wtp.acdatasock.type], txfragpacket, &g_wtp.wtpdataaddress, &g_wtp.acdataaddress)) {
			capwap_kill_timeout(timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
			capwap_set_timeout(g_wtp.dfa.rfcEchoInterval, timeout, CAPWAP_TIMER_CONTROL_ECHO);
			capwap_set_timeout(g_wtp.dfa.rfcDataChannelDeadInterval, timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD);
			wtp_dfa_change_state(CAPWAP_RUN_STATE);
		} else {
			/* Error to send packets */
			capwap_logging_debug("Warning: error to send data channel keepalive packet");
			wtp_dfa_change_state(CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
			status = WTP_DFA_NO_PACKET;
		}
	} else {
		capwap_logging_debug("Warning: error to send data channel keepalive packet, fragment packet");
		wtp_dfa_change_state(CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
		status = WTP_DFA_NO_PACKET;
	}

	/* Free packets manager */
	capwap_list_free(txfragpacket);
	capwap_packet_txmng_free(txmngpacket);

	/* */
	return status;
}

/* */
int wtp_dfa_state_datacheck_to_dtlsteardown(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	ASSERT(packet == NULL);
	ASSERT(timeout != NULL);

	return wtp_teardown_connection(timeout);
}
