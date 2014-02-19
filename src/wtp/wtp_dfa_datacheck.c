#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "wtp_dfa.h"

/* */
void wtp_send_datacheck(void) {
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_resultcode_element resultcode = { .code = CAPWAP_RESULTCODE_SUCCESS };

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_CHANGE_STATE_EVENT_REQUEST, g_wtp.localseqnumber++, g_wtp.mtu);

	/* Add message element */
	wtp_create_radioopsstate_element(txmngpacket);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RESULTCODE, &resultcode);

	/* CAPWAP_ELEMENT_RETURNEDMESSAGE */					/* TODO */
	/* CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM */			/* TODO */
	/* CAPWAP_ELEMENT_VENDORPAYLOAD */						/* TODO */

	/* Change State Event request complete, get fragment packets */
	wtp_free_reference_last_request();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, g_wtp.requestfragmentpacket, g_wtp.fragmentid);
	if (g_wtp.requestfragmentpacket->count > 1) {
		g_wtp.fragmentid++;
	}

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send Change State Event request to AC */
	if (capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], g_wtp.requestfragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
		g_wtp.dfa.rfcRetransmitCount = 0;
		capwap_timeout_set(g_wtp.dfa.rfcRetransmitInterval, g_wtp.timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		wtp_dfa_change_state(CAPWAP_DATA_CHECK_STATE);
	} else {
		/* Error to send packets */
		capwap_logging_debug("Warning: error to send change state event request packet");
		wtp_free_reference_last_request();
		wtp_teardown_connection();
	}
}

/* */
void wtp_dfa_state_datacheck(struct capwap_parsed_packet* packet) {
	unsigned short binding;
	struct capwap_resultcode_element* resultcode;

	if (packet) {
		binding = GET_WBID_HEADER(packet->rxmngpacket->header);
		if (packet->rxmngpacket->isctrlpacket && (binding == g_wtp.binding) && (packet->rxmngpacket->ctrlmsg.type == CAPWAP_CHANGE_STATE_EVENT_RESPONSE) && ((g_wtp.localseqnumber - 1) == packet->rxmngpacket->ctrlmsg.seq)) {
			/* Valid packet, free request packet */
			wtp_free_reference_last_request();

			/* Check the success of the Request */
			resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
			if (resultcode && !CAPWAP_RESULTCODE_OK(resultcode->code)) {
				capwap_logging_warning("Receive Data Check Response with error: %d", (int)resultcode->code);
				wtp_teardown_connection();
			} else {
				/* TODO: gestione richiesta */
				wtp_start_datachannel();
			}
		}
	} else {
		/* No change state response received */
		g_wtp.dfa.rfcRetransmitCount++;
		if (g_wtp.dfa.rfcRetransmitCount >= g_wtp.dfa.rfcMaxRetransmit) {
			/* Timeout join state */
			wtp_free_reference_last_request();
			wtp_teardown_connection();
		} else {
			/* Retransmit change state request */
			if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], g_wtp.requestfragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
				capwap_logging_debug("Warning: error to send change state request packet");
			}

			/* Update timeout */
			capwap_timeout_set(g_wtp.dfa.rfcRetransmitInterval, g_wtp.timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		}
	}
}
