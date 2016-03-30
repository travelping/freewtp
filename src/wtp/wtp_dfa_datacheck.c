#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "wtp_dfa.h"

/* */
void wtp_dfa_state_datacheck_enter(void)
{
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_resultcode_element resultcode = { .code = CAPWAP_RESULTCODE_SUCCESS };

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader,
							      CAPWAP_CHANGE_STATE_EVENT_REQUEST,
							      g_wtp.localseqnumber, g_wtp.mtu);

	/* Add message element */
	wtp_create_radioopsstate_element(txmngpacket);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RESULTCODE, &resultcode);

	/* CAPWAP_ELEMENT_RETURNEDMESSAGE */					/* TODO */
	/* CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM */			/* TODO */
	/* CAPWAP_ELEMENT_VENDORPAYLOAD */						/* TODO */

	/* Change State Event request complete, get fragment packets */
	wtp_free_reference_last_request();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, g_wtp.requestfragmentpacket, g_wtp.fragmentid);
	if (g_wtp.requestfragmentpacket->count > 1)
		g_wtp.fragmentid++;

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send Change State Event request to AC */
	if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.dtls, g_wtp.requestfragmentpacket)) {
		/* Error to send packets */
		log_printf(LOG_DEBUG, "Warning: error to send change state event request packet");
		wtp_free_reference_last_request();
		wtp_teardown_connection();

		return;
	}

	g_wtp.retransmitcount = 0;
	wtp_dfa_start_retransmition_timer();
}

/* */
void wtp_dfa_state_datacheck(struct capwap_parsed_packet* packet)
{
	unsigned short binding;
	struct capwap_resultcode_element* resultcode;

	if (packet->rxmngpacket->ctrlmsg.type != CAPWAP_CHANGE_STATE_EVENT_RESPONSE) {
		log_printf(LOG_DEBUG, "Unexpected message %d in state Data Check",
				     packet->rxmngpacket->ctrlmsg.type);
		return;
	}

	/* */
	binding = GET_WBID_HEADER(packet->rxmngpacket->header);
	if (binding != g_wtp.binding) {
		log_printf(LOG_DEBUG, "Change State Event for invalid binding");
		return;
	}

	if (g_wtp.localseqnumber != packet->rxmngpacket->ctrlmsg.seq) {
		log_printf(LOG_DEBUG, "Configuration Status Response with invalid sequence (%d != %d)",
				     g_wtp.localseqnumber, packet->rxmngpacket->ctrlmsg.seq);
		return;
	}

	wtp_dfa_stop_retransmition_timer();

	g_wtp.localseqnumber++;

	/* Valid packet, free request packet */
	wtp_free_reference_last_request();

	/* Check the success of the Request */
	resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet,
											CAPWAP_ELEMENT_RESULTCODE);
	if (resultcode && !CAPWAP_RESULTCODE_OK(resultcode->code)) {
		log_printf(LOG_WARNING, "Receive Data Check Response with error: %d",
				       (int)resultcode->code);
		wtp_teardown_connection();

		return;
	}

	wtp_start_datachannel();
}
