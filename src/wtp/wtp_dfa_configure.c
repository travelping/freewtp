#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "capwap_array.h"
#include "capwap_list.h"
#include "wtp_dfa.h"

/* */
void wtp_send_configure(struct timeout_control* timeout) {
	int i;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;

	ASSERT(timeout != NULL);

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_CONFIGURATION_STATUS_REQUEST, g_wtp.localseqnumber++, g_wtp.mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ACNAME, &g_wtp.acname);
	wtp_create_radioadmstate_element(txmngpacket);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_STATISTICSTIMER, &g_wtp.statisticstimer);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPREBOOTSTAT, &g_wtp.rebootstat);
	/* CAPWAP_ELEMENT_ACNAMEPRIORITY */					/* TODO */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_TRANSPORT, &g_wtp.transport);
	/* CAPWAP_ELEMENT_WTPSTATICIPADDRESS */				/* TODO */

	if (g_wtp.binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		for (i = 0; i < g_wtp.radios->count; i++) {
			struct wtp_radio* radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);

			/* Set message element */
			if ((radio->status == WTP_RADIO_ENABLED) && (radio->radioid == radio->radioinformation.radioid)) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION, &radio->radioinformation);

				if (radio->radioid == radio->radioinformation.radioid) {
					capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_ANTENNA, &radio->antenna);
				}

				if ((radio->radioid == radio->directsequencecontrol.radioid) && (radio->radioinformation.radiotype & (CAPWAP_RADIO_TYPE_80211B | CAPWAP_RADIO_TYPE_80211G))) {
					capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL, &radio->directsequencecontrol);
				} else if ((radio->radioid == radio->ofdmcontrol.radioid) && (radio->radioinformation.radiotype & CAPWAP_RADIO_TYPE_80211A)) {
					capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_OFDMCONTROL, &radio->ofdmcontrol);
				}

				if (radio->radioid == radio->macoperation.radioid) {
					capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_MACOPERATION, &radio->macoperation);
				}

				if (radio->radioid == radio->multidomaincapability.radioid) {
					capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY, &radio->multidomaincapability);
				}

				if (radio->radioid == radio->supportedrates.radioid) {
					capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_SUPPORTEDRATES, &radio->supportedrates);
				}

				if (radio->radioid == radio->txpower.radioid) {
					capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_TXPOWER, &radio->txpower);
				}

				if (radio->radioid == radio->txpowerlevel.radioid) {
					capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_TXPOWERLEVEL, &radio->txpowerlevel);
				}

				if (radio->radioid == radio->radioconfig.radioid) {
					capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_WTP_RADIO_CONF, &radio->radioconfig);
				}
			} else {
				struct capwap_80211_wtpradioinformation_element element = { (uint8_t)radio->radioid, 0 };
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION, &element);
			}
		}
	}

	/* CAPWAP_ELEMENT_VENDORPAYLOAD */					/* TODO */

	/* Configuration Status request complete, get fragment packets */
	wtp_free_reference_last_request();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, g_wtp.requestfragmentpacket, g_wtp.fragmentid);
	if (g_wtp.requestfragmentpacket->count > 1) {
		g_wtp.fragmentid++;
	}

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send Configuration Status request to AC */
	if (capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], g_wtp.requestfragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
		g_wtp.dfa.rfcRetransmitCount = 0;
		capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		wtp_dfa_change_state(CAPWAP_CONFIGURE_STATE);
	} else {
		/* Error to send packets */
		capwap_logging_debug("Warning: error to send configuration status request packet");
		wtp_free_reference_last_request();
		wtp_teardown_connection(timeout);
	}
}

/* */
void wtp_dfa_state_configure(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	struct capwap_timers_element* timers;
	struct capwap_resultcode_element* resultcode;

	ASSERT(timeout != NULL);

	if (packet) {
		unsigned short binding;

		/* */
		binding = GET_WBID_HEADER(packet->rxmngpacket->header);
		if (packet->rxmngpacket->isctrlpacket && (binding == g_wtp.binding) && (packet->rxmngpacket->ctrlmsg.type == CAPWAP_CONFIGURATION_STATUS_RESPONSE) && ((g_wtp.localseqnumber - 1) == packet->rxmngpacket->ctrlmsg.seq)) {
			/* Valid packet, free request packet */
			wtp_free_reference_last_request();

			/* Check the success of the Request */
			resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
			if (resultcode && !CAPWAP_RESULTCODE_OK(resultcode->code)) {
				capwap_logging_warning("Receive Configure Status Response with error: %d", (int)resultcode->code);
				wtp_teardown_connection(timeout);
			} else {
				/* Timers */
				timers = (struct capwap_timers_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_TIMERS);
				g_wtp.dfa.rfcMaxDiscoveryInterval = timers->discovery;
				g_wtp.dfa.rfcEchoInterval = timers->echorequest;

				/* Binding values */
				if (!wtp_radio_setconfiguration(packet)) {
					wtp_send_datacheck(timeout);		/* Send change state event packet */
				} else {
					capwap_logging_warning("Receive Configure Status Response with invalid elements");
					wtp_teardown_connection(timeout);
				}
			}
		}
	} else {
		/* No Configuration status response received */
		g_wtp.dfa.rfcRetransmitCount++;
		if (g_wtp.dfa.rfcRetransmitCount >= g_wtp.dfa.rfcMaxRetransmit) {
			/* Timeout join state */
			wtp_free_reference_last_request();
			wtp_teardown_connection(timeout);
		} else {
			/* Retransmit configuration status request */
			if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], g_wtp.requestfragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
				capwap_logging_debug("Warning: error to send configuration status request packet");
			}

			/* Update timeout */
			capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		}
	}
}
