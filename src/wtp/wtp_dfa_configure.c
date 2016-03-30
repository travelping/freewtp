#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "capwap_array.h"
#include "capwap_list.h"
#include "wtp_dfa.h"
#include "wtp_radio.h"

static void cfg_binding_add_ieee80211(struct capwap_packet_txmng* txmngpacket)
{
	int i;

	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio* radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);

		/* Set message element */

		if (radio->status != WTP_RADIO_ENABLED ||
		    radio->radioid != radio->radioinformation.radioid) {
			struct capwap_80211_wtpradioinformation_element element = { (uint8_t)radio->radioid, 0 };
			capwap_packet_txmng_add_message_element(txmngpacket,
								CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION,
								&element);
			continue;
		}

		capwap_packet_txmng_add_message_element(txmngpacket,
							CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION,
							&radio->radioinformation);

		if (radio->radioid == radio->radioinformation.radioid)
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_ANTENNA, &radio->antenna);

		if (radio->radioid == radio->directsequencecontrol.radioid &&
		    (radio->radioinformation.radiotype & (CAPWAP_RADIO_TYPE_80211B | CAPWAP_RADIO_TYPE_80211G))) {
			capwap_packet_txmng_add_message_element(txmngpacket,
								CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL,
								&radio->directsequencecontrol);
		} else if (radio->radioid == radio->ofdmcontrol.radioid &&
			   (radio->radioinformation.radiotype & CAPWAP_RADIO_TYPE_80211A)) {
			capwap_packet_txmng_add_message_element(txmngpacket,
								CAPWAP_ELEMENT_80211_OFDMCONTROL,
								&radio->ofdmcontrol);
		}

		if (radio->radioid == radio->macoperation.radioid)
			capwap_packet_txmng_add_message_element(txmngpacket,
								CAPWAP_ELEMENT_80211_MACOPERATION,
								&radio->macoperation);

		if (radio->radioid == radio->multidomaincapability.radioid)
			capwap_packet_txmng_add_message_element(txmngpacket,
								CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY,
								&radio->multidomaincapability);

		if (radio->radioid == radio->supportedrates.radioid)
			capwap_packet_txmng_add_message_element(txmngpacket,
								CAPWAP_ELEMENT_80211_SUPPORTEDRATES,
								&radio->supportedrates);

		if (radio->radioid == radio->txpower.radioid)
			capwap_packet_txmng_add_message_element(txmngpacket,
								CAPWAP_ELEMENT_80211_TXPOWER,
								&radio->txpower);

		if (radio->radioid == radio->txpowerlevel.radioid)
			capwap_packet_txmng_add_message_element(txmngpacket,
								CAPWAP_ELEMENT_80211_TXPOWERLEVEL,
								&radio->txpowerlevel);

		if (radio->radioid == radio->radioconfig.radioid)
			capwap_packet_txmng_add_message_element(txmngpacket,
								CAPWAP_ELEMENT_80211_WTP_RADIO_CONF,
								&radio->radioconfig);

		if (radio->radioid == radio->n_radio_cfg.radioid)
			capwap_packet_txmng_add_message_element(txmngpacket,
								CAPWAP_ELEMENT_80211N_RADIO_CONF,
								&radio->n_radio_cfg);
	}
}

/* */
void wtp_dfa_state_configure_enter(void)
{
	struct capwap_header_data capwapheader;
	struct capwap_acnamepriority_element acnamepriority;
	struct capwap_packet_txmng* txmngpacket;

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_CONFIGURATION_STATUS_REQUEST, g_wtp.localseqnumber, g_wtp.mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ACNAME, &g_wtp.acname);
	wtp_create_radioadmstate_element(txmngpacket);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_STATISTICSTIMER, &g_wtp.statisticstimer);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPREBOOTSTAT, &g_wtp.rebootstat);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_TRANSPORT, &g_wtp.transport);

	acnamepriority.priority = 1;
	acnamepriority.name = g_wtp.acname.name;
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ACNAMEPRIORITY, &acnamepriority);

	/* CAPWAP_ELEMENT_WTPSTATICIPADDRESS */				/* TODO */

	if (g_wtp.binding == CAPWAP_WIRELESS_BINDING_IEEE80211)
		cfg_binding_add_ieee80211(txmngpacket);

	/* CAPWAP_ELEMENT_VENDORPAYLOAD */					/* TODO */

	/* Configuration Status request complete, get fragment packets */
	wtp_free_reference_last_request();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, g_wtp.requestfragmentpacket, g_wtp.fragmentid);
	if (g_wtp.requestfragmentpacket->count > 1)
		g_wtp.fragmentid++;

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send Configuration Status request to AC */
	if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.dtls, g_wtp.requestfragmentpacket)) {
		/* Error to send packets */
		log_printf(LOG_DEBUG, "Warning: error to send configuration status request packet");
		wtp_free_reference_last_request();
		wtp_teardown_connection();

		return;
	}

	g_wtp.retransmitcount = 0;
	wtp_dfa_start_retransmition_timer();
}

/* */
void wtp_dfa_state_configure(struct capwap_parsed_packet* packet)
{
	unsigned short binding;
	struct capwap_timers_element* timers;
	struct capwap_resultcode_element* resultcode;

	if (packet->rxmngpacket->ctrlmsg.type != CAPWAP_CONFIGURATION_STATUS_RESPONSE) {
		log_printf(LOG_DEBUG, "Unexpected message %d in state Configure",
				     packet->rxmngpacket->ctrlmsg.type);
		return;
	}

	/* */
	binding = GET_WBID_HEADER(packet->rxmngpacket->header);
	if (binding != g_wtp.binding) {
		log_printf(LOG_DEBUG, "Configuration Status Response for invalid binding");
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
		log_printf(LOG_WARNING, "Receive Configure Status Response with error: %d",
				       (int)resultcode->code);
		wtp_teardown_connection();
		return;
	}

	/* Timers */
	timers = (struct capwap_timers_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_TIMERS);
	g_wtp.discoveryinterval = timers->discovery * 1000;
	g_wtp.echointerval = timers->echorequest * 1000;

	/* Binding values */
	if (wtp_radio_setconfiguration(packet)) {
		log_printf(LOG_WARNING, "Receive Configure Status Response with invalid elements");
		wtp_teardown_connection();
		return;
	}

	wtp_dfa_change_state(CAPWAP_DATA_CHECK_STATE);		/* Send change state event packet */
}
