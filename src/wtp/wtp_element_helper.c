#include "wtp.h"

/* */
void wtp_create_radioopsstate_element(struct capwap_packet_txmng* txmngpacket) {
	int i;

	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio* radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);
		struct capwap_radiooprstate_element radiooprstate;
		
		radiooprstate.radioid = (unsigned char)(i + 1);
		radiooprstate.state = ((radio->status == WTP_RADIO_ENABLED) ? CAPWAP_RADIO_OPERATIONAL_STATE_ENABLED : CAPWAP_RADIO_OPERATIONAL_STATE_DISABLED);
		
		if (radio->status == WTP_RADIO_ENABLED) {
			radiooprstate.cause = CAPWAP_RADIO_OPERATIONAL_CAUSE_NORMAL;
		} else if (radio->status == WTP_RADIO_DISABLED) {
			radiooprstate.cause = CAPWAP_RADIO_OPERATIONAL_CAUSE_ADMINSET;
		} else if (radio->status == WTP_RADIO_HWFAILURE) {
			radiooprstate.cause = CAPWAP_RADIO_OPERATIONAL_CAUSE_RADIOFAILURE;
		} else if (radio->status == WTP_RADIO_SWFAILURE) {
			radiooprstate.cause = CAPWAP_RADIO_OPERATIONAL_CAUSE_SOFTWAREFAILURE;
		} else {
			/* Unknown value */
			ASSERT(0);
		}

		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RADIOOPRSTATE, &radiooprstate);
	}
}

/* */
void wtp_create_radioadmstate_element(struct capwap_packet_txmng* txmngpacket) {
	int i;

	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio* radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);
		struct capwap_radioadmstate_element radioadmstate;
		
		radioadmstate.radioid = (unsigned char)(i + 1);
		radioadmstate.state = ((radio->status == WTP_RADIO_DISABLED) ? CAPWAP_RADIO_ADMIN_STATE_DISABLED : CAPWAP_RADIO_ADMIN_STATE_ENABLED);
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RADIOADMSTATE, &radioadmstate);
	}
}

/* */
void wtp_create_80211_wtpradioinformation_element(struct capwap_packet_txmng* txmngpacket) {
	int i;

	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio* radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION, &radio->radioinformation);
	}
}
