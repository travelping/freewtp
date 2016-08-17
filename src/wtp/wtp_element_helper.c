#include "wtp.h"
#include "wtp_radio.h"

/* */
void wtp_create_radioopsstate_element(struct capwap_packet_txmng* txmngpacket) {
	int i;

	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio* radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);
		struct capwap_radiooprstate_element radiooprstate;
		
		radiooprstate.radioid = radio->radioid;
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
		
		radioadmstate.radioid = radio->radioid;
		radioadmstate.state = ((radio->status == WTP_RADIO_DISABLED) ? CAPWAP_RADIO_ADMIN_STATE_DISABLED : CAPWAP_RADIO_ADMIN_STATE_ENABLED);
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RADIOADMSTATE, &radioadmstate);
	}
}

/* */
void wtp_create_80211_wtpradioinformation_element(struct capwap_packet_txmng* txmngpacket) {
	int i;
	struct wtp_radio* radio;
	struct capwap_80211_wtpradioinformation_element element;

	for (i = 0; i < g_wtp.radios->count; i++) {
		radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);

		/* Set message element */
		if (radio->status == WTP_RADIO_ENABLED) {
			memcpy(&element, &radio->radioinformation, sizeof(struct capwap_80211_wtpradioinformation_element));
		} else {
			memset(&element, 0, sizeof(struct capwap_80211_wtpradioinformation_element));
			element.radioid = radio->radioid;
		}

		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION, &element);
	}
}

/* */
void wtp_create_80211_encryption_capability_element(struct capwap_packet_txmng *txmngpacket,
						    struct wtp_radio *radio)
{
	struct capwap_vendor_travelping_80211_encryption_capability_element *element;

	if (!radio->devicehandle->capability->ciphers ||
	    radio->devicehandle->capability->ciphers_count == 0)
		return;

	element = alloca(sizeof(struct capwap_vendor_travelping_80211_encryption_capability_element) +
			 32 * sizeof(uint32_t));

	/* Set message element */
	element->radioid = radio->radioid;
	element->suites_count = radio->devicehandle->capability->ciphers_count;
	memcpy(element->suites, radio->devicehandle->capability->ciphers,
	       radio->devicehandle->capability->ciphers_count * sizeof(uint32_t));

	capwap_packet_txmng_add_message_element(txmngpacket,
						CAPWAP_ELEMENT_VENDOR_TRAVELPING_80211_ENCRYPTION_CAPABILITY, element);
}

/* */
void wtp_create_80211_encryption_capability_elements(struct capwap_packet_txmng *txmngpacket)
{
	int i;
	struct wtp_radio* radio;

	for (i = 0; i < g_wtp.radios->count; i++) {
		radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);

		wtp_create_80211_encryption_capability_element(txmngpacket, radio);
	}
}

/* */
void wtp_create_80211_supported_mac_profiles_elements(struct capwap_packet_txmng *txmngpacket)
{
	struct capwap_80211_supported_mac_profiles_element *element;

	switch (g_wtp.mactype.type) {
	case CAPWAP_SPLITMAC:
	case CAPWAP_LOCALANDSPLITMAC:
		element = alloca(sizeof(struct capwap_80211_supported_mac_profiles_element) +
				 sizeof(uint8_t));

		element->supported_mac_profilescount = 1;
		element->supported_mac_profiles[0] = 0;        /* IEEE 802.11 Split MAC Profile with WTP
								  encryption */
		capwap_packet_txmng_add_message_element(txmngpacket,
							CAPWAP_ELEMENT_80211_SUPPORTED_MAC_PROFILES, element);
		break;

	default:
		break;
	}
}
