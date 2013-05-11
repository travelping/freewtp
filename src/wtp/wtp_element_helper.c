#include "wtp.h"

void wtp_create_80211_wtpradioinformation_element(struct capwap_build_packet* buildpacket) {
	int i;

	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio* radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);
		capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_80211_WTPRADIOINFORMATION_ELEMENT(&radio->radioinformation));
	}
}
