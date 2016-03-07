#ifndef __CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM_HEADER__
#define __CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM_HEADER__

#define CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM			1047

#define CAPWAP_WTP_RADIO_FAIL_ALARM_TYPE_RECEIVER			1
#define CAPWAP_WTP_RADIO_FAIL_ALARM_TYPE_TRANSMITTER		2

struct capwap_80211_wtpradiofailalarm_element {
	uint8_t radioid;
	uint8_t type;
	uint8_t status;
	uint8_t pad;
};

extern const struct capwap_message_elements_ops capwap_element_80211_wtpradiofailalarm_ops;

#endif /* __CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM_HEADER__ */
