#ifndef __CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT_HEADER__
#define __CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT_HEADER__

#define CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT		1035

#define CAPWAP_RSNA_ERROR_REPORT_CLIENT_LENGTH			6
#define CAPWAP_RSNA_ERROR_REPORT_BSSID_LENGTH			6

struct capwap_80211_rsnaerrorreport_element {
	uint8_t client[CAPWAP_RSNA_ERROR_REPORT_CLIENT_LENGTH];
	uint8_t bssid[CAPWAP_RSNA_ERROR_REPORT_BSSID_LENGTH];
	uint8_t radioid;
	uint8_t wlanid;
	uint32_t tkipicverrors;
	uint32_t tkiplocalmicfailure;
	uint32_t tkipremotemicfailure;
	uint32_t ccmpreplays;
	uint32_t ccmpdecrypterrors;
	uint32_t tkipreplays;
};

extern struct capwap_message_elements_ops capwap_element_80211_rsnaerrorreport_ops;

#endif /* __CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT_HEADER__ */
