#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |Short Preamble| Num of BSSIDs |  DTIM Period  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            BSSID                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          BSSID                |      Beacon Period            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Country String                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1046 for IEEE 802.11 WTP WLAN Radio Configuration

Length:   16

********************************************************************/

/* */
static void capwap_80211_wtpradioconf_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_wtpradioconf_element* element = (struct capwap_80211_wtpradioconf_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->shortpreamble);
	func->write_u8(handle, element->maxbssid);
	func->write_u8(handle, element->dtimperiod);
	func->write_block(handle, element->bssid, CAPWAP_WTP_RADIO_CONF_BSSID_LENGTH);
	func->write_u16(handle, element->beaconperiod);
	func->write_block(handle, element->country, CAPWAP_WTP_RADIO_CONF_COUNTRY_LENGTH);
}

/* */
static void* capwap_80211_wtpradioconf_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_80211_wtpradioconf_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 16) {
		capwap_logging_debug("Invalid IEEE 802.11 WTP WLAN Radio Configuration element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_wtpradioconf_element*)capwap_alloc(sizeof(struct capwap_80211_wtpradioconf_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_80211_wtpradioconf_element));
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->shortpreamble);
	func->read_u8(handle, &data->maxbssid);
	func->read_u8(handle, &data->dtimperiod);
	func->read_block(handle, data->bssid, CAPWAP_WTP_RADIO_CONF_BSSID_LENGTH);
	func->read_u16(handle, &data->beaconperiod);
	func->read_block(handle, data->country, CAPWAP_WTP_RADIO_CONF_COUNTRY_LENGTH);

	return data;
}

/* */
static void capwap_80211_wtpradioconf_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_wtpradioconf_ops = {
	.create_message_element = capwap_80211_wtpradioconf_element_create,
	.parsing_message_element = capwap_80211_wtpradioconf_element_parsing,
	.free_parsed_message_element = capwap_80211_wtpradioconf_element_free
};
