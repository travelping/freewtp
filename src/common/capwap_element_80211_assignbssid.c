#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |    WLAN ID    |           BSSID
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             BSSID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1026 for IEEE 802.11 Assigned WTP BSSID

Length:   8

********************************************************************/

/* */
static void capwap_80211_assignbssid_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_assignbssid_element* element = (struct capwap_80211_assignbssid_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->wlanid);
	func->write_block(handle, element->bssid, CAPWAP_ASSIGN_BSSID_LENGTH);
}

/* */
static void* capwap_80211_assignbssid_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_80211_assignbssid_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 8) {
		capwap_logging_debug("Invalid IEEE 802.11 Assigned WTP BSSID element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_assignbssid_element*)capwap_alloc(sizeof(struct capwap_80211_assignbssid_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_80211_assignbssid_element));
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->wlanid);
	func->read_block(handle, data->bssid, CAPWAP_ASSIGN_BSSID_LENGTH);

	return data;
}

/* */
static void capwap_80211_assignbssid_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_assignbssid_ops = {
	.create_message_element = capwap_80211_assignbssid_element_create,
	.parsing_message_element = capwap_80211_assignbssid_element_parsing,
	.free_parsed_message_element = capwap_80211_assignbssid_element_free
};
