#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |    WLAN ID    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1027 for IEEE 802.11 Delete WLAN

Length:   2

********************************************************************/

/* */
static void capwap_80211_deletewlan_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_deletewlan_element* element = (struct capwap_80211_deletewlan_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->wlanid);
}

/* */
static void* capwap_80211_deletewlan_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_80211_deletewlan_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 2) {
		capwap_logging_debug("Invalid IEEE 802.11 Delete WLAN element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_deletewlan_element*)capwap_alloc(sizeof(struct capwap_80211_deletewlan_element));
	memset(data, 0, sizeof(struct capwap_80211_deletewlan_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->wlanid);

	return data;
}

/* */
static void* capwap_80211_deletewlan_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211_deletewlan_element));
}

/* */
static void capwap_80211_deletewlan_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_deletewlan_ops = {
	.create = capwap_80211_deletewlan_element_create,
	.parse = capwap_80211_deletewlan_element_parsing,
	.clone = capwap_80211_deletewlan_element_clone,
	.free = capwap_80211_deletewlan_element_free
};
