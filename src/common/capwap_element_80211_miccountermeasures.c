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

Type:   1031 for IEEE 802.11 MIC Countermeasures

Length:   8

********************************************************************/

/* */
static void capwap_80211_miccountermeasures_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_miccountermeasures_element* element = (struct capwap_80211_miccountermeasures_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->wlanid);
	func->write_block(handle, element->address, CAPWAP_MIC_COUNTERMEASURES_MACADDRESS_LENGTH);
}

/* */
static void* capwap_80211_miccountermeasures_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_80211_miccountermeasures_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 8) {
		capwap_logging_debug("Invalid IEEE 802.11 MIC Countermeasures element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_miccountermeasures_element*)capwap_alloc(sizeof(struct capwap_80211_miccountermeasures_element));
	memset(data, 0, sizeof(struct capwap_80211_miccountermeasures_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->wlanid);
	func->read_block(handle, data->address, CAPWAP_MIC_COUNTERMEASURES_MACADDRESS_LENGTH);

	return data;
}

/* */
static void* capwap_80211_miccountermeasures_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211_miccountermeasures_element));
}

/* */
static void capwap_80211_miccountermeasures_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_miccountermeasures_ops = {
	.create_message_element = capwap_80211_miccountermeasures_element_create,
	.parsing_message_element = capwap_80211_miccountermeasures_element_parsing,
	.clone_message_element = capwap_80211_miccountermeasures_element_clone,
	.free_message_element = capwap_80211_miccountermeasures_element_free
};
