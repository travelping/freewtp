#include "capwap.h"
#include "element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |    Reserved   |        Current Tx Power       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1041 for IEEE 802.11 Tx Power

Length:   4

********************************************************************/

/* */
static void capwap_80211_txpower_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_txpower_element* element = (struct capwap_80211_txpower_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_u8(handle, element->radioid);
	func->write_u8(handle, 0);
	func->write_u16(handle, element->currenttxpower);
}

/* */
static void* capwap_80211_txpower_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_80211_txpower_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 4) {
		log_printf(LOG_DEBUG, "Invalid IEEE 802.11 Tx Power element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_txpower_element*)capwap_alloc(sizeof(struct capwap_80211_txpower_element));
	memset(data, 0, sizeof(struct capwap_80211_txpower_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, NULL);
	func->read_u16(handle, &data->currenttxpower);

	return data;
}

/* */
static void* capwap_80211_txpower_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211_txpower_element));
}

/* */
static void capwap_80211_txpower_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
const struct capwap_message_elements_ops capwap_element_80211_txpower_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_ARRAY,
	.create = capwap_80211_txpower_element_create,
	.parse = capwap_80211_txpower_element_parsing,
	.clone = capwap_80211_txpower_element_clone,
	.free = capwap_80211_txpower_element_free
};
