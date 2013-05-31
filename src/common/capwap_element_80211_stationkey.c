#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           MAC Address                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          MAC Address          |A|C|           Flags           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Pairwise TSC                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Pairwise TSC          |         Pairwise RSC          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Pairwise RSC                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Key...
+-+-+-+-+-+-+-+-

Type:   1038 for IEEE 802.11 Station Session Key

Length:   >= 25

********************************************************************/

/* */
static void capwap_80211_stationkey_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_stationkey_element* element = (struct capwap_80211_stationkey_element*)data;

	ASSERT(data != NULL);

	func->write_block(handle, element->address, CAPWAP_STATION_SESSION_KEY_ADDRESS_LENGTH);
	func->write_u16(handle, element->flags);
	func->write_block(handle, element->pairwisetsc, CAPWAP_STATION_SESSION_KEY_PAIRWISE_TSC_LENGTH);
	func->write_block(handle, element->pairwisersc, CAPWAP_STATION_SESSION_KEY_PAIRWISE_RSC_LENGTH);
	func->write_block(handle, element->key, element->keylength);
}

/* */
static void* capwap_80211_stationkey_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_80211_stationkey_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 25) {
		capwap_logging_debug("Invalid IEEE 802.11 Station Session Key element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_stationkey_element*)capwap_alloc(sizeof(struct capwap_80211_stationkey_element));
	if (!data) {
		capwap_outofmemory();
	}

	data->keylength = length - 20;
	data->key = (uint8_t*)capwap_alloc(data->keylength);
	if (!data->key) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_80211_stationkey_element));
	func->read_block(handle, data->address, CAPWAP_STATION_SESSION_KEY_ADDRESS_LENGTH);
	func->read_u16(handle, &data->flags);
	func->read_block(handle, data->pairwisetsc, CAPWAP_STATION_SESSION_KEY_PAIRWISE_TSC_LENGTH);
	func->read_block(handle, data->pairwisersc, CAPWAP_STATION_SESSION_KEY_PAIRWISE_RSC_LENGTH);
	func->read_block(handle, data->key, data->keylength);

	return data;
}

/* */
static void capwap_80211_stationkey_element_free(void* data) {
	struct capwap_80211_stationkey_element* element = (struct capwap_80211_stationkey_element*)data;

	ASSERT(data != NULL);

	if (element->key) {
		capwap_free(element->key);
	}

	capwap_free(element);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_stationkey_ops = {
	.create_message_element = capwap_80211_stationkey_element_create,
	.parsing_message_element = capwap_80211_stationkey_element_parsing,
	.free_parsed_message_element = capwap_80211_stationkey_element_free
};
