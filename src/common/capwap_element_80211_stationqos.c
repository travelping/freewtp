#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           MAC Address                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          MAC Address          |         Reserved        |8021p|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1037 for IEEE 802.11 Station QoS Profile

Length:   8

********************************************************************/

/* */
static void capwap_80211_stationqos_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_stationqos_element* element = (struct capwap_80211_stationqos_element*)data;

	ASSERT(data != NULL);

	func->write_block(handle, element->address, MACADDRESS_EUI48_LENGTH);
	func->write_u8(handle, 0);
	func->write_u8(handle, element->priority);
}

/* */
static void* capwap_80211_stationqos_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_80211_stationqos_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 8) {
		capwap_logging_debug("Invalid IEEE 802.11 Station QoS Profile element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_stationqos_element*)capwap_alloc(sizeof(struct capwap_80211_stationqos_element));
	memset(data, 0, sizeof(struct capwap_80211_stationqos_element));

	/* Retrieve data */
	func->read_block(handle, data->address, MACADDRESS_EUI48_LENGTH);
	func->read_u8(handle, NULL);
	func->read_u8(handle, &data->priority);

	return data;
}

/* */
static void* capwap_80211_stationqos_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211_stationqos_element));
}

/* */
static void capwap_80211_stationqos_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_stationqos_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_80211_stationqos_element_create,
	.parse = capwap_80211_stationqos_element_parsing,
	.clone = capwap_80211_stationqos_element_clone,
	.free = capwap_80211_stationqos_element_free
};
