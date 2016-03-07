#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |    Reserved   |        First Channel #        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Number of Channels      |       Max Tx Power Level      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1032 for IEEE 802.11 Multi-Domain Capability

Length:   8

********************************************************************/

/* */
static void capwap_80211_multidomaincapability_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_multidomaincapability_element* element = (struct capwap_80211_multidomaincapability_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_u8(handle, element->radioid);
	func->write_u8(handle, 0);
	func->write_u16(handle, element->firstchannel);
	func->write_u16(handle, element->numberchannels);
	func->write_u16(handle, element->maxtxpowerlevel);
}

/* */
static void* capwap_80211_multidomaincapability_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_80211_multidomaincapability_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 8) {
		capwap_logging_debug("Invalid IEEE 802.11 Multi-Domain Capability element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_multidomaincapability_element*)capwap_alloc(sizeof(struct capwap_80211_multidomaincapability_element));
	memset(data, 0, sizeof(struct capwap_80211_multidomaincapability_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, NULL);
	func->read_u16(handle, &data->firstchannel);
	func->read_u16(handle, &data->numberchannels);
	func->read_u16(handle, &data->maxtxpowerlevel);

	return data;
}

/* */
static void* capwap_80211_multidomaincapability_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211_multidomaincapability_element));
}

/* */
static void capwap_80211_multidomaincapability_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_multidomaincapability_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_ARRAY,
	.create = capwap_80211_multidomaincapability_element_create,
	.parse = capwap_80211_multidomaincapability_element_parsing,
	.clone = capwap_80211_multidomaincapability_element_clone,
	.free = capwap_80211_multidomaincapability_element_free
};
