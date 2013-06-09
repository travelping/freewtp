#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Radio ID    |    WLAN ID    |B|P| Reserved  |Info Element...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1029 for IEEE 802.11 Information Element

Length:   >= 4

********************************************************************/

/* */
static void capwap_80211_ie_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_ie_element* element = (struct capwap_80211_ie_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->wlanid);
	func->write_u8(handle, element->flags);
	func->write_block(handle, element->ie, element->ielength);
}

/* */
static void* capwap_80211_ie_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_80211_ie_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 4) {
		capwap_logging_debug("Invalid IEEE 802.11 Information Element element");
		return NULL;
	}

	/* */
	length -= 3;

	/* */
	data = (struct capwap_80211_ie_element*)capwap_alloc(sizeof(struct capwap_80211_ie_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_80211_ie_element));
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->wlanid);
	func->read_u8(handle, &data->flags);
	data->ielength = length;
	data->ie = (uint8_t*)capwap_alloc(data->ielength);
	if (!data->ie) {
		capwap_outofmemory();
	}
	func->read_block(handle, data->ie, data->ielength);

	return data;
}

/* */
static void capwap_80211_ie_element_free(void* data) {
	struct capwap_80211_ie_element* element = (struct capwap_80211_ie_element*)data;

	ASSERT(data != NULL);

	capwap_free(element->ie);
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_ie_ops = {
	.create_message_element = capwap_80211_ie_element_create,
	.parsing_message_element = capwap_80211_ie_element_parsing,
	.free_parsed_message_element = capwap_80211_ie_element_free
};
