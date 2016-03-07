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
	memset(data, 0, sizeof(struct capwap_80211_ie_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->wlanid);
	func->read_u8(handle, &data->flags);
	data->ielength = length;
	data->ie = (uint8_t*)capwap_alloc(data->ielength);
	func->read_block(handle, data->ie, data->ielength);

	log_printf(LOG_DEBUG, "802.11 IE flags: %02x (%p)", data->flags, &data->flags);
	return data;
}

/* */
static void* capwap_80211_ie_element_clone(void* data) {
	struct capwap_80211_ie_element* cloneelement;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_80211_ie_element));
	cloneelement->ie = capwap_clone(((struct capwap_80211_ie_element*)data)->ie, cloneelement->ielength);

	return cloneelement;
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
	.category = CAPWAP_MESSAGE_ELEMENT_ARRAY,
	.create = capwap_80211_ie_element_create,
	.parse = capwap_80211_ie_element_parsing,
	.clone = capwap_80211_ie_element_clone,
	.free = capwap_80211_ie_element_free
};
