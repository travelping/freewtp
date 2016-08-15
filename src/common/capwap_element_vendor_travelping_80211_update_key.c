#include "capwap.h"
#include "capwap_element.h"

/*
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Radio ID   |    WLAN ID    |   Key Index   |   Key Status  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Cipher Suite                          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                              Key...                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * IEEE 802.11 Update Key
 *
 * Vendor Id:  18681 (Travelping GmbH)
 * Type:       19
 *
 * Length:   >= 6
 *
 */

/* */
static void
capwap_vendor_travelping_80211_update_key_element_create(void *data,
							 capwap_message_elements_handle handle,
							 struct capwap_write_message_elements_ops *func)
{
	struct capwap_vendor_travelping_80211_update_key_element *element =
		(struct capwap_vendor_travelping_80211_update_key_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->wlanid);
	func->write_u8(handle, element->keyindex);
	func->write_u8(handle, element->keystatus);
	func->write_u32(handle, element->ciphersuite);
	if (element->keylength > 0)
		func->write_block(handle, element->key, element->keylength);
}

/* */
static void *
capwap_vendor_travelping_80211_update_key_element_parsing(capwap_message_elements_handle handle,
							  struct capwap_read_message_elements_ops *func)
{
	unsigned short length;
	struct capwap_vendor_travelping_80211_update_key_element *data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 8) {
		log_printf(LOG_DEBUG, "Invalid Vendor Travelping IEEE 802.11 Update Key element");
		return NULL;
	}

	length -= 8;

	/* */
	data = (struct capwap_vendor_travelping_80211_update_key_element *)
		capwap_alloc(sizeof(struct capwap_vendor_travelping_80211_update_key_element) + length);
	memset(data, 0, sizeof(struct capwap_vendor_travelping_80211_update_key_element) + length);

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->wlanid);
	func->read_u8(handle, &data->keyindex);
	func->read_u8(handle, &data->keystatus);
	func->read_u32(handle, &data->ciphersuite);
	data->keylength = length;
	func->read_block(handle, data->key, data->keylength);

	return data;
}

/* */
static void *capwap_vendor_travelping_80211_update_key_element_clone(void *data)
{
	struct capwap_vendor_travelping_80211_update_key_element *element =
		(struct capwap_vendor_travelping_80211_update_key_element*)data;

	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_vendor_travelping_80211_update_key_element) +
			    element->keylength);
}

/* */
static void capwap_vendor_travelping_80211_update_key_element_free(void *data)
{
	ASSERT(data != NULL);

	capwap_free(data);
}

/* */
const struct capwap_message_elements_ops capwap_element_vendor_travelping_80211_update_key_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_ARRAY,
	.create = capwap_vendor_travelping_80211_update_key_element_create,
	.parse = capwap_vendor_travelping_80211_update_key_element_parsing,
	.clone = capwap_vendor_travelping_80211_update_key_element_clone,
	.free = capwap_vendor_travelping_80211_update_key_element_free
};
