#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |    WLAN ID    |          Capability           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Key Index   |   Key Status  |           Key Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Key...                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1044 for IEEE 802.11 Update WLAN

Length:   >= 8

********************************************************************/

/* */
static void capwap_80211_updatewlan_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_updatewlan_element* element = (struct capwap_80211_updatewlan_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->wlanid);
	func->write_u16(handle, element->capability);
	func->write_u8(handle, element->keyindex);
	func->write_u8(handle, element->keystatus);
	func->write_u16(handle, element->keylength);
	if ((element->keylength > 0) && element->key) {
		func->write_block(handle, element->key, element->keylength);
	}
}

/* */
static void capwap_80211_updatewlan_element_free(void* data) {
	struct capwap_80211_updatewlan_element* element = (struct capwap_80211_updatewlan_element*)data;

	ASSERT(data != NULL);

	if (element->key) {
		capwap_free(element->key);
	}

	capwap_free(data);
}

/* */
static void* capwap_80211_updatewlan_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_80211_updatewlan_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 8) {
		capwap_logging_debug("Invalid IEEE 802.11 Update WLAN element");
		return NULL;
	}

	length -= 8;

	/* */
	data = (struct capwap_80211_updatewlan_element*)capwap_alloc(sizeof(struct capwap_80211_updatewlan_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_80211_updatewlan_element));

	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->wlanid);
	func->read_u16(handle, &data->capability);
	func->read_u8(handle, &data->keyindex);
	func->read_u8(handle, &data->keystatus);
	func->read_u16(handle, &data->keylength);

	if (length != data->keylength) {
		capwap_80211_updatewlan_element_free((void*)data);
		capwap_logging_debug("Invalid IEEE 802.11 Update WLAN element");
		return NULL;
	} else if (data->keylength > 0) {
		data->key = (uint8_t*)capwap_alloc(data->keylength);
		if (!data->key) {
			capwap_outofmemory();
		}

		func->read_block(handle, data->key, data->keylength);
	}

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_80211_updatewlan_ops = {
	.create_message_element = capwap_80211_updatewlan_element_create,
	.parsing_message_element = capwap_80211_updatewlan_element_parsing,
	.free_parsed_message_element = capwap_80211_updatewlan_element_free
};
