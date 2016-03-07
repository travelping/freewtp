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
|                           Group TSC                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Group TSC           |      QoS      |   Auth Type   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   MAC Mode    |  Tunnel Mode  | Suppress SSID |    SSID ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1024 for IEEE 802.11 Add WLAN

Length:   >= 20

********************************************************************/

/* */
static void capwap_80211_addwlan_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	int length;
	struct capwap_80211_addwlan_element* element = (struct capwap_80211_addwlan_element*)data;

	ASSERT(data != NULL);
	ASSERT(IS_VALID_RADIOID(element->radioid));
	ASSERT(IS_VALID_WLANID(element->wlanid));

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->wlanid);
	func->write_u16(handle, element->capability);
	func->write_u8(handle, element->keyindex);
	func->write_u8(handle, element->keystatus);
	func->write_u16(handle, element->keylength);
	if ((element->keylength > 0) && element->key) {
		func->write_block(handle, element->key, element->keylength);
	}
	func->write_block(handle, element->grouptsc, CAPWAP_ADD_WLAN_GROUPTSC_LENGTH);
	func->write_u8(handle, element->qos);
	func->write_u8(handle, element->authmode);
	func->write_u8(handle, element->macmode);
	func->write_u8(handle, element->tunnelmode);
	func->write_u8(handle, element->suppressssid);

	length = strlen((char*)element->ssid);
	ASSERT((length > 0) && (length <= CAPWAP_ADD_WLAN_SSID_LENGTH));

	func->write_block(handle, element->ssid, length);
}

/* */
static void* capwap_80211_addwlan_element_clone(void* data) {
	struct capwap_80211_addwlan_element* cloneelement;
	struct capwap_80211_addwlan_element* element = (struct capwap_80211_addwlan_element*)data;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_80211_addwlan_element));
	if (cloneelement->keylength > 0) {
		cloneelement->key = capwap_clone(element->key, cloneelement->keylength);
	}
	cloneelement->ssid = (uint8_t*)capwap_duplicate_string((char*)element->ssid);

	return cloneelement;
}

/* */
static void capwap_80211_addwlan_element_free(void* data) {
	struct capwap_80211_addwlan_element* element = (struct capwap_80211_addwlan_element*)data;

	ASSERT(data != NULL);

	if (element->ssid) {
		capwap_free(element->ssid);
	}

	if (element->key) {
		capwap_free(element->key);
	}

	capwap_free(data);
}

/* */
static void* capwap_80211_addwlan_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_80211_addwlan_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 20) {
		capwap_logging_debug("Invalid IEEE 802.11 Add WLAN element: underbuffer");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_addwlan_element*)capwap_alloc(sizeof(struct capwap_80211_addwlan_element));
	memset(data, 0, sizeof(struct capwap_80211_addwlan_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->wlanid);

	if (!IS_VALID_RADIOID(data->radioid)) {
		capwap_80211_addwlan_element_free((void*)data);
		capwap_logging_debug("Invalid IEEE 802.11 Add WLAN element: invalid radioid");
		return NULL;
	} else if (!IS_VALID_WLANID(data->wlanid)) {
		capwap_80211_addwlan_element_free((void*)data);
		capwap_logging_debug("Invalid IEEE 802.11 Add WLAN element: invalid wlanid");
		return NULL;
	}

	func->read_u16(handle, &data->capability);
	func->read_u8(handle, &data->keyindex);
	func->read_u8(handle, &data->keystatus);
	func->read_u16(handle, &data->keylength);

	if (data->keylength > 0) {
		data->key = (uint8_t*)capwap_alloc(data->keylength);
		func->read_block(handle, data->key, data->keylength);
	}

	func->read_block(handle, data->grouptsc, CAPWAP_ADD_WLAN_GROUPTSC_LENGTH);
	func->read_u8(handle, &data->qos);
	func->read_u8(handle, &data->authmode);
	func->read_u8(handle, &data->macmode);
	func->read_u8(handle, &data->tunnelmode);
	func->read_u8(handle, &data->suppressssid);

	length = func->read_ready(handle);
	if (!length || (length > CAPWAP_ADD_WLAN_SSID_LENGTH)) {
		capwap_80211_addwlan_element_free((void*)data);
		capwap_logging_debug("Invalid IEEE 802.11 Add WLAN element: invalid ssid");
		return NULL;
	}

	data->ssid = (uint8_t*)capwap_alloc(length + 1);
	func->read_block(handle, data->ssid, length);
	data->ssid[length] = 0;

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_80211_addwlan_ops = {
	.create = capwap_80211_addwlan_element_create,
	.parse = capwap_80211_addwlan_element_parsing,
	.clone = capwap_80211_addwlan_element_clone,
	.free = capwap_80211_addwlan_element_free
};
