#include "capwap.h"
#include "element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |        Association ID         |     Flags     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           MAC Address                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          MAC Address          |          Capabilities         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   WLAN ID     |Supported Rates|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1036 for IEEE 802.11 Station

Length:   >= 14

********************************************************************/

/* */
static void capwap_80211_station_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_station_element* element = (struct capwap_80211_station_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	func->write_u16(handle, element->associationid);
	func->write_u8(handle, element->flags);
	func->write_block(handle, element->address, MACADDRESS_EUI48_LENGTH);
	func->write_u16(handle, element->capabilities);
	func->write_u8(handle, element->wlanid);
	func->write_block(handle, element->supportedrates, element->supportedratescount);
}

/* */
static void* capwap_80211_station_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_80211_station_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 14) {
		log_printf(LOG_DEBUG, "Invalid IEEE 802.11 Station element");
		return NULL;
	}

	length -= 13;
	if (length > CAPWAP_STATION_RATES_MAXLENGTH) {
		log_printf(LOG_DEBUG, "Invalid IEEE 802.11 Station element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_station_element*)capwap_alloc(sizeof(struct capwap_80211_station_element));
	memset(data, 0, sizeof(struct capwap_80211_station_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u16(handle, &data->associationid);
	func->read_u8(handle, &data->flags);
	func->read_block(handle, data->address, MACADDRESS_EUI48_LENGTH);
	func->read_u16(handle, &data->capabilities);
	func->read_u8(handle, &data->wlanid);
	data->supportedratescount = length;
	func->read_block(handle, data->supportedrates, length);

	return data;
}

/* */
static void* capwap_80211_station_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211_station_element));
}

/* */
static void capwap_80211_station_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
const struct capwap_message_elements_ops capwap_element_80211_station_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_80211_station_element_create,
	.parse = capwap_80211_station_element_parsing,
	.clone = capwap_80211_station_element_clone,
	.free = capwap_80211_station_element_free
};
