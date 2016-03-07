#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Client MAC Address                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Client MAC Address       |             BSSID             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             BSSID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Radio ID    |    WLAN ID    |           Reserved            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        TKIP ICV Errors                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    TKIP Local MIC Failures                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   TKIP Remote MIC Failures                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          CCMP Replays                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        CCMP Decrypt Errors                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TKIP Replays                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


Type:   1035 for IEEE 802.11 RSNA Error Report From Station

Length:   40

********************************************************************/

/* */
static void capwap_80211_rsnaerrorreport_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_rsnaerrorreport_element* element = (struct capwap_80211_rsnaerrorreport_element*)data;

	ASSERT(data != NULL);

	func->write_block(handle, element->client, MACADDRESS_EUI48_LENGTH);
	func->write_block(handle, element->bssid, MACADDRESS_EUI48_LENGTH);
	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->wlanid);
	func->write_u16(handle, 0);
	func->write_u32(handle, element->tkipicverrors);
	func->write_u32(handle, element->tkiplocalmicfailure);
	func->write_u32(handle, element->tkipremotemicfailure);
	func->write_u32(handle, element->ccmpreplays);
	func->write_u32(handle, element->ccmpdecrypterrors);
	func->write_u32(handle, element->tkipreplays);
}

/* */
static void* capwap_80211_rsnaerrorreport_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_80211_rsnaerrorreport_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 40) {
		capwap_logging_debug("Invalid IEEE 802.11 RSNA Error Report From Station element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_rsnaerrorreport_element*)capwap_alloc(sizeof(struct capwap_80211_rsnaerrorreport_element));
	memset(data, 0, sizeof(struct capwap_80211_rsnaerrorreport_element));

	/* Retrieve data */
	func->read_block(handle, data->client, MACADDRESS_EUI48_LENGTH);
	func->read_block(handle, data->bssid, MACADDRESS_EUI48_LENGTH);
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->wlanid);
	func->read_u16(handle, NULL);
	func->read_u32(handle, &data->tkipicverrors);
	func->read_u32(handle, &data->tkiplocalmicfailure);
	func->read_u32(handle, &data->tkipremotemicfailure);
	func->read_u32(handle, &data->ccmpreplays);
	func->read_u32(handle, &data->ccmpdecrypterrors);
	func->read_u32(handle, &data->tkipreplays);

	return data;
}

/* */
static void* capwap_80211_rsnaerrorreport_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211_rsnaerrorreport_element));
}

/* */
static void capwap_80211_rsnaerrorreport_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_rsnaerrorreport_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_80211_rsnaerrorreport_element_create,
	.parse = capwap_80211_rsnaerrorreport_element_parsing,
	.clone = capwap_80211_rsnaerrorreport_element_clone,
	.free = capwap_80211_rsnaerrorreport_element_free
};
