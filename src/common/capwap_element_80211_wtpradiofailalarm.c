#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Radio ID    |     Type      |    Status     |      Pad      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1047 for IEEE 802.11 WTP Radio Fail Alarm Indication

Length:   4

********************************************************************/

/* */
static void capwap_80211_wtpradiofailalarm_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_wtpradiofailalarm_element* element = (struct capwap_80211_wtpradiofailalarm_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->type);
	func->write_u8(handle, element->status);
	func->write_u8(handle, element->pad);
}

/* */
static void* capwap_80211_wtpradiofailalarm_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_80211_wtpradiofailalarm_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 4) {
		capwap_logging_debug("Invalid IEEE 802.11 WTP Radio Fail Alarm Indication element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_wtpradiofailalarm_element*)capwap_alloc(sizeof(struct capwap_80211_wtpradiofailalarm_element));
	memset(data, 0, sizeof(struct capwap_80211_wtpradiofailalarm_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->type);
	func->read_u8(handle, &data->status);
	func->read_u8(handle, &data->pad);

	return data;
}

/* */
static void* capwap_80211_wtpradiofailalarm_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211_wtpradiofailalarm_element));
}

/* */
static void capwap_80211_wtpradiofailalarm_element_free(void* data) {
	ASSERT(data != NULL);

	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_wtpradiofailalarm_ops = {
	.create = capwap_80211_wtpradiofailalarm_element_create,
	.parse = capwap_80211_wtpradiofailalarm_element_parsing,
	.clone = capwap_80211_wtpradiofailalarm_element_clone,
	.free = capwap_80211_wtpradiofailalarm_element_free
};
