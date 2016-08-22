#include "capwap.h"
#include "element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |    Reserved   | Current Chan  |  Current CCA  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Energy Detect Threshold                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1028 for IEEE 802.11 Direct Sequence Control

Length:   8

********************************************************************/

/* */
static void capwap_80211_directsequencecontrol_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_80211_directsequencecontrol_element* element = (struct capwap_80211_directsequencecontrol_element*)data;

	ASSERT(data != NULL);
	ASSERT(IS_VALID_RADIOID(element->radioid));

	/* */
	func->write_u8(handle, element->radioid);
	func->write_u8(handle, 0);
	func->write_u8(handle, element->currentchannel);
	func->write_u8(handle, element->currentcca);
	func->write_u32(handle, element->enerydetectthreshold);
}

/* */
static void* capwap_80211_directsequencecontrol_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211_directsequencecontrol_element));
}

/* */
static void capwap_80211_directsequencecontrol_element_free(void* data) {
	ASSERT(data != NULL);

	capwap_free(data);
}

/* */
static void* capwap_80211_directsequencecontrol_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_80211_directsequencecontrol_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 8) {
		log_printf(LOG_DEBUG, "Invalid IEEE 802.11 Direct Sequence Control element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_directsequencecontrol_element*)capwap_alloc(sizeof(struct capwap_80211_directsequencecontrol_element));
	memset(data, 0, sizeof(struct capwap_80211_directsequencecontrol_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	if (!IS_VALID_RADIOID(data->radioid)) {
		capwap_80211_directsequencecontrol_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid IEEE 802.11 Direct Sequence Control element: invalid radio");
		return NULL;
	}

	func->read_u8(handle, NULL);
	func->read_u8(handle, &data->currentchannel);
	func->read_u8(handle, &data->currentcca);
	func->read_u32(handle, &data->enerydetectthreshold);

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_80211_directsequencecontrol_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_ARRAY,
	.create = capwap_80211_directsequencecontrol_element_create,
	.parse = capwap_80211_directsequencecontrol_element_parsing,
	.clone = capwap_80211_directsequencecontrol_element_clone,
	.free = capwap_80211_directsequencecontrol_element_free
};
