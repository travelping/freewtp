#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |   Diversity   |    Combiner   |  Antenna Cnt  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Antenna Selection...
+-+-+-+-+-+-+-+-+

Type:   1025 for IEEE 802.11 Antenna

Length:   >= 5

********************************************************************/

/* */
static void capwap_80211_antenna_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	int i;
	struct capwap_80211_antenna_element* element = (struct capwap_80211_antenna_element*)data;

	ASSERT(data != NULL);
	ASSERT(IS_VALID_RADIOID(element->radioid));
	ASSERT(element->selections != NULL);

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->diversity);
	func->write_u8(handle, element->combiner);
	func->write_u8(handle, element->selections->count);
	for (i = 0; i < element->selections->count; i++) {
		func->write_u8(handle, *(uint8_t*)capwap_array_get_item_pointer(element->selections, i));
	}
}

/* */
static void* capwap_80211_antenna_element_clone(void* data) {
	int i;
	struct capwap_80211_antenna_element* cloneelement;
	struct capwap_80211_antenna_element* element = (struct capwap_80211_antenna_element*)data;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_80211_antenna_element));
	cloneelement->selections = capwap_array_create(sizeof(uint8_t), 0, 1);
	for (i = 0; i < element->selections->count; i++) {
		memcpy(capwap_array_get_item_pointer(cloneelement->selections, i), capwap_array_get_item_pointer(element->selections, i), sizeof(uint8_t));
	}

	return cloneelement;
}

/* */
static void capwap_80211_antenna_element_free(void* data) {
	struct capwap_80211_antenna_element* element = (struct capwap_80211_antenna_element*)data;

	ASSERT(data != NULL);
	ASSERT(element->selections != NULL);

	capwap_array_free(element->selections);
	capwap_free(data);
}

/* */
static void* capwap_80211_antenna_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	int i;
	uint8_t count;
	unsigned short length;
	struct capwap_80211_antenna_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 5) {
		capwap_logging_debug("Invalid IEEE 802.11 Antenna element");
		return NULL;
	}

	length -= 4;
	if (length > CAPWAP_ANTENNASELECTIONS_MAXLENGTH) {
		capwap_logging_debug("Invalid IEEE 802.11 Antenna element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_antenna_element*)capwap_alloc(sizeof(struct capwap_80211_antenna_element));
	memset(data, 0, sizeof(struct capwap_80211_antenna_element));
	data->selections = capwap_array_create(sizeof(uint8_t), 0, 1);

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	if (!IS_VALID_RADIOID(data->radioid)) {
		capwap_80211_antenna_element_free((void*)data);
		capwap_logging_debug("Invalid IEEE 802.11 Antenna element element: invalid radio");
		return NULL;
	}

	func->read_u8(handle, &data->diversity);
	func->read_u8(handle, &data->combiner);
	func->read_u8(handle, &count);

	/* Check */
	if (count != length) {
		capwap_logging_debug("Invalid IEEE 802.11 Antenna element");
		capwap_free(data);
		return NULL;
	}

	for (i = 0; i < count; i++) {
		func->read_u8(handle, (uint8_t*)capwap_array_get_item_pointer(data->selections, i));
	}

	return data;
}

/* */
void capwap_element_80211_antenna_copy(struct capwap_80211_antenna_element* dst, struct capwap_80211_antenna_element* src) {
	int i;

	ASSERT(dst != NULL);
	ASSERT(src != NULL);

	if (dst->selections) {
		capwap_array_resize(dst->selections, 0);
	} else {
		dst->selections = capwap_array_create(sizeof(uint8_t), 0, 1);
	}

	dst->radioid = src->radioid;
	dst->diversity = src->diversity;
	dst->combiner = src->combiner;

	if (src->selections) {
		for (i = 0; i < src->selections->count; i++) {
			uint8_t* value = (uint8_t*)capwap_array_get_item_pointer(dst->selections, i);
			*value = *(uint8_t*)capwap_array_get_item_pointer(src->selections, i);
		}
	}
}

/* */
const struct capwap_message_elements_ops capwap_element_80211_antenna_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_ARRAY,
	.create = capwap_80211_antenna_element_create,
	.parse = capwap_80211_antenna_element_parsing,
	.clone = capwap_80211_antenna_element_clone,
	.free = capwap_80211_antenna_element_free
};
