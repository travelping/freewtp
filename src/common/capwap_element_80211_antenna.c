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
	struct capwap_80211_antenna_element* element = (struct capwap_80211_antenna_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->diversity);
	func->write_u8(handle, element->combiner);
	func->write_u8(handle, element->antennacount);
	func->write_block(handle, element->antennaselections, element->antennacount);
}

/* */
static void* capwap_80211_antenna_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
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
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_80211_antenna_element));
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->diversity);
	func->read_u8(handle, &data->combiner);
	func->read_u8(handle, &data->antennacount);

	/* Check */
	if (data->antennacount != length) {
		capwap_logging_debug("Invalid IEEE 802.11 Antenna element");
		capwap_free(data);
		return NULL;
	}

	func->read_block(handle, data->antennaselections, length);

	return data;
}

/* */
static void capwap_80211_antenna_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_antenna_ops = {
	.create_message_element = capwap_80211_antenna_element_create,
	.parsing_message_element = capwap_80211_antenna_element_parsing,
	.free_parsed_message_element = capwap_80211_antenna_element_free
};
