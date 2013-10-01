#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |   Num Levels  |        Power Level [n]        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1042 for IEEE 802.11 Tx Power Level

Length:   >= 4

********************************************************************/

/* */
static void capwap_80211_txpowerlevel_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	int i;
	struct capwap_80211_txpowerlevel_element* element = (struct capwap_80211_txpowerlevel_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->numlevels);
	for (i = 0; i < element->numlevels; i++) {
		func->write_u16(handle, element->powerlevel[i]);
	}
}

/* */
static void* capwap_80211_txpowerlevel_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	int i;
	unsigned short length;
	struct capwap_80211_txpowerlevel_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 4) {
		capwap_logging_debug("Invalid IEEE 802.11 Tx Power Level element");
		return NULL;
	}

	length -= 2;
	if ((length % sizeof(uint16_t)) || ((length / sizeof(uint16_t)) > CAPWAP_TXPOWERLEVEL_MAXLENGTH)) {
		capwap_logging_debug("Invalid IEEE 802.11 Tx Power Level element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_txpowerlevel_element*)capwap_alloc(sizeof(struct capwap_80211_txpowerlevel_element));
	memset(data, 0, sizeof(struct capwap_80211_txpowerlevel_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->numlevels);

	/* Check */
	if ((data->numlevels * sizeof(uint16_t)) != length) {
		capwap_logging_debug("Invalid IEEE 802.11 Tx Power Level element");
		capwap_free(data);
		return NULL;
	}

	for (i = 0; i < data->numlevels; i++) {
		func->read_u16(handle, &data->powerlevel[i]);
	}

	return data;
}

/* */
static void* capwap_80211_txpowerlevel_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211_txpowerlevel_element));
}

/* */
static void capwap_80211_txpowerlevel_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_txpowerlevel_ops = {
	.create_message_element = capwap_80211_txpowerlevel_element_create,
	.parsing_message_element = capwap_80211_txpowerlevel_element_parsing,
	.clone_message_element = capwap_80211_txpowerlevel_element_clone,
	.free_message_element = capwap_80211_txpowerlevel_element_free
};
