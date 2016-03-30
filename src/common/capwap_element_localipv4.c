#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           IP Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   30 for CAPWAP Local IPv4 Address

Length:   4

********************************************************************/

/* */
static void capwap_localipv4_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_localipv4_element* element = (struct capwap_localipv4_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_block(handle, (uint8_t*)&element->address, sizeof(struct in_addr));
}

/* */
static void* capwap_localipv4_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_localipv4_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 4) {
		log_printf(LOG_DEBUG, "Invalid Local IPv4 Address element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_localipv4_element*)capwap_alloc(sizeof(struct capwap_localipv4_element));
	func->read_block(handle, (uint8_t*)&data->address, sizeof(struct in_addr));

	return data;
}

/* */
static void* capwap_localipv4_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_localipv4_element));
}

/* */
static void capwap_localipv4_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
const struct capwap_message_elements_ops capwap_element_localipv4_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_localipv4_element_create,
	.parse = capwap_localipv4_element_parsing,
	.clone = capwap_localipv4_element_clone,
	.free = capwap_localipv4_element_free
};
