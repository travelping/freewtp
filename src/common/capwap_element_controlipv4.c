#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           IP Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           WTP Count           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   10 for CAPWAP Control IPv4 Address

Length:   6

********************************************************************/

/* */
static void capwap_controlipv4_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_controlipv4_element* element = (struct capwap_controlipv4_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_block(handle, (uint8_t*)&element->address, sizeof(struct in_addr));
	func->write_u16(handle, element->wtpcount);
}

/* */
static void* capwap_controlipv4_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_controlipv4_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 6) {
		capwap_logging_debug("Invalid Control IPv4 Address element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_controlipv4_element*)capwap_alloc(sizeof(struct capwap_controlipv4_element));
	func->read_block(handle, (uint8_t*)&data->address, sizeof(struct in_addr));
	func->read_u16(handle, &data->wtpcount);

	return data;
}

/* */
static void* capwap_controlipv4_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_controlipv4_element));
}

/* */
static void capwap_controlipv4_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_controlipv4_ops = {
	.create = capwap_controlipv4_element_create,
	.parse = capwap_controlipv4_element_parsing,
	.clone = capwap_controlipv4_element_clone,
	.free = capwap_controlipv4_element_free
};
