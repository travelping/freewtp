#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           IP Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           IP Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           IP Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           IP Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           WTP Count           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   11 for CAPWAP Control IPv6 Address

Length:   18

********************************************************************/

/* */
static void capwap_controlipv6_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_controlipv6_element* element = (struct capwap_controlipv6_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_block(handle, (uint8_t*)&element->address, sizeof(struct in6_addr));
	func->write_u16(handle, element->wtpcount);
}

/* */
static void* capwap_controlipv6_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_controlipv6_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 18) {
		capwap_logging_debug("Invalid Control IPv6 Address element");
		return NULL;
	}

	/* */
	data = (struct capwap_controlipv6_element*)capwap_alloc(sizeof(struct capwap_controlipv6_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_controlipv6_element));
	func->read_block(handle, (uint8_t*)&data->address, sizeof(struct in6_addr));
	func->read_u16(handle, &data->wtpcount);

	return data;
}

/* */
static void capwap_controlipv6_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_controlipv6_ops = {
	.create_message_element = capwap_controlipv6_element_create,
	.parsing_message_element = capwap_controlipv6_element_parsing,
	.free_parsed_message_element = capwap_controlipv6_element_free
};
