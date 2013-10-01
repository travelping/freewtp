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

Type:   50 for CAPWAP Local IPv6 Address
Length:   16

********************************************************************/

/* */
static void capwap_localipv6_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_localipv6_element* element = (struct capwap_localipv6_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_block(handle, (uint8_t*)&element->address, sizeof(struct in6_addr));
}

/* */
static void* capwap_localipv6_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_localipv6_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 16) {
		capwap_logging_debug("Invalid Local IPv6 Address element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_localipv6_element*)capwap_alloc(sizeof(struct capwap_localipv6_element));
	func->read_block(handle, (uint8_t*)&data->address, sizeof(struct in6_addr));

	return data;
}

/* */
static void* capwap_localipv6_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_localipv6_element));
}

/* */
static void capwap_localipv6_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_localipv6_ops = {
	.create_message_element = capwap_localipv6_element_create,
	.parsing_message_element = capwap_localipv6_element_parsing,
	.clone_message_element = capwap_localipv6_element_clone,
	.free_message_element = capwap_localipv6_element_free
};
