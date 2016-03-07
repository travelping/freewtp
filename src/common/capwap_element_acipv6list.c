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

Type:   3 for AC IPV6 List

Length:   >= 16

********************************************************************/

/* */
static void capwap_acipv6list_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	unsigned long i;
	struct capwap_acipv6list_element* element = (struct capwap_acipv6list_element*)data;

	ASSERT(data != NULL);

	/* */
	for (i = 0; i < element->addresses->count; i++) {
		func->write_block(handle, (uint8_t*)capwap_array_get_item_pointer(element->addresses, i), sizeof(struct in6_addr));
	}
}

/* */
static void* capwap_acipv6list_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	uint16_t length;
	struct capwap_acipv6list_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if ((length >= 16) && (length <= CAPWAP_ACIPV4LIST_MAX_ELEMENTS * 16) && (length % 16)) {
		capwap_logging_debug("Invalid AC IPv6 List element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_acipv6list_element*)capwap_alloc(sizeof(struct capwap_acipv6list_element));
	data->addresses = capwap_array_create(sizeof(struct in6_addr), 0, 0);
	while (length > 0) {
		struct in6_addr* address = (struct in6_addr*)capwap_array_get_item_pointer(data->addresses, data->addresses->count);
		func->read_block(handle, (uint8_t*)address, sizeof(struct in6_addr));
		length -= 16;
	}

	return data;
}

/* */
static void* capwap_acipv6list_element_clone(void* data) {
	int i;
	struct capwap_acipv6list_element* cloneelement;
	struct capwap_acipv6list_element* element = (struct capwap_acipv6list_element*)data;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_acipv6list_element));
	cloneelement->addresses = capwap_array_create(sizeof(struct in6_addr), 0, 0);
	for (i = 0; i < element->addresses->count; i++) {
		memcpy(capwap_array_get_item_pointer(cloneelement->addresses, i), capwap_array_get_item_pointer(element->addresses, i), sizeof(struct in6_addr));
	}

	return cloneelement;
}

/* */
static void capwap_acipv6list_element_free(void* data) {
	struct capwap_acipv6list_element* element = (struct capwap_acipv6list_element*)data;

	ASSERT(data != NULL);
	
	capwap_array_free(element->addresses);
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_acipv6list_ops = {
	.create = capwap_acipv6list_element_create,
	.parse = capwap_acipv6list_element_parsing,
	.clone = capwap_acipv6list_element_clone,
	.free = capwap_acipv6list_element_free
};
