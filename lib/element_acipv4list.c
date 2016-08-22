#include "capwap.h"
#include "element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           IP Address[]                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   2 for AC IPv4 List

Length:   >= 4

********************************************************************/

/* */
static void capwap_acipv4list_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	unsigned long i;
	struct capwap_acipv4list_element* element = (struct capwap_acipv4list_element*)data;

	ASSERT(data != NULL);

	/* */
	for (i = 0; i < element->addresses->count; i++) {
		func->write_block(handle, (uint8_t*)capwap_array_get_item_pointer(element->addresses, i), sizeof(struct in_addr));
	}
}

/* */
static void* capwap_acipv4list_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	uint16_t length;
	struct capwap_acipv4list_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if ((length >= 4) && (length <= CAPWAP_ACIPV4LIST_MAX_ELEMENTS * 4) && (length % 4)) {
		log_printf(LOG_DEBUG, "Invalid AC IPv4 List element: unbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_acipv4list_element*)capwap_alloc(sizeof(struct capwap_acipv4list_element));
	data->addresses = capwap_array_create(sizeof(struct in_addr), 0, 0);
	while (length > 0) {
		struct in_addr* address = (struct in_addr*)capwap_array_get_item_pointer(data->addresses, data->addresses->count);
		func->read_block(handle, (uint8_t*)address, sizeof(struct in_addr));
		length -= 4;
	}

	return data;
}

/* */
static void* capwap_acipv4list_element_clone(void* data) {
	int i;
	struct capwap_acipv4list_element* cloneelement;
	struct capwap_acipv4list_element* element = (struct capwap_acipv4list_element*)data;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_acipv4list_element));
	cloneelement->addresses = capwap_array_create(sizeof(struct in_addr), 0, 0);
	for (i = 0; i < element->addresses->count; i++) {
		memcpy(capwap_array_get_item_pointer(cloneelement->addresses, i), capwap_array_get_item_pointer(element->addresses, i), sizeof(struct in_addr));
	}

	return cloneelement;
}

/* */
static void capwap_acipv4list_element_free(void* data) {
	struct capwap_acipv4list_element* element = (struct capwap_acipv4list_element*)data;

	ASSERT(data != NULL);
	
	capwap_array_free(element->addresses);
	capwap_free(data);
}

/* */
const struct capwap_message_elements_ops capwap_element_acipv4list_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_acipv4list_element_create,
	.parse = capwap_acipv4list_element_parsing,
	.clone = capwap_acipv4list_element_clone,
	.free = capwap_acipv4list_element_free
};
