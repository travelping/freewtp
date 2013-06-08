#include "capwap.h"
#include "capwap_element.h"

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
		capwap_logging_debug("Invalid AC IPv4 List element");
		return NULL;
	}

	/* */
	data = (struct capwap_acipv4list_element*)capwap_alloc(sizeof(struct capwap_acipv4list_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	data->addresses = capwap_array_create(sizeof(struct in_addr), 0, 0);
	while (length > 0) {
		struct in_addr* address = (struct in_addr*)capwap_array_get_item_pointer(data->addresses, data->addresses->count);
		func->read_block(handle, (uint8_t*)address, sizeof(struct in_addr));
		length -= 4;
	}

	return data;
}

/* */
static void capwap_acipv4list_element_free(void* data) {
	struct capwap_acipv4list_element* element = (struct capwap_acipv4list_element*)data;

	ASSERT(data != NULL);
	
	capwap_array_free(element->addresses);
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_acipv4list_ops = {
	.create_message_element = capwap_acipv4list_element_create,
	.parsing_message_element = capwap_acipv4list_element_parsing,
	.free_parsed_message_element = capwap_acipv4list_element_free
};
