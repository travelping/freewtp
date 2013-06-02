#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          IP Address                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          IP Address                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          IP Address                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          IP Address                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Status    |     Length    |         MAC Address ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   22 for Duplicate IPv6 Address

Length:   >= 24

********************************************************************/

/* */
static void capwap_duplicateipv6_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_duplicateipv6_element* element = (struct capwap_duplicateipv6_element*)data;

	ASSERT(data != NULL);

	func->write_block(handle, (uint8_t*)&element->address, sizeof(struct in6_addr));
	func->write_u8(handle, element->status);
	func->write_u8(handle, element->length);
	func->write_block(handle, element->macaddress, element->length);
}

/* */
static void capwap_duplicateipv6_element_free(void* data) {
	struct capwap_duplicateipv6_element* element = (struct capwap_duplicateipv6_element*)data;

	ASSERT(data != NULL);

	if (element->macaddress) {
		capwap_free(element->macaddress);
	}

	capwap_free(element);
}

/* */
static void* capwap_duplicateipv6_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_duplicateipv6_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 24) {
		capwap_logging_debug("Invalid Duplicate IPv6 Address element");
		return NULL;
	}

	length -= 18;

	/* */
	data = (struct capwap_duplicateipv6_element*)capwap_alloc(sizeof(struct capwap_duplicateipv6_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_duplicateipv6_element));

	func->read_block(handle, (uint8_t*)&data->address, sizeof(struct in6_addr));
	func->read_u8(handle, &data->status);
	func->read_u8(handle, &data->length);

	if (length != data->length) {
		capwap_duplicateipv6_element_free((void*)data);
		capwap_logging_debug("Invalid Duplicate IPv6 Address element");
		return NULL;
	}

	data->macaddress = (uint8_t*)capwap_alloc(data->length);
	if (!data->macaddress) {
		capwap_outofmemory();
	}

	func->read_block(handle, data->macaddress, data->length);

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_duplicateipv6_ops = {
	.create_message_element = capwap_duplicateipv6_element_create,
	.parsing_message_element = capwap_duplicateipv6_element_parsing,
	.free_parsed_message_element = capwap_duplicateipv6_element_free
};
