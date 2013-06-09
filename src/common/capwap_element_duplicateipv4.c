#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          IP Address                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Status    |     Length    |          MAC Address ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   21 for Duplicate IPv4 Address

Length:   >= 12

********************************************************************/

/* */
static void capwap_duplicateipv4_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_duplicateipv4_element* element = (struct capwap_duplicateipv4_element*)data;

	ASSERT(data != NULL);
	ASSERT((element->status == CAPWAP_DUPLICATEIPv4_CLEARED) || (element->status == CAPWAP_DUPLICATEIPv4_DETECTED));
	ASSERT(IS_VALID_MACADDRESS_LENGTH(element->length));

	func->write_block(handle, (uint8_t*)&element->address, sizeof(struct in_addr));
	func->write_u8(handle, element->status);
	func->write_u8(handle, element->length);
	func->write_block(handle, element->macaddress, element->length);
}

/* */
static void capwap_duplicateipv4_element_free(void* data) {
	struct capwap_duplicateipv4_element* element = (struct capwap_duplicateipv4_element*)data;

	ASSERT(data != NULL);

	if (element->macaddress) {
		capwap_free(element->macaddress);
	}

	capwap_free(data);
}

/* */
static void* capwap_duplicateipv4_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_duplicateipv4_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 12) {
		capwap_logging_debug("Invalid Duplicate IPv4 Address element: underbuffer");
		return NULL;
	}

	length -= 6;

	/* */
	data = (struct capwap_duplicateipv4_element*)capwap_alloc(sizeof(struct capwap_duplicateipv4_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_duplicateipv4_element));
	func->read_block(handle, (uint8_t*)&data->address, sizeof(struct in_addr));
	func->read_u8(handle, &data->status);
	func->read_u8(handle, &data->length);

	if ((data->status != CAPWAP_DUPLICATEIPv4_CLEARED) && (data->status != CAPWAP_DUPLICATEIPv4_DETECTED)) {
		capwap_duplicateipv4_element_free((void*)data);
		capwap_logging_debug("Invalid Duplicate IPv4 Address element: invalid status");
		return NULL;
	} else if (!IS_VALID_MACADDRESS_LENGTH(data->length) || (length != data->length)) {
		capwap_duplicateipv4_element_free((void*)data);
		capwap_logging_debug("Invalid Duplicate IPv4 Address element: invalid length");
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
struct capwap_message_elements_ops capwap_element_duplicateipv4_ops = {
	.create_message_element = capwap_duplicateipv4_element_create,
	.parsing_message_element = capwap_duplicateipv4_element_parsing,
	.free_parsed_message_element = capwap_duplicateipv4_element_free
};
