#include "capwap.h"
#include "element.h"

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
static void* capwap_duplicateipv4_element_clone(void* data) {
	struct capwap_duplicateipv4_element* cloneelement;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_duplicateipv4_element));
	if (cloneelement->length > 0) {
		cloneelement->macaddress = capwap_clone(((struct capwap_duplicateipv4_element*)data)->macaddress, cloneelement->length);
	}

	return cloneelement;
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
		log_printf(LOG_DEBUG, "Invalid Duplicate IPv4 Address element: underbuffer");
		return NULL;
	}

	length -= 6;

	/* */
	data = (struct capwap_duplicateipv4_element*)capwap_alloc(sizeof(struct capwap_duplicateipv4_element));
	memset(data, 0, sizeof(struct capwap_duplicateipv4_element));

	/* Retrieve data */
	func->read_block(handle, (uint8_t*)&data->address, sizeof(struct in_addr));
	func->read_u8(handle, &data->status);
	func->read_u8(handle, &data->length);

	if ((data->status != CAPWAP_DUPLICATEIPv4_CLEARED) && (data->status != CAPWAP_DUPLICATEIPv4_DETECTED)) {
		capwap_duplicateipv4_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid Duplicate IPv4 Address element: invalid status");
		return NULL;
	} else if (!IS_VALID_MACADDRESS_LENGTH(data->length) || (length != data->length)) {
		capwap_duplicateipv4_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid Duplicate IPv4 Address element: invalid length");
		return NULL;
	}

	data->macaddress = (uint8_t*)capwap_alloc(data->length);
	func->read_block(handle, data->macaddress, data->length);

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_duplicateipv4_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_duplicateipv4_element_create,
	.parse = capwap_duplicateipv4_element_parsing,
	.clone = capwap_duplicateipv4_element_clone,
	.free = capwap_duplicateipv4_element_free
};
