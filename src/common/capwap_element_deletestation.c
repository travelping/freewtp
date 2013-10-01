#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |     Length    |          MAC Address ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   18 for Delete Station

Length:   >= 8

********************************************************************/

/* */
static void capwap_deletestation_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_deletestation_element* element = (struct capwap_deletestation_element*)data;

	ASSERT(data != NULL);
	ASSERT(IS_VALID_RADIOID(element->radioid));
	ASSERT(IS_VALID_MACADDRESS_LENGTH(element->length));

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->length);
	func->write_block(handle, element->address, element->length);
}

/* */
static void* capwap_deletestation_element_clone(void* data) {
	struct capwap_deletestation_element* cloneelement;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_deletestation_element));
	if (cloneelement->length > 0) {
		cloneelement->address = capwap_clone(((struct capwap_deletestation_element*)data)->address, cloneelement->length);
	}

	return cloneelement;
}

/* */
static void capwap_deletestation_element_free(void* data) {
	struct capwap_deletestation_element* element = (struct capwap_deletestation_element*)data;

	ASSERT(data != NULL);

	if (element->address) {
		capwap_free(element->address);
	}

	capwap_free(data);
}

/* */
static void* capwap_deletestation_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_deletestation_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 8) {
		capwap_logging_debug("Invalid Delete Station element: underbuffer");
		return NULL;
	}

	length -= 2;

	/* */
	data = (struct capwap_deletestation_element*)capwap_alloc(sizeof(struct capwap_deletestation_element));
	memset(data, 0, sizeof(struct capwap_deletestation_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->length);

	if (!IS_VALID_RADIOID(data->radioid)) {
		capwap_deletestation_element_free((void*)data);
		capwap_logging_debug("Invalid Delete Station element: invalid radio");
		return NULL;
	} else if (!IS_VALID_MACADDRESS_LENGTH(data->length) || (length != data->length)) {
		capwap_deletestation_element_free((void*)data);
		capwap_logging_debug("Invalid Delete Station element: invalid length");
		return NULL;
	}

	data->address = (uint8_t*)capwap_alloc(data->length);
	func->read_block(handle, data->address, data->length);

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_deletestation_ops = {
	.create_message_element = capwap_deletestation_element_create,
	.parsing_message_element = capwap_deletestation_element_parsing,
	.clone_message_element = capwap_deletestation_element_clone,
	.free_message_element = capwap_deletestation_element_free
};
