#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Vendor Identifier                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Data...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   25 for Image Identifier

Length:   >= 5

********************************************************************/

/* */
static void capwap_imageidentifier_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	int length;
	struct capwap_imageidentifier_element* element = (struct capwap_imageidentifier_element*)data;

	ASSERT(data != NULL);

	length = strlen((char*)element->name);
	ASSERT(length <= CAPWAP_IMAGEDATA_DATA_MAX_LENGTH);

	func->write_u32(handle, element->vendor);
	func->write_block(handle, element->name, length);
}

/* */
static void capwap_imageidentifier_element_free(void* data) {
	struct capwap_imageidentifier_element* element = (struct capwap_imageidentifier_element*)data;

	ASSERT(data != NULL);

	if (element->name) {
		capwap_free(element->name);
	}

	capwap_free(data);
}

/* */
static void* capwap_imageidentifier_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_imageidentifier_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 5) {
		capwap_logging_debug("Invalid Image Indentifier element: underbuffer");
		return NULL;
	}

	length -= 4;
	if (length > CAPWAP_IMAGEIDENTIFIER_MAXLENGTH) {
		capwap_logging_debug("Invalid Image Indentifier element: invalid length");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_imageidentifier_element*)capwap_alloc(sizeof(struct capwap_imageidentifier_element));
	data->name = (uint8_t*)capwap_alloc(length + 1);
	func->read_u32(handle, &data->vendor);
	func->read_block(handle, data->name, length);
	data->name[length] = 0;

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_imageidentifier_ops = {
	.create_message_element = capwap_imageidentifier_element_create,
	.parsing_message_element = capwap_imageidentifier_element_parsing,
	.free_parsed_message_element = capwap_imageidentifier_element_free
};
