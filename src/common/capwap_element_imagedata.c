#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Data Type   |                    Data ....
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   24 for Image Data

Length:   >= 1

********************************************************************/

/* */
static void capwap_imagedata_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_imagedata_element* element = (struct capwap_imagedata_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->type);
	func->write_block(handle, element->data, element->length);
}

/* */
static void capwap_imagedata_element_free(void* data) {
	struct capwap_imagedata_element* element = (struct capwap_imagedata_element*)data;

	ASSERT(data != NULL);

	if (element->data) {
		capwap_free(element->data);
	}

	capwap_free(element);
}

/* */
static void* capwap_imagedata_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_imagedata_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 1) {
		capwap_logging_debug("Invalid Image Data element");
		return NULL;
	}

	length -= 1;

	/* */
	data = (struct capwap_imagedata_element*)capwap_alloc(sizeof(struct capwap_imagedata_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_imagedata_element));

	func->read_u8(handle, &data->type);
	data->length = length;
	if (length > 0) {
		data->data = (uint8_t*)capwap_alloc(length);
		if (!data->data) {
			capwap_outofmemory();
		}
	
		func->read_block(handle, data->data, length);
	}

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_imagedata_ops = {
	.create_message_element = capwap_imagedata_element_create,
	.parsing_message_element = capwap_imagedata_element_parsing,
	.free_parsed_message_element = capwap_imagedata_element_free
};
