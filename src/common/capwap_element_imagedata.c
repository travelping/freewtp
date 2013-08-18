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
	ASSERT((element->type == CAPWAP_IMAGEDATA_TYPE_DATA_IS_INCLUDED) || (element->type == CAPWAP_IMAGEDATA_TYPE_DATA_EOF) || (element->type == CAPWAP_IMAGEDATA_TYPE_ERROR));
	ASSERT(element->length <= CAPWAP_IMAGEDATA_DATA_MAX_LENGTH);

	func->write_u8(handle, element->type);
	if (element->length > 0) {
		func->write_block(handle, element->data, element->length);
	}
}

/* */
static void capwap_imagedata_element_free(void* data) {
	struct capwap_imagedata_element* element = (struct capwap_imagedata_element*)data;

	ASSERT(data != NULL);

	if (element->data) {
		capwap_free(element->data);
	}

	capwap_free(data);
}

/* */
static void* capwap_imagedata_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_imagedata_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 1) {
		capwap_logging_debug("Invalid Image Data element: underbuffer");
		return NULL;
	}

	length -= 1;

	/* */
	data = (struct capwap_imagedata_element*)capwap_alloc(sizeof(struct capwap_imagedata_element));
	memset(data, 0, sizeof(struct capwap_imagedata_element));

	/* Retrieve data */
	func->read_u8(handle, &data->type);
	if ((data->type != CAPWAP_IMAGEDATA_TYPE_DATA_IS_INCLUDED) && (data->type != CAPWAP_IMAGEDATA_TYPE_DATA_EOF) && (data->type != CAPWAP_IMAGEDATA_TYPE_ERROR)) {
		capwap_imagedata_element_free((void*)data);
		capwap_logging_debug("Invalid Image Data element: underbuffer: invalid type");
		return NULL;
	} else if ((data->type == CAPWAP_IMAGEDATA_TYPE_ERROR) && (length > 0)) {
		capwap_imagedata_element_free((void*)data);
		capwap_logging_debug("Invalid Image Data element: underbuffer: invalid error type");
		return NULL;
	} else if (length > CAPWAP_IMAGEDATA_DATA_MAX_LENGTH) {
		capwap_imagedata_element_free((void*)data);
		capwap_logging_debug("Invalid Image Data element: underbuffer: invalid length");
		return NULL;
	}

	data->length = length;
	if (!length) {
		data->data = NULL;
	} else {
		data->data = (uint8_t*)capwap_alloc(length);
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
