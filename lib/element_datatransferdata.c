#include "capwap.h"
#include "element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Data Type   |   Data Mode   |         Data Length           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Data ....
+-+-+-+-+-+-+-+-+

Type:   13 for Data Transfer Data

Length:   >= 5

********************************************************************/

/* */
static void capwap_datatransferdata_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_datatransferdata_element* element = (struct capwap_datatransferdata_element*)data;

	ASSERT(data != NULL);
	ASSERT((element->type == CAPWAP_DATATRANSFERDATA_TYPE_DATA_IS_INCLUDED) || (element->type == CAPWAP_DATATRANSFERDATA_TYPE_DATA_EOF) || (element->type == CAPWAP_DATATRANSFERDATA_TYPE_ERROR));
	ASSERT((element->mode == CAPWAP_DATATRANSFERDATA_MODE_CRASH_DUMP) || (element->mode == CAPWAP_DATATRANSFERDATA_MODE_MEMORY_DUMP));
	ASSERT(element->length > 0);

	func->write_u8(handle, element->type);
	func->write_u8(handle, element->mode);
	func->write_u16(handle, element->length);
	func->write_block(handle, element->data, element->length);
}

/* */
static void* capwap_datatransferdata_element_clone(void* data) {
	struct capwap_datatransferdata_element* cloneelement;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_datatransferdata_element));
	if (cloneelement->length > 0) {
		cloneelement->data = capwap_clone(((struct capwap_datatransferdata_element*)data)->data, cloneelement->length);
	}

	return cloneelement;
}

/* */
static void capwap_datatransferdata_element_free(void* data) {
	struct capwap_datatransferdata_element* element = (struct capwap_datatransferdata_element*)data;

	ASSERT(data != NULL);

	if (element->data) {
		capwap_free(element->data);
	}

	capwap_free(data);
}

/* */
static void* capwap_datatransferdata_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_datatransferdata_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 5) {
		log_printf(LOG_DEBUG, "Invalid Data Transfer Data element: underbuffer");
		return NULL;
	}

	length -= 4;

	/* */
	data = (struct capwap_datatransferdata_element*)capwap_alloc(sizeof(struct capwap_datatransferdata_element));
	memset(data, 0, sizeof(struct capwap_datatransferdata_element));

	/* Retrieve data */
	func->read_u8(handle, &data->type);
	func->read_u8(handle, &data->mode);
	func->read_u16(handle, &data->length);

	if ((data->type != CAPWAP_DATATRANSFERDATA_TYPE_DATA_IS_INCLUDED) && (data->type != CAPWAP_DATATRANSFERDATA_TYPE_DATA_EOF) && (data->type != CAPWAP_DATATRANSFERDATA_TYPE_ERROR)) {
		capwap_datatransferdata_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid Data Transfer Data element: invalid type");
		return NULL;
	} else if ((data->mode != CAPWAP_DATATRANSFERDATA_MODE_CRASH_DUMP) && (data->mode != CAPWAP_DATATRANSFERDATA_MODE_MEMORY_DUMP)) {
		capwap_datatransferdata_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid Data Transfer Data element: invalid mode");
		return NULL;
	} else if (length != data->length) {
		capwap_datatransferdata_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid Data Transfer Data element: invalid length");
		return NULL;
	}

	data->data = (uint8_t*)capwap_alloc(length);
	func->read_block(handle, data->data, length);

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_datatransferdata_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_datatransferdata_element_create,
	.parse = capwap_datatransferdata_element_parsing,
	.clone = capwap_datatransferdata_element_clone,
	.free = capwap_datatransferdata_element_free
};
