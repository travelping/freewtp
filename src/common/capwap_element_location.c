#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|   Location ...
+-+-+-+-+-+-+-+-+

Type:   28 for Location Data

Length:   >= 1

********************************************************************/

/* */
static void capwap_location_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	int length;
	struct capwap_location_element* element = (struct capwap_location_element*)data;

	ASSERT(data != NULL);

	length = strlen((char*)element->value);
	ASSERT(length <= CAPWAP_LOCATION_MAXLENGTH);

	func->write_block(handle, element->value, length);
}

/* */
static void capwap_location_element_free(void* data) {
	struct capwap_location_element* element = (struct capwap_location_element*)data;

	ASSERT(data != NULL);

	if (element->value) {
		capwap_free(element->value);
	}

	capwap_free(data);
}

/* */
static void* capwap_location_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_location_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if ((length < 1) || (length > CAPWAP_LOCATION_MAXLENGTH)) {
		capwap_logging_debug("Invalid Location Data element: underbuffer");
		return NULL;
	}

	/* */
	data = (struct capwap_location_element*)capwap_alloc(sizeof(struct capwap_location_element));
	if (!data) {
		capwap_outofmemory();
	}

	data->value = (uint8_t*)capwap_alloc(length + 1);
	if (!data->value) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	func->read_block(handle, data->value, length);
	data->value[length] = 0;

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_location_ops = {
	.create_message_element = capwap_location_element_create,
	.parsing_message_element = capwap_location_element_parsing,
	.free_parsed_message_element = capwap_location_element_free
};
