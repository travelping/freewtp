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
static void* capwap_location_element_clone(void* data) {
	struct capwap_location_element* cloneelement;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_location_element));
	cloneelement->value = (uint8_t*)capwap_duplicate_string((char*)((struct capwap_location_element*)data)->value);

	return cloneelement;
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

	/* Retrieve data */
	data = (struct capwap_location_element*)capwap_alloc(sizeof(struct capwap_location_element));
	data->value = (uint8_t*)capwap_alloc(length + 1);
	func->read_block(handle, data->value, length);
	data->value[length] = 0;

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_location_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_location_element_create,
	.parse = capwap_location_element_parsing,
	.clone = capwap_location_element_clone,
	.free = capwap_location_element_free
};
