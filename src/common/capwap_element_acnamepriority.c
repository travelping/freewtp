#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Priority  |   AC Name...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   5 for AC Name with Priority

Length:   >= 2

********************************************************************/

/* */
static void capwap_acnamepriority_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_acnamepriority_element* element = (struct capwap_acnamepriority_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->priority);
	func->write_block(handle, element->name, strlen((char*)element->name));
}

/* */
static void* capwap_acnamepriority_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_acnamepriority_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle) - 1;
	if ((length < 1) || (length > CAPWAP_ACNAMEPRIORITY_MAXLENGTH)) {
		capwap_logging_debug("Invalid AC Name Priority element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_acnamepriority_element*)capwap_alloc(sizeof(struct capwap_acnamepriority_element));
	data->name = (uint8_t*)capwap_alloc(length + 1);
	func->read_u8(handle, &data->priority);
	func->read_block(handle, data->name, length);
	data->name[length] = 0;

	return data;
}

/* */
static void* capwap_acnamepriority_element_clone(void* data) {
	struct capwap_acnamepriority_element* cloneelement;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_acnamepriority_element));
	if (cloneelement->name) {
		cloneelement->name = (uint8_t*)capwap_duplicate_string((char*)((struct capwap_acnamepriority_element*)data)->name);
	}

	return cloneelement;
}

/* */
static void capwap_acnamepriority_element_free(void* data) {
	struct capwap_acnamepriority_element* element = (struct capwap_acnamepriority_element*)data;

	ASSERT(data != NULL);

	if (element->name) {
		capwap_free(element->name);
	}

	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_acnamepriority_ops = {
	.create = capwap_acnamepriority_element_create,
	.parse = capwap_acnamepriority_element_parsing,
	.clone = capwap_acnamepriority_element_clone,
	.free = capwap_acnamepriority_element_free
};
