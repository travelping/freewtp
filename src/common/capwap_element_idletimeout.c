#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Timeout                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   23 for Idle Timeout
Length:  4

********************************************************************/

/* */
static void capwap_idletimeout_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_idletimeout_element* element = (struct capwap_idletimeout_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_u32(handle, element->timeout);
}

/* */
static void* capwap_idletimeout_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_idletimeout_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 4) {
		capwap_logging_debug("Invalid Idle Timeout element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_idletimeout_element*)capwap_alloc(sizeof(struct capwap_idletimeout_element));
	func->read_u32(handle, &data->timeout);

	return data;
}

/* */
static void* capwap_idletimeout_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_idletimeout_element));
}

/* */
static void capwap_idletimeout_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_idletimeout_ops = {
	.create_message_element = capwap_idletimeout_element_create,
	.parsing_message_element = capwap_idletimeout_element_parsing,
	.clone_message_element = capwap_idletimeout_element_clone,
	.free_message_element = capwap_idletimeout_element_free
};
