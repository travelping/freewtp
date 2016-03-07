#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Result Code                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   33 for Result Code

Length:  4

********************************************************************/

/* */
static void capwap_resultcode_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_resultcode_element* element = (struct capwap_resultcode_element*)data;

	ASSERT(data != NULL);
	ASSERT((element->code >= CAPWAP_RESULTCODE_FIRST) && (element->code <= CAPWAP_RESULTCODE_LAST));

	/* */
	func->write_u32(handle, element->code);
}

/* */
static void* capwap_resultcode_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_resultcode_element));
}

/* */
static void capwap_resultcode_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
static void* capwap_resultcode_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_resultcode_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 4) {
		capwap_logging_debug("Invalid Result Code element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_resultcode_element*)capwap_alloc(sizeof(struct capwap_resultcode_element));
	func->read_u32(handle, &data->code);
	if ((data->code < CAPWAP_RESULTCODE_FIRST) || (data->code > CAPWAP_RESULTCODE_LAST)) {
		capwap_resultcode_element_free((void*)data);
		capwap_logging_debug("Invalid Result Code element: invalid code");
		return NULL;
	}

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_resultcode_ops = {
	.create = capwap_resultcode_element_create,
	.parse = capwap_resultcode_element_parsing,
	.clone = capwap_resultcode_element_clone,
	.free = capwap_resultcode_element_free
};
