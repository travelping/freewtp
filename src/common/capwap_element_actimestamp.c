#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   6 for AC Timestamp

Length:   4

********************************************************************/

/* */
static void capwap_actimestamp_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_actimestamp_element* element = (struct capwap_actimestamp_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_u32(handle, element->timestamp);
}

/* */
static void* capwap_actimestamp_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_actimestamp_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 4) {
		capwap_logging_debug("Invalid AC Timestamp element: underbuffer");
		return NULL;
	}

	/* */
	data = (struct capwap_actimestamp_element*)capwap_alloc(sizeof(struct capwap_actimestamp_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	func->read_u32(handle, &data->timestamp);

	return data;
}

/* */
static void capwap_actimestamp_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_actimestamp_ops = {
	.create_message_element = capwap_actimestamp_element_create,
	.parsing_message_element = capwap_actimestamp_element_parsing,
	.free_parsed_message_element = capwap_actimestamp_element_free
};
