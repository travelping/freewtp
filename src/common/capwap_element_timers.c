#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Discovery   | Echo Request  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   12 for CAPWAP Timers

Length:  2

********************************************************************/

/* */
static void capwap_timers_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_timers_element* element = (struct capwap_timers_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_u8(handle, element->discovery);
	func->write_u8(handle, element->echorequest);
}

/* */
static void* capwap_timers_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_timers_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 2) {
		capwap_logging_debug("Invalid Timers element: underbuffer");
		return NULL;
	}

	/* */
	data = (struct capwap_timers_element*)capwap_alloc(sizeof(struct capwap_timers_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	func->read_u8(handle, &data->discovery);
	func->read_u8(handle, &data->echorequest);

	return data;
}

/* */
static void capwap_timers_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_timers_ops = {
	.create_message_element = capwap_timers_element_create,
	.parsing_message_element = capwap_timers_element_parsing,
	.free_parsed_message_element = capwap_timers_element_free
};
