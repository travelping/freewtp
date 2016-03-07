#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Statistics Timer       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   36 for Statistics Timer

Length:  2

********************************************************************/

/* */
static void capwap_statisticstimer_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_statisticstimer_element* element = (struct capwap_statisticstimer_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_u16(handle, element->timer);
}

/* */
static void* capwap_statisticstimer_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_statisticstimer_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 2) {
		capwap_logging_debug("Invalid Statistics Timer element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_statisticstimer_element*)capwap_alloc(sizeof(struct capwap_statisticstimer_element));
	func->read_u16(handle, &data->timer);

	return data;
}

/* */
static void* capwap_statisticstimer_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_statisticstimer_element));
}

/* */
static void capwap_statisticstimer_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_statisticstimer_ops = {
	.create = capwap_statisticstimer_element_create,
	.parse = capwap_statisticstimer_element_parsing,
	.clone = capwap_statisticstimer_element_clone,
	.free = capwap_statisticstimer_element_free
};
