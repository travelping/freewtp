#include "capwap.h"
#include "element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|   Data Mode   |
+-+-+-+-+-+-+-+-+

Type:   14 for Data Transfer Mode

Length:   1

********************************************************************/

/* */
static void capwap_datatransfermode_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_datatransfermode_element* element = (struct capwap_datatransfermode_element*)data;

	ASSERT(data != NULL);
	ASSERT((element->mode == CAPWAP_DATATRANSFERMODE_MODE_CRASH_DUMP) || (element->mode == CAPWAP_DATATRANSFERMODE_MODE_MEMORY_DUMP));

	/* */
	func->write_u8(handle, element->mode);
}

/* */
static void* capwap_datatransfermode_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_datatransfermode_element));
}

/* */
static void capwap_datatransfermode_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
static void* capwap_datatransfermode_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_datatransfermode_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 1) {
		log_printf(LOG_DEBUG, "Invalid Data Transfer Mode element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_datatransfermode_element*)capwap_alloc(sizeof(struct capwap_datatransfermode_element));
	func->read_u8(handle, &data->mode);
	if ((data->mode != CAPWAP_DATATRANSFERMODE_MODE_CRASH_DUMP) && (data->mode != CAPWAP_DATATRANSFERMODE_MODE_MEMORY_DUMP)) {
		capwap_datatransfermode_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid Data Transfer Mode element: invalid mode");
		return NULL;
	}

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_datatransfermode_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_datatransfermode_element_create,
	.parse = capwap_datatransfermode_element_parsing,
	.clone = capwap_datatransfermode_element_clone,
	.free = capwap_datatransfermode_element_free
};
