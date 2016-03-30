#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|   MAC Type    |
+-+-+-+-+-+-+-+-+

Type:   44 for WTP MAC Type

Length:  1

********************************************************************/

/* */
static void capwap_wtpmactype_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_wtpmactype_element* element = (struct capwap_wtpmactype_element*)data;

	ASSERT(data != NULL);
	ASSERT((element->type == CAPWAP_LOCALMAC) || (element->type == CAPWAP_SPLITMAC) || (element->type == CAPWAP_LOCALANDSPLITMAC));

	/* */
	func->write_u8(handle, element->type);
}

/* */
static void* capwap_wtpmactype_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_wtpmactype_element));
}

/* */
static void capwap_wtpmactype_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
static void* capwap_wtpmactype_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_wtpmactype_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 1) {
		log_printf(LOG_DEBUG, "Invalid WTP MAC Type element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_wtpmactype_element*)capwap_alloc(sizeof(struct capwap_wtpmactype_element));
	func->read_u8(handle, &data->type);
	if ((data->type != CAPWAP_LOCALMAC) && (data->type != CAPWAP_SPLITMAC) && (data->type != CAPWAP_LOCALANDSPLITMAC)) {
		capwap_wtpmactype_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid WTP MAC Type element: invalid type");
		return NULL;
	}

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_wtpmactype_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_wtpmactype_element_create,
	.parse = capwap_wtpmactype_element_parsing,
	.clone = capwap_wtpmactype_element_clone,
	.free = capwap_wtpmactype_element_free
};
