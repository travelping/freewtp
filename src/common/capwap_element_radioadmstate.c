#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Radio ID    |  Admin State  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   31 for Radio Administrative State

Length:  2

********************************************************************/

/* */
static void capwap_radioadmstate_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_radioadmstate_element* element = (struct capwap_radioadmstate_element*)data;

	ASSERT(data != NULL);
	ASSERT(IS_VALID_RADIOID(element->radioid));
	ASSERT((element->state == CAPWAP_RADIO_ADMIN_STATE_ENABLED) || (element->state == CAPWAP_RADIO_ADMIN_STATE_DISABLED));

	/* */
	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->state);
}

/* */
static void* capwap_radioadmstate_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_radioadmstate_element));
}

/* */
static void capwap_radioadmstate_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
static void* capwap_radioadmstate_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_radioadmstate_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 2) {
		capwap_logging_debug("Invalid Radio Administrative State element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_radioadmstate_element*)capwap_alloc(sizeof(struct capwap_radioadmstate_element));
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->state);

	if (!IS_VALID_RADIOID(data->radioid)) {
		capwap_radioadmstate_element_free((void*)data);
		capwap_logging_debug("Invalid Radio Administrative State element: invalid radioid");
		return NULL;
	} else if ((data->state != CAPWAP_RADIO_ADMIN_STATE_ENABLED) && (data->state != CAPWAP_RADIO_ADMIN_STATE_DISABLED)) {
		capwap_radioadmstate_element_free((void*)data);
		capwap_logging_debug("Invalid Radio Administrative State element: invalid state");
		return NULL;
	}

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_radioadmstate_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_ARRAY,
	.create = capwap_radioadmstate_element_create,
	.parse = capwap_radioadmstate_element_parsing,
	.clone = capwap_radioadmstate_element_clone,
	.free = capwap_radioadmstate_element_free
};
