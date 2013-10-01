#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Radio ID    |     State     |     Cause     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   32 for Radio Operational State

Length:  3

********************************************************************/

/* */
static void capwap_radiooprstate_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_radiooprstate_element* element = (struct capwap_radiooprstate_element*)data;

	ASSERT(data != NULL);
	ASSERT(IS_VALID_RADIOID(element->radioid));
	ASSERT((element->state == CAPWAP_RADIO_OPERATIONAL_STATE_ENABLED) || (element->state == CAPWAP_RADIO_OPERATIONAL_STATE_DISABLED));
	ASSERT((element->cause == CAPWAP_RADIO_OPERATIONAL_CAUSE_NORMAL) || (element->cause == CAPWAP_RADIO_OPERATIONAL_CAUSE_RADIOFAILURE) || 
		(element->cause == CAPWAP_RADIO_OPERATIONAL_CAUSE_SOFTWAREFAILURE) || (element->cause == CAPWAP_RADIO_OPERATIONAL_CAUSE_ADMINSET));

	/* */
	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->state);
	func->write_u8(handle, element->cause);
}

/* */
static void* capwap_radiooprstate_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_radiooprstate_element));
}

/* */
static void capwap_radiooprstate_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
static void* capwap_radiooprstate_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_radiooprstate_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 3) {
		capwap_logging_debug("Invalid Radio Operational State element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_radiooprstate_element*)capwap_alloc(sizeof(struct capwap_radiooprstate_element));
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->state);
	func->read_u8(handle, &data->cause);

	if (!IS_VALID_RADIOID(data->radioid)) {
		capwap_radiooprstate_element_free((void*)data);
		capwap_logging_debug("Invalid Radio Operational State element: invalid radioid");
		return NULL;
	} else if ((data->state != CAPWAP_RADIO_OPERATIONAL_STATE_ENABLED) && (data->state != CAPWAP_RADIO_OPERATIONAL_STATE_DISABLED)) {
		capwap_radiooprstate_element_free((void*)data);
		capwap_logging_debug("Invalid Radio Operational State element: invalid state");
		return NULL;
	} else if ((data->cause != CAPWAP_RADIO_OPERATIONAL_CAUSE_NORMAL) && 
			(data->cause != CAPWAP_RADIO_OPERATIONAL_CAUSE_RADIOFAILURE) && 
			(data->cause != CAPWAP_RADIO_OPERATIONAL_CAUSE_SOFTWAREFAILURE) && 
			(data->cause != CAPWAP_RADIO_OPERATIONAL_CAUSE_ADMINSET)) {
		capwap_radiooprstate_element_free((void*)data);
		capwap_logging_debug("Invalid Radio Operational State element: invalid cause");
		return NULL;
	}

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_radiooprstate_ops = {
	.create_message_element = capwap_radiooprstate_element_create,
	.parsing_message_element = capwap_radiooprstate_element_parsing,
	.clone_message_element = capwap_radiooprstate_element_clone,
	.free_message_element = capwap_radiooprstate_element_free
};
