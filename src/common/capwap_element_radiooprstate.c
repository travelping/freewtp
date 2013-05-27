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

	/* */
	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->state);
	func->write_u8(handle, element->cause);
}

/* */
static void* capwap_radiooprstate_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_radiooprstate_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 3) {
		capwap_logging_debug("Invalid Radio Operational State element");
		return NULL;
	}

	/* */
	data = (struct capwap_radiooprstate_element*)capwap_alloc(sizeof(struct capwap_radiooprstate_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_radiooprstate_element));
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->state);
	func->read_u8(handle, &data->cause);

	return data;
}

/* */
static void capwap_radiooprstate_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_radiooprstate_ops = {
	.create_message_element = capwap_radiooprstate_element_create,
	.parsing_message_element = capwap_radiooprstate_element_parsing,
	.free_parsed_message_element = capwap_radiooprstate_element_free
};
