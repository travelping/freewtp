#include "capwap.h"
#include "element.h"

/********************************************************************

 0                   1                   2
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Radio ID    |        Report Interval        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   16 for Decryption Error Report Period

Length:  3

********************************************************************/

/* */
static void capwap_decrypterrorreportperiod_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_decrypterrorreportperiod_element* element = (struct capwap_decrypterrorreportperiod_element*)data;

	ASSERT(data != NULL);
	ASSERT(IS_VALID_RADIOID(element->radioid));

	/* */
	func->write_u8(handle, element->radioid);
	func->write_u16(handle, element->interval);
}

/* */
static void* capwap_decrypterrorreportperiod_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_decrypterrorreportperiod_element));
}

/* */
static void capwap_decrypterrorreportperiod_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
static void* capwap_decrypterrorreportperiod_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_decrypterrorreportperiod_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 3) {
		log_printf(LOG_DEBUG, "Invalid Decryption Error Report Period element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_decrypterrorreportperiod_element*)capwap_alloc(sizeof(struct capwap_decrypterrorreportperiod_element));
	func->read_u8(handle, &data->radioid);
	func->read_u16(handle, &data->interval);

	if (!IS_VALID_RADIOID(data->radioid)) {
		capwap_decrypterrorreportperiod_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid Decryption Error Report Period element: invalid radioid");
		return NULL;
	}

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_decrypterrorreportperiod_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_ARRAY,
	.create = capwap_decrypterrorreportperiod_element_create,
	.parse = capwap_decrypterrorreportperiod_element_parsing,
	.clone = capwap_decrypterrorreportperiod_element_clone,
	.free = capwap_decrypterrorreportperiod_element_free
};
