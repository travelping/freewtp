#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|   Name ...
+-+-+-+-+-+-+-+-+

Type:   45 for WTP Name

Length:   >= 1

********************************************************************/

/* */
static void capwap_wtpname_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_wtpname_element* element = (struct capwap_wtpname_element*)data;

	ASSERT(data != NULL);

	func->write_block(handle, element->name, strlen((char*)element->name));
}

/* */
static void* capwap_wtpname_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_wtpname_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if ((length < 1) || (length > CAPWAP_WTPNAME_MAXLENGTH)) {
		capwap_logging_debug("Invalid WTP Name element");
		return NULL;
	}

	/* */
	data = (struct capwap_wtpname_element*)capwap_alloc(sizeof(struct capwap_wtpname_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_wtpname_element));
	func->read_block(handle, data->name, length);

	return data;
}

/* */
static void capwap_wtpname_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_wtpname_ops = {
	.create_message_element = capwap_wtpname_element_create,
	.parsing_message_element = capwap_wtpname_element_parsing,
	.free_parsed_message_element = capwap_wtpname_element_free
};
