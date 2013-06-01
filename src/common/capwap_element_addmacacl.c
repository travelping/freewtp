#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Num of Entries|    Length     |         MAC Address ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   7 for Add MAC ACL Entry

Length:   >= 8

********************************************************************/

/* */
static void capwap_addmacacl_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_addmacacl_element* element = (struct capwap_addmacacl_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->entry);
	func->write_u8(handle, element->length);
	func->write_block(handle, element->address, element->entry * element->length);
}

/* */
static void capwap_addmacacl_element_free(void* data) {
	struct capwap_addmacacl_element* element = (struct capwap_addmacacl_element*)data;

	ASSERT(data != NULL);

	if (element->address) {
		capwap_free(element->address);
	}

	capwap_free(element);
}

/* */
static void* capwap_addmacacl_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_addmacacl_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 8) {
		capwap_logging_debug("Invalid Add MAC ACL Entry element");
		return NULL;
	}

	length -= 2;
	if ((length % 6) && (length % 8)) {
		capwap_logging_debug("Invalid Add MAC ACL Entry element");
		return NULL;
	}

	/* */
	data = (struct capwap_addmacacl_element*)capwap_alloc(sizeof(struct capwap_addmacacl_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_addmacacl_element));

	func->read_u8(handle, &data->entry);
	func->read_u8(handle, &data->length);

	if (length != (data->entry * data->length)) {
		capwap_addmacacl_element_free((void*)data);
		capwap_logging_debug("Invalid Add MAC ACL Entry element");
		return NULL;
	}

	data->address = (uint8_t*)capwap_alloc(length);
	if (!data->address) {
		capwap_outofmemory();
	}

	func->read_block(handle, data->address, length);

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_addmacacl_ops = {
	.create_message_element = capwap_addmacacl_element_create,
	.parsing_message_element = capwap_addmacacl_element_parsing,
	.free_parsed_message_element = capwap_addmacacl_element_free
};
