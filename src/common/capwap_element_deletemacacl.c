#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Num of Entries|    Length     |         MAC Address ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   17 for Delete MAC ACL Entry

Length:   >= 8

********************************************************************/

/* */
static void capwap_deletemacacl_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_deletemacacl_element* element = (struct capwap_deletemacacl_element*)data;

	ASSERT(data != NULL);
	ASSERT(element->entry > 0);
	ASSERT(IS_VALID_MACADDRESS_LENGTH(element->length));

	func->write_u8(handle, element->entry);
	func->write_u8(handle, element->length);
	func->write_block(handle, element->address, element->entry * element->length);
}

/* */
static void* capwap_deletemacacl_element_clone(void* data) {
	struct capwap_deletemacacl_element* cloneelement;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_deletemacacl_element));
	if (cloneelement->entry > 0) {
		cloneelement->address = capwap_clone(((struct capwap_deletemacacl_element*)data)->address, cloneelement->entry * cloneelement->length);
	}

	return cloneelement;
}

/* */
static void capwap_deletemacacl_element_free(void* data) {
	struct capwap_deletemacacl_element* element = (struct capwap_deletemacacl_element*)data;

	ASSERT(data != NULL);

	if (element->address) {
		capwap_free(element->address);
	}

	capwap_free(data);
}

/* */
static void* capwap_deletemacacl_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_deletemacacl_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 8) {
		capwap_logging_debug("Invalid Delete MAC ACL Entry element: underbuffer");
		return NULL;
	}

	length -= 2;

	/* */
	data = (struct capwap_deletemacacl_element*)capwap_alloc(sizeof(struct capwap_deletemacacl_element));
	memset(data, 0, sizeof(struct capwap_deletemacacl_element));

	/* Retrieve data */
	func->read_u8(handle, &data->entry);
	func->read_u8(handle, &data->length);

	if (!data->entry) {
		capwap_deletemacacl_element_free((void*)data);
		capwap_logging_debug("Invalid Delete MAC ACL Entry element: invalid entry");
		return NULL;
	} else if (!IS_VALID_MACADDRESS_LENGTH(data->length)) {
		capwap_deletemacacl_element_free((void*)data);
		capwap_logging_debug("Invalid Delete MAC ACL Entry element: invalid length");
		return NULL;
	}

	if (length != (data->entry * data->length)) {
		capwap_deletemacacl_element_free((void*)data);
		capwap_logging_debug("Invalid Delete MAC ACL Entry element");
		return NULL;
	}

	data->address = (uint8_t*)capwap_alloc(length);
	func->read_block(handle, data->address, length);

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_deletemacacl_ops = {
	.create = capwap_deletemacacl_element_create,
	.parse = capwap_deletemacacl_element_parsing,
	.clone = capwap_deletemacacl_element_clone,
	.free = capwap_deletemacacl_element_free
};
