#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Reason     |    Length     |       Message Element...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   34 for Returned Message Element

Length:  >= 6

********************************************************************/

/* */
static void capwap_returnedmessage_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_returnedmessage_element* element = (struct capwap_returnedmessage_element*)data;

	ASSERT(data != NULL);
	ASSERT(element->length >= 4);
	ASSERT((element->reason == CAPWAP_RETURNED_MESSAGE_UNKNOWN_MESSAGE_ELEMENT) || (element->reason == CAPWAP_RETURNED_MESSAGE_UNSUPPORTED_MESSAGE_ELEMENT) || 
		(element->reason == CAPWAP_RETURNED_MESSAGE_UNKNOWN_MESSAGE_ELEMENT_VALUE) || (element->reason == CAPWAP_RETURNED_MESSAGE_UNSUPPORTED_MESSAGE_ELEMENT_VALUE));

	func->write_u8(handle, element->reason);
	func->write_u8(handle, element->length);
	func->write_block(handle, element->message, element->length);
}

/* */
static void capwap_returnedmessage_element_free(void* data) {
	struct capwap_returnedmessage_element* element = (struct capwap_returnedmessage_element*)data;

	ASSERT(data != NULL);

	if (element->message) {
		capwap_free(element->message);
	}

	capwap_free(data);
}

/* */
static void* capwap_returnedmessage_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_returnedmessage_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 6) {
		capwap_logging_debug("Invalid Returned Message element: underbuffer");
		return NULL;
	}

	length -= 2;
	if (length > CAPWAP_RETURNED_MESSAGE_MAX_LENGTH) {
		capwap_logging_debug("Invalid Returned Message element: overbuffer");
		return NULL;
	}

	/* */
	data = (struct capwap_returnedmessage_element*)capwap_alloc(sizeof(struct capwap_returnedmessage_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_returnedmessage_element));
	func->read_u8(handle, &data->reason);
	func->read_u8(handle, &data->length);

	if ((data->reason != CAPWAP_RETURNED_MESSAGE_UNKNOWN_MESSAGE_ELEMENT) &&
		(data->reason != CAPWAP_RETURNED_MESSAGE_UNSUPPORTED_MESSAGE_ELEMENT) &&
		(data->reason != CAPWAP_RETURNED_MESSAGE_UNKNOWN_MESSAGE_ELEMENT_VALUE) &&
		(data->reason != CAPWAP_RETURNED_MESSAGE_UNSUPPORTED_MESSAGE_ELEMENT_VALUE)) {
		capwap_returnedmessage_element_free((void*)data);
		capwap_logging_debug("Invalid Returned Message element: invalid reason");
		return NULL;
	} else if (data->length != length) {
		capwap_returnedmessage_element_free((void*)data);
		capwap_logging_debug("Invalid Returned Message element: invalid length");
		return NULL;
	}

	data->message = (uint8_t*)capwap_alloc(data->length);
	if (!data->message) {
		capwap_outofmemory();
	}

	func->read_block(handle, data->message, data->length);

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_returnedmessage_ops = {
	.create_message_element = capwap_returnedmessage_element_create,
	.parsing_message_element = capwap_returnedmessage_element_parsing,
	.free_parsed_message_element = capwap_returnedmessage_element_free
};
