#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Vendor Identifier                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Element ID           |    Data...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   37 for Vendor Specific Payload

Length:   >= 7

********************************************************************/

/* */
static void capwap_vendorpayload_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_vendorpayload_element* element = (struct capwap_vendorpayload_element*)data;

	ASSERT(data != NULL);

	func->write_u32(handle, element->vendorid);
	func->write_u16(handle, element->elementid);
	func->write_block(handle, element->data, element->datalength);
}

/* */
static void* capwap_vendorpayload_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	unsigned short length;
	struct capwap_vendorpayload_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 7) {
		capwap_logging_debug("Invalid Vendor Specific Payload element");
		return NULL;
	}

	length -= 6;
	if (length > CAPWAP_VENDORPAYLOAD_MAXLENGTH) {
		capwap_logging_debug("Invalid Vendor Specific Payload element");
		return NULL;
	}

	/* */
	data = (struct capwap_vendorpayload_element*)capwap_alloc(sizeof(struct capwap_vendorpayload_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_vendorpayload_element));
	func->read_u32(handle, &data->vendorid);
	func->read_u16(handle, &data->elementid);
	func->read_block(handle, data->data, length);

	return data;
}

/* */
static void capwap_vendorpayload_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_vendorpayload_ops = {
	.create_message_element = capwap_vendorpayload_element_create,
	.parsing_message_element = capwap_vendorpayload_element_parsing,
	.free_parsed_message_element = capwap_vendorpayload_element_free
};
