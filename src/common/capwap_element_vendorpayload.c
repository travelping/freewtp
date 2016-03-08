#include "capwap.h"
#include "capwap_element.h"

/*
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       Vendor Identifier                       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          Element ID           |    Data...
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Type:   37 for Vendor Specific Payload
 *
 * Length:   >= 7
 *
 */

/* */
static void capwap_vendorpayload_element_create(void* data,
						capwap_message_elements_handle handle,
						struct capwap_write_message_elements_ops* func)
{
	struct capwap_vendorpayload_element* element = (struct capwap_vendorpayload_element *)data;

	ASSERT(data != NULL);
	ASSERT(element->datalength > 0);

	func->write_u32(handle, element->vendorid);
	func->write_u16(handle, element->elementid);
	func->write_block(handle, element->data, element->datalength);
}

/* */
static void* capwap_vendorpayload_element_clone(void *data)
{
	struct capwap_vendorpayload_element* element = (struct capwap_vendorpayload_element *)data;

	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_vendorpayload_element) + element->datalength);
}

/* */
static void capwap_vendorpayload_element_free(void *data)
{
	ASSERT(data != NULL);

	capwap_free(data);
}


/* */
void *
capwap_unknown_vendorpayload_element_parsing(capwap_message_elements_handle handle,
					     struct capwap_read_message_elements_ops *func,
					     unsigned short length,
					     const struct capwap_message_element_id vendor_id)
{
	struct capwap_vendorpayload_element* data;

	/* Retrieve data */
	data = (struct capwap_vendorpayload_element *)capwap_alloc(sizeof(struct capwap_vendorpayload_element)
								   + length);
	data->vendorid = vendor_id.vendor;
	data->elementid = vendor_id.type;
	data->datalength = length;
	func->read_block(handle, data->data, length);

	return data;
}

/* */
static void *
capwap_vendorpayload_element_parsing(capwap_message_elements_handle handle,
				     struct capwap_read_message_elements_ops *func)
{
	unsigned short length;
	struct capwap_message_element_id vendor_id;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 7) {
		capwap_logging_debug("Invalid Vendor Specific Payload element: underbuffer");
		return NULL;
	}

	length -= 6;
	if (length > CAPWAP_VENDORPAYLOAD_MAXLENGTH) {
		capwap_logging_debug("Invalid Vendor Specific Payload element: overbuffer");
		return NULL;
	}

	/* Retrieve data */
	func->read_u32(handle, &vendor_id.vendor);
	func->read_u16(handle, &vendor_id.type);

	return capwap_unknown_vendorpayload_element_parsing(handle, func, length, vendor_id);
}

/* */
const struct capwap_message_elements_ops capwap_element_vendorpayload_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_ARRAY,
	.create = capwap_vendorpayload_element_create,
	.parse = capwap_vendorpayload_element_parsing,
	.clone = capwap_vendorpayload_element_clone,
	.free = capwap_vendorpayload_element_free
};
