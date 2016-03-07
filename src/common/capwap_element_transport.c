#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|   Transport   |
+-+-+-+-+-+-+-+-+

Type:   51 for CAPWAP Transport Protocol

Length:  1

********************************************************************/

/* */
static void capwap_transport_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_transport_element* element = (struct capwap_transport_element*)data;

	ASSERT(data != NULL);
	ASSERT((element->type == CAPWAP_UDPLITE_TRANSPORT) || (element->type == CAPWAP_UDP_TRANSPORT));

	/* */
	func->write_u8(handle, element->type);
}

/* */
static void* capwap_transport_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_transport_element));
}

/* */
static void capwap_transport_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
static void* capwap_transport_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_transport_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 1) {
		capwap_logging_debug("Invalid Transport Protocol element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_transport_element*)capwap_alloc(sizeof(struct capwap_transport_element));
	func->read_u8(handle, &data->type);
	if ((data->type != CAPWAP_UDPLITE_TRANSPORT) && (data->type != CAPWAP_UDP_TRANSPORT)) {
		capwap_transport_element_free((void*)data);
		capwap_logging_debug("Invalid Transport Protocol element: invalid type");
		return NULL;
	}

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_transport_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_transport_element_create,
	.parse = capwap_transport_element_parsing,
	.clone = capwap_transport_element_clone,
	.free = capwap_transport_element_free
};
