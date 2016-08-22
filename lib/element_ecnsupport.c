#include "capwap.h"
#include "element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|  ECN Support  |
+-+-+-+-+-+-+-+-+

Type:   53 for ECN Support

Length:  1

********************************************************************/

/* */
static void capwap_ecnsupport_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_ecnsupport_element* element = (struct capwap_ecnsupport_element*)data;

	ASSERT(data != NULL);
	ASSERT((element->flag == CAPWAP_LIMITED_ECN_SUPPORT) || (element->flag == CAPWAP_FULL_ECN_SUPPORT));

	/* */
	func->write_u8(handle, element->flag);
}

/* */
static void* capwap_ecnsupport_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_ecnsupport_element));
}

/* */
static void capwap_ecnsupport_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
static void* capwap_ecnsupport_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_ecnsupport_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 1) {
		log_printf(LOG_DEBUG, "Invalid ECN Support element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_ecnsupport_element*)capwap_alloc(sizeof(struct capwap_ecnsupport_element));
	func->read_u8(handle, &data->flag);

	if ((data->flag != CAPWAP_LIMITED_ECN_SUPPORT) && (data->flag != CAPWAP_FULL_ECN_SUPPORT)) {
		capwap_ecnsupport_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid ECN Support element: invalid flag");
		return NULL;
	}

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_ecnsupport_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_ecnsupport_element_create,
	.parse = capwap_ecnsupport_element_parsing,
	.clone = capwap_ecnsupport_element_clone,
	.free = capwap_ecnsupport_element_free
};
