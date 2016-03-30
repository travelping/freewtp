#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|Reservd|N|E|L|U|
+-+-+-+-+-+-+-+-+

Type:   41 for WTP Frame Tunnel Mode

Length:   1

********************************************************************/

/* */
static void capwap_wtpframetunnelmode_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_wtpframetunnelmode_element* element = (struct capwap_wtpframetunnelmode_element*)data;

	ASSERT(data != NULL);
	ASSERT((element->mode & CAPWAP_WTP_FRAME_TUNNEL_MODE_MASK) == element->mode);

	/* */
	func->write_u8(handle, element->mode);
}

/* */
static void* capwap_wtpframetunnelmode_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_wtpframetunnelmode_element));
}

/* */
static void capwap_wtpframetunnelmode_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
static void* capwap_wtpframetunnelmode_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_wtpframetunnelmode_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 1) {
		log_printf(LOG_DEBUG, "Invalid WTP Frame Tunnel Mode element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_wtpframetunnelmode_element*)capwap_alloc(sizeof(struct capwap_wtpframetunnelmode_element));
	func->read_u8(handle, &data->mode);
	if ((data->mode & CAPWAP_WTP_FRAME_TUNNEL_MODE_MASK) != data->mode) {
		capwap_wtpframetunnelmode_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid WTP Frame Tunnel Mode element: invalid mode");
		return NULL;
	}

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_wtpframetunnelmode_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_wtpframetunnelmode_element_create,
	.parse = capwap_wtpframetunnelmode_element_parsing,
	.clone = capwap_wtpframetunnelmode_element_clone,
	.free = capwap_wtpframetunnelmode_element_free
};
