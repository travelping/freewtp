#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Session ID                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Session ID                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Session ID                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Session ID                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


Type:   35 for Session ID
Length:   16

********************************************************************/

/* */
void capwap_sessionid_generate(struct capwap_sessionid_element* session) {
	int i;

	ASSERT(session != NULL);

	for (i = 0; i < 16; i++) {
		session->id[i] = (uint8_t)capwap_get_rand(256);
	}
}

/* */
void capwap_sessionid_printf(struct capwap_sessionid_element* session, char* string) {
	int i;
	char* pos = string;

	ASSERT(session != NULL);
	ASSERT(string != NULL);

	for (i = 0; i < 16; i++) {
		sprintf(pos, "%02x", session->id[i]);
		pos += 2;
	}

	*pos = 0;
}

/* */
static void capwap_sessionid_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_sessionid_element* element = (struct capwap_sessionid_element*)data;

	ASSERT(data != NULL);

	func->write_block(handle, element->id, 16);
}

/* */
static void* capwap_sessionid_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_sessionid_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 16) {
		capwap_logging_debug("Invalid Session ID element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_sessionid_element*)capwap_alloc(sizeof(struct capwap_sessionid_element));
	func->read_block(handle, data->id, 16);

	return data;
}

/* */
static void* capwap_sessionid_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_sessionid_element));
}

/* */
static void capwap_sessionid_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_sessionid_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_sessionid_element_create,
	.parse = capwap_sessionid_element_parsing,
	.clone = capwap_sessionid_element_clone,
	.free = capwap_sessionid_element_free
};
