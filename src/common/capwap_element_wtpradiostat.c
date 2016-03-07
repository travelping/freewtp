#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Radio ID    | Last Fail Type|          Reset Count          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       SW Failure Count        |        HW Failure Count       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Other  Failure Count      |     Unknown Failure Count     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Config Update Count      |     Channel Change Count      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Band Change Count       |      Current Noise Floor      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   47 for WTP Radio Statistics

Length:   20

********************************************************************/

/* */
static void capwap_wtpradiostat_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_wtpradiostat_element* element = (struct capwap_wtpradiostat_element*)data;

	ASSERT(data != NULL);
	ASSERT(IS_VALID_RADIOID(element->radioid));

	/* */
	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->lastfailtype);
	func->write_u16(handle, element->resetcount);
	func->write_u16(handle, element->swfailercount);
	func->write_u16(handle, element->hwfailercount);
	func->write_u16(handle, element->otherfailercount);
	func->write_u16(handle, element->unknownfailercount);
	func->write_u16(handle, element->configupdatecount);
	func->write_u16(handle, element->channelchangecount);
	func->write_u16(handle, element->bandchangecount);
	func->write_u16(handle, element->currentnoisefloor);
}

/* */
static void* capwap_wtpradiostat_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_wtpradiostat_element));
}

/* */
static void capwap_wtpradiostat_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
static void* capwap_wtpradiostat_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_wtpradiostat_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 20) {
		capwap_logging_debug("Invalid WTP Radio Statistics element: underbuffer");
		return NULL;
	}

	/* Retrieve data */
	data = (struct capwap_wtpradiostat_element*)capwap_alloc(sizeof(struct capwap_wtpradiostat_element));
	func->read_u8(handle, &data->radioid);
	if (!IS_VALID_RADIOID(data->radioid)) {
		capwap_wtpradiostat_element_free((void*)data);
		capwap_logging_debug("Invalid WTP Radio Statistics element: invalid radioid");
		return NULL;
	}

	func->read_u8(handle, &data->lastfailtype);
	func->read_u16(handle, &data->resetcount);
	func->read_u16(handle, &data->swfailercount);
	func->read_u16(handle, &data->hwfailercount);
	func->read_u16(handle, &data->otherfailercount);
	func->read_u16(handle, &data->unknownfailercount);
	func->read_u16(handle, &data->configupdatecount);
	func->read_u16(handle, &data->channelchangecount);
	func->read_u16(handle, &data->bandchangecount);
	func->read_u16(handle, &data->currentnoisefloor);

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_wtpradiostat_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_wtpradiostat_element_create,
	.parse = capwap_wtpradiostat_element_parsing,
	.clone = capwap_wtpradiostat_element_clone,
	.free = capwap_wtpradiostat_element_free
};
