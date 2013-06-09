#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Reboot Count          |      AC Initiated Count       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Link Failure Count       |       SW Failure Count        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       HW Failure Count        |      Other Failure Count      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Unknown Failure Count     |Last Failure Ty|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   48 for WTP Reboot Statistics

Length:   15

********************************************************************/

/* */
static void capwap_wtprebootstat_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_wtprebootstat_element* element = (struct capwap_wtprebootstat_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_u16(handle, element->rebootcount);
	func->write_u16(handle, element->acinitiatedcount);
	func->write_u16(handle, element->linkfailurecount);
	func->write_u16(handle, element->swfailurecount);
	func->write_u16(handle, element->hwfailurecount);
	func->write_u16(handle, element->otherfailurecount);
	func->write_u16(handle, element->unknownfailurecount);
	func->write_u8(handle, element->lastfailuretype);
}

/* */
static void* capwap_wtprebootstat_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_wtprebootstat_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 15) {
		capwap_logging_debug("Invalid WTP Reboot Statistics element: underbuffer");
		return NULL;
	}

	/* */
	data = (struct capwap_wtprebootstat_element*)capwap_alloc(sizeof(struct capwap_wtprebootstat_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	func->read_u16(handle, &data->rebootcount);
	func->read_u16(handle, &data->acinitiatedcount);
	func->read_u16(handle, &data->linkfailurecount);
	func->read_u16(handle, &data->swfailurecount);
	func->read_u16(handle, &data->hwfailurecount);
	func->read_u16(handle, &data->otherfailurecount);
	func->read_u16(handle, &data->unknownfailurecount);
	func->read_u8(handle, &data->lastfailuretype);

	return data;
}

/* */
static void capwap_wtprebootstat_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_wtprebootstat_ops = {
	.create_message_element = capwap_wtprebootstat_element_create,
	.parsing_message_element = capwap_wtprebootstat_element_parsing,
	.free_parsed_message_element = capwap_wtprebootstat_element_free
};
