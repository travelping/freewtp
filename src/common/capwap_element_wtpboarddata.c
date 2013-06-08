#include "capwap.h"
#include "capwap_array.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Vendor Identifier                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Board Data Sub-Element...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Board Data Type        |       Board Data Length       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Board Data Value...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   38 for WTP Board Data

Length:   >=14

********************************************************************/

/* */
static void capwap_wtpboarddata_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	int i;
	struct capwap_wtpboarddata_element* element = (struct capwap_wtpboarddata_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_u32(handle, element->vendor);

	/* */
	for (i = 0; i < element->boardsubelement->count; i++) {
		struct capwap_wtpboarddata_board_subelement* desc = (struct capwap_wtpboarddata_board_subelement*)capwap_array_get_item_pointer(element->boardsubelement, i);

		func->write_u16(handle, desc->type);
		func->write_u16(handle, desc->length);
		func->write_block(handle, desc->data, desc->length);
	}
}

/* */
static void capwap_wtpboarddata_element_free(void* data) {
	struct capwap_wtpboarddata_element* dataelement = (struct capwap_wtpboarddata_element*)data;

	ASSERT(dataelement != NULL);
	ASSERT(dataelement->boardsubelement != NULL);

	capwap_array_free(dataelement->boardsubelement);
	capwap_free(dataelement);
}

/* */
static void* capwap_wtpboarddata_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_wtpboarddata_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) < 14) {
		capwap_logging_debug("Invalid WTP Board Data element");
		return NULL;
	}

	/* */
	data = (struct capwap_wtpboarddata_element*)capwap_alloc(sizeof(struct capwap_wtpboarddata_element));
	if (!data) {
		capwap_outofmemory();
	}

	data->boardsubelement = capwap_array_create(sizeof(struct capwap_wtpboarddata_board_subelement), 0, 1);

	/* Retrieve data */
	func->read_u32(handle, &data->vendor);

	/* WTP Board Data Subelement */
	while (func->read_ready(handle) > 0) {
		unsigned short length;
		struct capwap_wtpboarddata_board_subelement* desc = (struct capwap_wtpboarddata_board_subelement*)capwap_array_get_item_pointer(data->boardsubelement, data->boardsubelement->count);

		/* */
		func->read_u16(handle, &desc->type);
		func->read_u16(handle, &desc->length);

		/* Check buffer size */
		length = func->read_ready(handle);
		if ((length > CAPWAP_BOARD_SUBELEMENT_MAXDATA) || (length < desc->length)) {
			capwap_logging_debug("Invalid WTP Board Data element");
			capwap_wtpboarddata_element_free(data);
			return NULL;
		}

		func->read_block(handle, desc->data, desc->length);
	}

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_wtpboarddata_ops = {
	.create_message_element = capwap_wtpboarddata_element_create,
	.parsing_message_element = capwap_wtpboarddata_element_parsing,
	.free_parsed_message_element = capwap_wtpboarddata_element_free
};
