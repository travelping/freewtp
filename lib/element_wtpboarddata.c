#include "capwap.h"
#include "array.h"
#include "element.h"

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
	ASSERT(element->vendor != 0);
	ASSERT(element->boardsubelement->count > 0);

	/* */
	func->write_u32(handle, element->vendor);

	/* */
	for (i = 0; i < element->boardsubelement->count; i++) {
		struct capwap_wtpboarddata_board_subelement* desc = (struct capwap_wtpboarddata_board_subelement*)capwap_array_get_item_pointer(element->boardsubelement, i);

		ASSERT((desc->type >= CAPWAP_BOARD_SUBELEMENT_TYPE_FIRST) && (desc->type <= CAPWAP_BOARD_SUBELEMENT_TYPE_LAST));
		ASSERT((desc->length > 0) && (desc->length <= CAPWAP_BOARD_SUBELEMENT_MAXDATA));

		func->write_u16(handle, desc->type);
		func->write_u16(handle, desc->length);
		func->write_block(handle, desc->data, desc->length);
	}
}

/* */
static void* capwap_wtpboarddata_element_clone(void* data) {
	int i;
	struct capwap_wtpboarddata_element* cloneelement;
	struct capwap_wtpboarddata_element* element = (struct capwap_wtpboarddata_element*)data;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_wtpboarddata_element));
	cloneelement->boardsubelement = capwap_array_create(sizeof(struct capwap_wtpboarddata_board_subelement), 0, 1);
	for (i = 0; i < element->boardsubelement->count; i++) {
		struct capwap_wtpboarddata_board_subelement* desc = (struct capwap_wtpboarddata_board_subelement*)capwap_array_get_item_pointer(element->boardsubelement, i);
		struct capwap_wtpboarddata_board_subelement* clonedesc = (struct capwap_wtpboarddata_board_subelement*)capwap_array_get_item_pointer(cloneelement->boardsubelement, i);

		memcpy(clonedesc, desc, sizeof(struct capwap_wtpboarddata_board_subelement));
		if (desc->length) {
			clonedesc->data = capwap_clone(desc->data, desc->length);
		}
	}

	return cloneelement;
}

/* */
static void capwap_wtpboarddata_element_free(void* data) {
	int i;
	struct capwap_wtpboarddata_element* element = (struct capwap_wtpboarddata_element*)data;

	ASSERT(data != NULL);
	ASSERT(element->boardsubelement != NULL);

	/* */
	for (i = 0; i < element->boardsubelement->count; i++) {
		struct capwap_wtpboarddata_board_subelement* desc = (struct capwap_wtpboarddata_board_subelement*)capwap_array_get_item_pointer(element->boardsubelement, i);

		if (desc->data) {
			capwap_free(desc->data);
		}
	}

	capwap_array_free(element->boardsubelement);
	capwap_free(data);
}

/* */
static void* capwap_wtpboarddata_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_wtpboarddata_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) < 14) {
		log_printf(LOG_DEBUG, "Invalid WTP Board Data element: underbuffer");
		return NULL;
	}

	/* */
	data = (struct capwap_wtpboarddata_element*)capwap_alloc(sizeof(struct capwap_wtpboarddata_element));
	data->boardsubelement = capwap_array_create(sizeof(struct capwap_wtpboarddata_board_subelement), 0, 1);

	/* Retrieve data */
	func->read_u32(handle, &data->vendor);
	if (!data->vendor) {
		capwap_wtpboarddata_element_free((void*)data);
		log_printf(LOG_DEBUG, "Invalid WTP Board Data element: invalid vendor");
		return NULL;
	}

	/* WTP Board Data Subelement */
	while (func->read_ready(handle) > 0) {
		unsigned short length;
		struct capwap_wtpboarddata_board_subelement* desc = (struct capwap_wtpboarddata_board_subelement*)capwap_array_get_item_pointer(data->boardsubelement, data->boardsubelement->count);

		/* */
		func->read_u16(handle, &desc->type);
		func->read_u16(handle, &desc->length);

		if ((desc->type < CAPWAP_BOARD_SUBELEMENT_TYPE_FIRST) || (desc->type > CAPWAP_BOARD_SUBELEMENT_TYPE_LAST)) {
			log_printf(LOG_DEBUG, "Invalid WTP Board Data element: invalid type");
			capwap_wtpboarddata_element_free(data);
			return NULL;
		}

		/* Check buffer size */
		length = func->read_ready(handle);
		if (!length || (length > CAPWAP_BOARD_SUBELEMENT_MAXDATA) || (length < desc->length)) {
			log_printf(LOG_DEBUG, "Invalid WTP Board Data element: invalid length");
			capwap_wtpboarddata_element_free(data);
			return NULL;
		}

		desc->data = (uint8_t*)capwap_alloc(desc->length);
		func->read_block(handle, desc->data, desc->length);
	}

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_wtpboarddata_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_wtpboarddata_element_create,
	.parse = capwap_wtpboarddata_element_parsing,
	.clone = capwap_wtpboarddata_element_clone,
	.free = capwap_wtpboarddata_element_free
};

/* */
struct capwap_wtpboarddata_board_subelement* capwap_wtpboarddata_get_subelement(struct capwap_wtpboarddata_element* wtpboarddata, int subelement) {
	int i;

	ASSERT(wtpboarddata != NULL);
	ASSERT((subelement >= CAPWAP_BOARD_SUBELEMENT_TYPE_FIRST) && (subelement <= CAPWAP_BOARD_SUBELEMENT_TYPE_LAST));

	/* */
	for (i = 0; i < wtpboarddata->boardsubelement->count; i++) {
		struct capwap_wtpboarddata_board_subelement* desc = (struct capwap_wtpboarddata_board_subelement*)capwap_array_get_item_pointer(wtpboarddata->boardsubelement, i);

		if (desc->type == subelement) {
			return desc;
		}
	}

	return NULL;
}
