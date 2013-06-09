#include "capwap.h"
#include "capwap_array.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Max Radios  | Radios in use |  Num Encrypt  |Encryp Sub-Elmt|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Encryption Sub-Element    |    Descriptor Sub-Element...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 0                   1                   2
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Resvd|  WBID   |  Encryption Capabilities      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Descriptor Vendor Identifier                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Descriptor Type        |       Descriptor Length       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Descriptor Data...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   39 for WTP Descriptor

Length:   >= 33

********************************************************************/

/* */
static void capwap_wtpdescriptor_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	int i;
	struct capwap_wtpdescriptor_element* element = (struct capwap_wtpdescriptor_element*)data;

	ASSERT(data != NULL);
	ASSERT(element->maxradios >= element->radiosinuse);
	ASSERT(element->encryptsubelement->count > 0);
	ASSERT(element->descsubelement->count > 0);

	/* */
	func->write_u8(handle, element->maxradios);
	func->write_u8(handle, element->radiosinuse);
	func->write_u8(handle, element->encryptsubelement->count);

	/* */
	for (i = 0; i < element->encryptsubelement->count; i++) {
		struct capwap_wtpdescriptor_encrypt_subelement* desc = (struct capwap_wtpdescriptor_encrypt_subelement*)capwap_array_get_item_pointer(element->encryptsubelement, i);

		ASSERT((desc->wbid & CAPWAP_WTPDESC_SUBELEMENT_WBID_MASK) == desc->wbid);

		func->write_u8(handle, desc->wbid);
		func->write_u16(handle, desc->capabilities);
	}

	/* */
	for (i = 0; i < element->descsubelement->count; i++) {
		struct capwap_wtpdescriptor_desc_subelement* desc = (struct capwap_wtpdescriptor_desc_subelement*)capwap_array_get_item_pointer(element->descsubelement, i);

		ASSERT((desc->type >= CAPWAP_WTPDESC_SUBELEMENT_TYPE_FIRST) && (desc->type <= CAPWAP_WTPDESC_SUBELEMENT_TYPE_LAST));
		ASSERT(desc->length > 0);

		func->write_u32(handle, desc->vendor);
		func->write_u16(handle, desc->type);
		func->write_u16(handle, desc->length);
		func->write_block(handle, desc->data, desc->length);
	}
}

/* */
static void capwap_wtpdescriptor_element_free(void* data) {
	int i;
	struct capwap_wtpdescriptor_element* element = (struct capwap_wtpdescriptor_element*)data;

	ASSERT(data != NULL);
	ASSERT(element->encryptsubelement != NULL);
	ASSERT(element->descsubelement != NULL);

	/* */
	for (i = 0; i < element->descsubelement->count; i++) {
		struct capwap_wtpdescriptor_desc_subelement* desc = (struct capwap_wtpdescriptor_desc_subelement*)capwap_array_get_item_pointer(element->descsubelement, i);

		if (desc->data) {
			capwap_free(desc->data);
		}
	}

	capwap_array_free(element->encryptsubelement);
	capwap_array_free(element->descsubelement);
	capwap_free(data);
}

/* */
static void* capwap_wtpdescriptor_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	uint8_t i;
	uint8_t encryptlength;
	struct capwap_wtpdescriptor_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) < 33) {
		capwap_logging_debug("Invalid WTP Descriptor element: underbufer");
		return NULL;
	}

	/* */
	data = (struct capwap_wtpdescriptor_element*)capwap_alloc(sizeof(struct capwap_wtpdescriptor_element));
	if (!data) {
		capwap_outofmemory();
	}

	data->encryptsubelement = capwap_array_create(sizeof(struct capwap_wtpdescriptor_encrypt_subelement), 0, 0);
	data->descsubelement = capwap_array_create(sizeof(struct capwap_wtpdescriptor_desc_subelement), 0, 1);

	/* Retrieve data */
	func->read_u8(handle, &data->maxradios);
	func->read_u8(handle, &data->radiosinuse);
	func->read_u8(handle, &encryptlength);

	/* Check */
	if (!encryptlength) {
		capwap_wtpdescriptor_element_free(data);
		capwap_logging_debug("Invalid WTP Descriptor element: invalid encryptlength");
		return NULL;
	} else if (data->maxradios < data->radiosinuse) {
		capwap_wtpdescriptor_element_free(data);
		capwap_logging_debug("Invalid WTP Descriptor element: invalid radio");
		return NULL;
	}

	/* Encryption Subelement */
	for (i = 0; i < encryptlength; i++) {
		struct capwap_wtpdescriptor_encrypt_subelement* desc;

		/* Check */
		if (func->read_ready(handle) < 3) {
			capwap_logging_debug("Invalid WTP Descriptor subelement: underbuffer");
			capwap_wtpdescriptor_element_free(data);
			return NULL;
		}

		/* */
		desc = (struct capwap_wtpdescriptor_encrypt_subelement*)capwap_array_get_item_pointer(data->encryptsubelement, data->encryptsubelement->count);
		func->read_u8(handle, &desc->wbid);
		func->read_u16(handle, &desc->capabilities);

		if ((desc->wbid & CAPWAP_WTPDESC_SUBELEMENT_WBID_MASK) != desc->wbid) {
			capwap_wtpdescriptor_element_free(data);
			capwap_logging_debug("Invalid WTP Descriptor element: invalid wbid");
			return NULL;
		}
	}

	/* WTP Description Subelement */
	while (func->read_ready(handle) > 0) {
		unsigned short length;
		struct capwap_wtpdescriptor_desc_subelement* desc;

		/* Check */
		if (func->read_ready(handle) < 8) {
			capwap_logging_debug("Invalid WTP Descriptor subelement: underbuffer");
			capwap_wtpdescriptor_element_free(data);
			return NULL;
		}

		/* */
		desc = (struct capwap_wtpdescriptor_desc_subelement*)capwap_array_get_item_pointer(data->descsubelement, data->descsubelement->count);
		func->read_u32(handle, &desc->vendor);
		func->read_u16(handle, &desc->type);
		func->read_u16(handle, &desc->length);

		if ((desc->type < CAPWAP_WTPDESC_SUBELEMENT_TYPE_FIRST) || (desc->type > CAPWAP_WTPDESC_SUBELEMENT_TYPE_LAST)) {
			capwap_logging_debug("Invalid WTP Descriptor subelement: invalid type");
			capwap_wtpdescriptor_element_free(data);
			return NULL;
		}

		/* Check buffer size */
		length = func->read_ready(handle);
		if (!length || (length > CAPWAP_WTPDESC_SUBELEMENT_MAXDATA) || (length < desc->length)) {
			capwap_logging_debug("Invalid WTP Descriptor element");
			capwap_wtpdescriptor_element_free(data);
			return NULL;
		}

		func->read_block(handle, desc->data, desc->length);
	}

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_wtpdescriptor_ops = {
	.create_message_element = capwap_wtpdescriptor_element_create,
	.parsing_message_element = capwap_wtpdescriptor_element_parsing,
	.free_parsed_message_element = capwap_wtpdescriptor_element_free
};
