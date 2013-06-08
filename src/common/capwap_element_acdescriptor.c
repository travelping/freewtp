#include "capwap.h"
#include "capwap_array.h"
#include "capwap_element.h"

/********************************************************************
 
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Stations           |             Limit             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Active WTPs          |            Max WTPs           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Security   |  R-MAC Field  |   Reserved1   |  DTLS Policy  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  AC Information Sub-Element...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                AC Information Vendor Identifier               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      AC Information Type      |     AC Information Length     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     AC Information Data...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1 for AC Descriptor
Length:   >= 12

********************************************************************/

/* */
static void capwap_acdescriptor_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	int i;
	struct capwap_acdescriptor_element* element = (struct capwap_acdescriptor_element*)data;

	ASSERT(data != NULL);

	/* */
	func->write_u16(handle, element->stations);
	func->write_u16(handle, element->stationlimit);
	func->write_u16(handle, element->activewtp);
	func->write_u16(handle, element->maxwtp);
	func->write_u8(handle, element->security);
	func->write_u8(handle, element->rmacfield);
	func->write_u8(handle, 0);
	func->write_u8(handle, element->dtlspolicy);

	/* */
	for (i = 0; i < element->descsubelement->count; i++) {
		struct capwap_acdescriptor_desc_subelement* desc = (struct capwap_acdescriptor_desc_subelement*)capwap_array_get_item_pointer(element->descsubelement, i);

		func->write_u32(handle, desc->vendor);
		func->write_u16(handle, desc->type);
		func->write_u16(handle, desc->length);
		func->write_block(handle, desc->data, desc->length);
	}
}

/* */
static void capwap_acdescriptor_element_free(void* data) {
	struct capwap_acdescriptor_element* dataelement = (struct capwap_acdescriptor_element*)data;

	ASSERT(dataelement != NULL);
	ASSERT(dataelement->descsubelement != NULL);

	capwap_array_free(dataelement->descsubelement);
	capwap_free(dataelement);
}

/* */
static void* capwap_acdescriptor_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_acdescriptor_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) < 12) {
		capwap_logging_debug("Invalid AC Descriptor element");
		return NULL;
	}

	/* */
	data = (struct capwap_acdescriptor_element*)capwap_alloc(sizeof(struct capwap_acdescriptor_element));
	if (!data) {
		capwap_outofmemory();
	}

	memset(data, 0, sizeof(struct capwap_acdescriptor_element));
	data->descsubelement = capwap_array_create(sizeof(struct capwap_acdescriptor_desc_subelement), 0, 1);

	/* Retrieve data */
	func->read_u16(handle, &data->stations);
	func->read_u16(handle, &data->stationlimit);
	func->read_u16(handle, &data->activewtp);
	func->read_u16(handle, &data->maxwtp);

	/* Check */
	if ((data->stations > data->stationlimit) || (data->activewtp > data->maxwtp)) {
		capwap_logging_debug("Invalid AC Descriptor element");
		capwap_acdescriptor_element_free(data);
		return NULL;
	}

	/* */
	func->read_u8(handle, &data->security);
	func->read_u8(handle, &data->rmacfield);
	func->read_u8(handle, NULL);
	func->read_u8(handle, &data->dtlspolicy);

	/* Description Subelement */
	while (func->read_ready(handle) > 0) {
		unsigned short length;
		struct capwap_acdescriptor_desc_subelement* desc = (struct capwap_acdescriptor_desc_subelement*)capwap_array_get_item_pointer(data->descsubelement, data->descsubelement->count);

		/* */
		func->read_u32(handle, &desc->vendor);
		func->read_u16(handle, &desc->type);
		func->read_u16(handle, &desc->length);

		/* Check buffer size */
		length = func->read_ready(handle);
		if ((length > CAPWAP_ACDESC_SUBELEMENT_MAXDATA) || (length < desc->length)) {
			capwap_logging_debug("Invalid AC Descriptor element");
			capwap_acdescriptor_element_free(data);
			return NULL;
		}

		func->read_block(handle, desc->data, desc->length);
	}

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_acdescriptor_ops = {
	.create_message_element = capwap_acdescriptor_element_create,
	.parsing_message_element = capwap_acdescriptor_element_parsing,
	.free_parsed_message_element = capwap_acdescriptor_element_free
};
