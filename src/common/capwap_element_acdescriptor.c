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
	ASSERT(!(element->security & ~CAPWAP_ACDESC_SECURITY_MASK));
	ASSERT(!(element->dtlspolicy & ~CAPWAP_ACDESC_DTLS_POLICY_MASK));
	ASSERT((element->rmacfield == CAPWAP_ACDESC_RMACFIELD_SUPPORTED) || (element->rmacfield == CAPWAP_ACDESC_RMACFIELD_NOTSUPPORTED));

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

		ASSERT(desc->length  > 0);
		ASSERT(desc->data != NULL);

		func->write_u32(handle, desc->vendor);
		func->write_u16(handle, desc->type);
		func->write_u16(handle, desc->length);
		func->write_block(handle, desc->data, desc->length);
	}
}

/* */
static void capwap_acdescriptor_element_free(void* data) {
	int i;
	struct capwap_acdescriptor_element* element = (struct capwap_acdescriptor_element*)data;

	ASSERT(element != NULL);
	ASSERT(element->descsubelement != NULL);

	/* */
	for (i = 0; i < element->descsubelement->count; i++) {
		struct capwap_acdescriptor_desc_subelement* desc = (struct capwap_acdescriptor_desc_subelement*)capwap_array_get_item_pointer(element->descsubelement, i);

		if (desc->data) {
			capwap_free(desc->data);
		}
	}

	capwap_array_free(element->descsubelement);
	capwap_free(data);
}

/* */
static void* capwap_acdescriptor_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_acdescriptor_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) < 12) {
		capwap_logging_debug("Invalid AC Descriptor element: underbuffer");
		return NULL;
	}

	/* */
	data = (struct capwap_acdescriptor_element*)capwap_alloc(sizeof(struct capwap_acdescriptor_element));
	memset(data, 0, sizeof(struct capwap_acdescriptor_element));
	data->descsubelement = capwap_array_create(sizeof(struct capwap_acdescriptor_desc_subelement), 0, 1);

	/* Retrieve data */
	func->read_u16(handle, &data->stations);
	func->read_u16(handle, &data->stationlimit);
	func->read_u16(handle, &data->activewtp);
	func->read_u16(handle, &data->maxwtp);

	/* Check */
	if (data->stations > data->stationlimit) {
		capwap_logging_debug("Invalid AC Descriptor element: stations > stationlimit");
		capwap_acdescriptor_element_free(data);
		return NULL;
	} else if (data->activewtp > data->maxwtp) {
		capwap_logging_debug("Invalid AC Descriptor element: activewtp > maxwtp");
		capwap_acdescriptor_element_free(data);
		return NULL;
	}

	/* */
	func->read_u8(handle, &data->security);
	func->read_u8(handle, &data->rmacfield);
	func->read_u8(handle, NULL);
	func->read_u8(handle, &data->dtlspolicy);

	/* */
	if (data->security & ~CAPWAP_ACDESC_SECURITY_MASK) {
		capwap_logging_debug("Invalid AC Descriptor element: security");
		capwap_acdescriptor_element_free(data);
		return NULL;
	} else if (data->dtlspolicy & ~CAPWAP_ACDESC_DTLS_POLICY_MASK) {
		capwap_logging_debug("Invalid AC Descriptor element: dtlspolicy");
		capwap_acdescriptor_element_free(data);
		return NULL;
	} else if ((data->rmacfield != CAPWAP_ACDESC_RMACFIELD_SUPPORTED) && (data->rmacfield != CAPWAP_ACDESC_RMACFIELD_NOTSUPPORTED)) {
		capwap_logging_debug("Invalid AC Descriptor element: rmacfield");
		capwap_acdescriptor_element_free(data);
		return NULL;
	}

	/* Description Subelement */
	while (func->read_ready(handle) > 0) {
		unsigned short length;
		struct capwap_acdescriptor_desc_subelement* desc = (struct capwap_acdescriptor_desc_subelement*)capwap_array_get_item_pointer(data->descsubelement, data->descsubelement->count);

		/* */
		func->read_u32(handle, &desc->vendor);
		func->read_u16(handle, &desc->type);
		func->read_u16(handle, &desc->length);

		if ((desc->type != CAPWAP_ACDESC_SUBELEMENT_HARDWAREVERSION) && (desc->type != CAPWAP_ACDESC_SUBELEMENT_SOFTWAREVERSION)) {
			capwap_logging_debug("Invalid AC Descriptor subelement: type");
			capwap_acdescriptor_element_free(data);
			return NULL;
		}

		/* Check buffer size */
		length = func->read_ready(handle);
		if ((length > CAPWAP_ACDESC_SUBELEMENT_MAXDATA) || (length < desc->length)) {
			capwap_logging_debug("Invalid AC Descriptor subelement: length");
			capwap_acdescriptor_element_free(data);
			return NULL;
		}

		desc->data = (uint8_t*)capwap_alloc(desc->length + 1);
		func->read_block(handle, desc->data, desc->length);
		desc->data[desc->length] = 0;
	}

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_acdescriptor_ops = {
	.create_message_element = capwap_acdescriptor_element_create,
	.parsing_message_element = capwap_acdescriptor_element_parsing,
	.free_parsed_message_element = capwap_acdescriptor_element_free
};
