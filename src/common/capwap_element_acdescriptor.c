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

struct capwap_acdescriptor_raw_element {
	unsigned short stations;
	unsigned short limit;
	unsigned short activewtp;
	unsigned short maxwtp;
	unsigned char security;
	unsigned char rmacfield;
	unsigned char reserved;
	unsigned char dtlspolicy;
	char data[0];
} __attribute__((__packed__));

struct capwap_acdescriptor_raw_desc_subelement {
	unsigned long vendor;
	unsigned short type;
	unsigned short length;
	char data[0];
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_acdescriptor_element_create(void* data, unsigned long datalength) {
	char* pos;
	unsigned long i;
	unsigned short length;
	struct capwap_message_element* element;
	struct capwap_acdescriptor_raw_element* dataraw;
	struct capwap_acdescriptor_element* dataelement = (struct capwap_acdescriptor_element*)data;
	
	ASSERT(data != NULL);
	ASSERT(datalength >= sizeof(struct capwap_acdescriptor_element));
	ASSERT(dataelement->descsubelement != NULL);
	
	/* Calc length packet */
	length = sizeof(struct capwap_acdescriptor_raw_element);
	for (i = 0; i < dataelement->descsubelement->count; i++) {
		struct capwap_acdescriptor_desc_subelement* desc = (struct capwap_acdescriptor_desc_subelement*)capwap_array_get_item_pointer(dataelement->descsubelement, i);
		length += sizeof(struct capwap_acdescriptor_raw_desc_subelement) + desc->length;
	}
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + length);
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + length);
	element->type = htons(CAPWAP_ELEMENT_ACDESCRIPTION);
	element->length = htons(length);

	/* Descriptor */
	dataraw = (struct capwap_acdescriptor_raw_element*)element->data;
	dataraw->stations = htons(dataelement->station);
	dataraw->limit = htons(dataelement->stationlimit);
	dataraw->activewtp = htons(dataelement->wtp);
	dataraw->maxwtp = htons(dataelement->wtplimit);
	dataraw->security = dataelement->security;
	dataraw->rmacfield = dataelement->rmacfield;
	dataraw->dtlspolicy = dataelement->dtlspolicy;
	
	/* Descriptor Sub-Element */
	pos = dataraw->data;
	for (i = 0; i < dataelement->descsubelement->count; i++) {
		struct capwap_acdescriptor_raw_desc_subelement* descraw = (struct capwap_acdescriptor_raw_desc_subelement*)pos;
		struct capwap_acdescriptor_desc_subelement* desc = (struct capwap_acdescriptor_desc_subelement*)capwap_array_get_item_pointer(dataelement->descsubelement, i);
		
		descraw->vendor = htonl(desc->vendor);
		descraw->type = htons(desc->type);
		descraw->length = htons(desc->length);
		memcpy(descraw->data, desc->data, desc->length);
		
		pos += sizeof(struct capwap_acdescriptor_raw_desc_subelement) + desc->length;
	}
	
	return element;
}

/* */
int capwap_acdescriptor_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_acdescriptor_element_parsing(struct capwap_message_element* element) {
	unsigned char i;
	long length;
	char* pos;
	struct capwap_acdescriptor_element* data;
	struct capwap_acdescriptor_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_ACDESCRIPTION);
	
	length = (long)ntohs(element->length);
	if (length < 12) {
		capwap_logging_debug("Invalid AC Descriptor element");
		return NULL;
	}

	/* */
	dataraw = (struct capwap_acdescriptor_raw_element*)element->data;
	if ((dataraw->stations > dataraw->limit) || (dataraw->activewtp > dataraw->maxwtp)) {
		capwap_logging_debug("Invalid AC Descriptor element");
		return NULL;
	}

	/* */
	data = (struct capwap_acdescriptor_element*)capwap_alloc(sizeof(struct capwap_acdescriptor_element));
	if (!data) {
		capwap_outofmemory();
	}

	data->descsubelement = capwap_array_create(sizeof(struct capwap_acdescriptor_desc_subelement), 0);
	
	/* */
	data->station = htons(dataraw->stations);
	data->stationlimit = htons(dataraw->limit);
	data->wtp = htons(dataraw->activewtp);
	data->wtplimit = htons(dataraw->maxwtp);
	data->security = dataraw->security;
	data->rmacfield = dataraw->rmacfield;
	data->dtlspolicy = dataraw->dtlspolicy;
	
	pos = dataraw->data;
	length -= sizeof(struct capwap_acdescriptor_raw_element);
	
	/* Description Subelement */
	i = 0;
	while (length > 0) {
		struct capwap_acdescriptor_desc_subelement* desc = (struct capwap_acdescriptor_desc_subelement*)capwap_array_get_item_pointer(data->descsubelement, i);
		struct capwap_acdescriptor_raw_desc_subelement* descraw = (struct capwap_acdescriptor_raw_desc_subelement*)pos;
		unsigned short desclength = ntohs(descraw->length);
		unsigned short descrawlength = sizeof(struct capwap_acdescriptor_raw_desc_subelement) + desclength;
		
		if ((desclength > CAPWAP_ACDESC_SUBELEMENT_MAXDATA) || (length < descrawlength)) {
			capwap_logging_debug("Invalid AC Descriptor element");
			capwap_acdescriptor_element_free(data);
			return NULL;
		}
		
		/* */
		desc->vendor = ntohl(descraw->vendor);
		desc->type = ntohs(descraw->type);
		desc->length = desclength;
		memcpy(desc->data, descraw->data, desclength);

		/* */
		i++;
		pos += descrawlength;
		length -= descrawlength;
	}
	
	return data;
}

/* */
void capwap_acdescriptor_element_free(void* data) {
	struct capwap_acdescriptor_element* dataelement = (struct capwap_acdescriptor_element*)data;
	
	ASSERT(dataelement != NULL);
	ASSERT(dataelement->descsubelement != NULL);
	
	capwap_array_free(dataelement->descsubelement);
	capwap_free(dataelement);
}
