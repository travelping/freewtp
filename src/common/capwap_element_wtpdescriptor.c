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

struct capwap_wtpdescriptor_raw_element {
	unsigned char maxradios;
	unsigned char radiosinuse;
	unsigned char encryptcount;
	char data[0];
} __attribute__((__packed__));

struct capwap_wtpdescriptor_raw_encrypt_subelement {
#ifdef CAPWAP_BIG_ENDIAN
	unsigned char reserved : 3;
	unsigned char wbid : 5;
#else
	unsigned char wbid : 5;
	unsigned char reserved : 3;
#endif	
	unsigned short capabilities;
} __attribute__((__packed__));

struct capwap_wtpdescriptor_raw_desc_subelement {
	unsigned long vendor;
	unsigned short type;
	unsigned short length;
	char data[0];
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_wtpdescriptor_element_create(void* data, unsigned long datalength) {
	char* pos;
	unsigned long i;
	unsigned short length;
	struct capwap_message_element* element;
	struct capwap_wtpdescriptor_raw_element* dataraw;
	struct capwap_wtpdescriptor_element* dataelement = (struct capwap_wtpdescriptor_element*)data;
	
	ASSERT(data != NULL);
	ASSERT(datalength >= sizeof(struct capwap_wtpdescriptor_element));
	ASSERT(dataelement->encryptsubelement != NULL);
	ASSERT(dataelement->descsubelement != NULL);
	
	/* Calc length packet */
	length = sizeof(struct capwap_wtpdescriptor_raw_element);
	length += dataelement->encryptsubelement->count * sizeof(struct capwap_wtpdescriptor_raw_encrypt_subelement);
	for (i = 0; i < dataelement->descsubelement->count; i++) {
		struct capwap_wtpdescriptor_desc_subelement* desc = (struct capwap_wtpdescriptor_desc_subelement*)capwap_array_get_item_pointer(dataelement->descsubelement, i);
		length += sizeof(struct capwap_wtpdescriptor_raw_desc_subelement) + desc->length;
	}
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + length);
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + length);
	element->type = htons(CAPWAP_ELEMENT_WTPDESCRIPTOR);
	element->length = htons(length);

	/* Descriptor */
	dataraw = (struct capwap_wtpdescriptor_raw_element*)element->data;
	dataraw->maxradios = dataelement->maxradios;
	dataraw->radiosinuse = dataelement->radiosinuse;
	dataraw->encryptcount = (unsigned char)dataelement->encryptsubelement->count;
	pos = dataraw->data;

	/* Encryption Sub-Element */
	for (i = 0; i < dataelement->encryptsubelement->count; i++) {
		struct capwap_wtpdescriptor_raw_encrypt_subelement* encryptraw = (struct capwap_wtpdescriptor_raw_encrypt_subelement*)pos;
		struct capwap_wtpdescriptor_encrypt_subelement* encrypt = (struct capwap_wtpdescriptor_encrypt_subelement*)capwap_array_get_item_pointer(dataelement->encryptsubelement, i);
		
		encryptraw->wbid = encrypt->wbid;
		encryptraw->capabilities = htons(encrypt->capabilities);
		
		pos += sizeof(struct capwap_wtpdescriptor_raw_encrypt_subelement);
	}
	
	/* Descriptor Sub-Element */
	for (i = 0; i < dataelement->descsubelement->count; i++) {
		struct capwap_wtpdescriptor_raw_desc_subelement* descraw = (struct capwap_wtpdescriptor_raw_desc_subelement*)pos;
		struct capwap_wtpdescriptor_desc_subelement* desc = (struct capwap_wtpdescriptor_desc_subelement*)capwap_array_get_item_pointer(dataelement->descsubelement, i);
		
		descraw->vendor = htonl(desc->vendor);
		descraw->type = htons(desc->type);
		descraw->length = htons(desc->length);
		memcpy(descraw->data, desc->data, desc->length);
		
		pos += sizeof(struct capwap_wtpdescriptor_raw_desc_subelement) + desc->length;
	}
	
	return element;
}

/* */
int capwap_wtpdescriptor_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_wtpdescriptor_element_parsing(struct capwap_message_element* element) {
	unsigned char i;
	long length;
	char* pos;
	struct capwap_wtpdescriptor_element* data;
	struct capwap_wtpdescriptor_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_WTPDESCRIPTOR);
	
	length = (long)ntohs(element->length);
	if (length < 33) {
		capwap_logging_debug("Invalid WTP Descriptor element");
		return NULL;
	}

	/* */
	dataraw = (struct capwap_wtpdescriptor_raw_element*)element->data;
	if ((dataraw->radiosinuse > dataraw->maxradios) || (dataraw->encryptcount == 0)) {
		capwap_logging_debug("Invalid WTP Descriptor element");
		return NULL;
	}

	/* */
	data = (struct capwap_wtpdescriptor_element*)capwap_alloc(sizeof(struct capwap_wtpdescriptor_element));
	if (!data) {
		capwap_outofmemory();
	}

	data->encryptsubelement = capwap_array_create(sizeof(struct capwap_wtpdescriptor_encrypt_subelement), 0);
	data->descsubelement = capwap_array_create(sizeof(struct capwap_wtpdescriptor_desc_subelement), 0);
	
	/* */
	data->maxradios = dataraw->maxradios;
	data->radiosinuse = dataraw->radiosinuse;
	capwap_array_resize(data->encryptsubelement, dataraw->encryptcount);
	
	pos = dataraw->data;
	length -= sizeof(struct capwap_wtpdescriptor_raw_element);
	
	/* Encrypt Subelement */
	for (i = 0; i < dataraw->encryptcount; i++) {
		struct capwap_wtpdescriptor_encrypt_subelement* encrypt = (struct capwap_wtpdescriptor_encrypt_subelement*)capwap_array_get_item_pointer(data->encryptsubelement, i);
		struct capwap_wtpdescriptor_raw_encrypt_subelement* encryptraw = (struct capwap_wtpdescriptor_raw_encrypt_subelement*)pos;
	
		if (length < sizeof(struct capwap_wtpdescriptor_raw_element)) {
			capwap_logging_debug("Invalid WTP Descriptor element");
			capwap_wtpdescriptor_element_free(data);
			return NULL;
		}

		/* */
		encrypt->wbid = encryptraw->wbid;
		encrypt->capabilities = ntohs(encryptraw->capabilities);

		/* */	
		pos += sizeof(struct capwap_wtpdescriptor_raw_encrypt_subelement);
		length -= sizeof(struct capwap_wtpdescriptor_raw_element);
	}
	
	if (length < 0) {
		capwap_logging_debug("Invalid WTP Descriptor element");
		capwap_wtpdescriptor_element_free(data);
		return NULL;
	}

	/* Description Subelement */
	i = 0;
	while (length > 0) {
		struct capwap_wtpdescriptor_desc_subelement* desc = (struct capwap_wtpdescriptor_desc_subelement*)capwap_array_get_item_pointer(data->descsubelement, i);
		struct capwap_wtpdescriptor_raw_desc_subelement* descraw = (struct capwap_wtpdescriptor_raw_desc_subelement*)pos;
		unsigned short desclength = ntohs(descraw->length);
		unsigned short descrawlength = sizeof(struct capwap_wtpdescriptor_raw_desc_subelement) + desclength;
		
		if ((desclength > CAPWAP_WTPDESC_SUBELEMENT_MAXDATA) || (length < descrawlength)) {
			capwap_logging_debug("Invalid WTP Descriptor element");
			capwap_wtpdescriptor_element_free(data);
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
void capwap_wtpdescriptor_element_free(void* data) {
	struct capwap_wtpdescriptor_element* dataelement = (struct capwap_wtpdescriptor_element*)data;
	
	ASSERT(dataelement != NULL);
	ASSERT(dataelement->encryptsubelement != NULL);
	ASSERT(dataelement->descsubelement != NULL);
	
	capwap_array_free(dataelement->encryptsubelement);
	capwap_array_free(dataelement->descsubelement);
	capwap_free(dataelement);
}
