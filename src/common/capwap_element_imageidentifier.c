#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Vendor Identifier                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Data...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   25 for Image Identifier
Length:   >= 5

********************************************************************/

struct capwap_imageidentifier_raw_element {
	unsigned long vendor;
	char name[0];
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_imageidentifier_element_create(void* data, unsigned long datalength) {
	unsigned short namelength;
	struct capwap_message_element* element;
	struct capwap_imageidentifier_raw_element* dataraw;
	struct capwap_imageidentifier_element* dataelement = (struct capwap_imageidentifier_element*)data;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_imageidentifier_element));
	
	/* Alloc block of memory */
	namelength = strlen(dataelement->name);
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_imageidentifier_raw_element) + namelength);
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_imageidentifier_raw_element) + namelength);
	element->type = htons(CAPWAP_ELEMENT_IMAGEIDENTIFIER);
	element->length = htons(sizeof(struct capwap_imageidentifier_raw_element) + namelength);
	
	dataraw = (struct capwap_imageidentifier_raw_element*)element->data;
	dataraw->vendor = htonl(dataelement->vendor);
	memcpy(&dataraw->name[0], &dataelement->name[0], namelength);
	
	return element;
}

/* */
int capwap_imageidentifier_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_imageidentifier_element_parsing(struct capwap_message_element* element) {
	unsigned short namelength;
	struct capwap_imageidentifier_element* data;
	struct capwap_imageidentifier_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_IMAGEIDENTIFIER);

	namelength = ntohs(element->length) - sizeof(struct capwap_imageidentifier_raw_element);
	if (!namelength  || (namelength > CAPWAP_IMAGEIDENTIFIER_MAXLENGTH))  {
		return NULL;
	}

	/* */
	dataraw = (struct capwap_imageidentifier_raw_element*)element->data;
	data = (struct capwap_imageidentifier_element*)capwap_alloc(sizeof(struct capwap_imageidentifier_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->vendor = ntohl(dataraw->vendor);
	memcpy(&data->name[0], &dataraw->name[0], namelength);
	data->name[namelength] = 0;
	
	return data;
}

/* */
void capwap_imageidentifier_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
