#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Vendor Identifier                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Element ID           |    Data...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   37 for Vendor Specific Payload
Length:   >= 7

********************************************************************/

struct capwap_vendorpayload_raw_element {
	unsigned long vendorid;
	unsigned short elementid;
	char data[0];
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_vendorpayload_element_create(void* data, unsigned long datalength) {
	unsigned short elementlength;
	struct capwap_message_element* element;
	struct capwap_vendorpayload_raw_element* dataraw;
	struct capwap_vendorpayload_element* dataelement = (struct capwap_vendorpayload_element*)data;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_vendorpayload_element));
	
	/* */
	if (!dataelement->datalength || (dataelement->datalength > CAPWAP_VENDORPAYLOAD_MAXLENGTH)) {
		return NULL; 
	}
	
	/* Alloc block of memory */
	elementlength = sizeof(struct capwap_vendorpayload_raw_element) + dataelement->datalength;
	element = capwap_alloc(sizeof(struct capwap_message_element) + elementlength);
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + elementlength);
	element->type = htons(CAPWAP_ELEMENT_VENDORPAYLOAD);
	element->length = htons(elementlength);
	
	dataraw = (struct capwap_vendorpayload_raw_element*)element->data;
	dataraw->vendorid = htonl(dataelement->vendorid);
	dataraw->elementid = htons(dataelement->elementid);
	memcpy(&dataraw->data[0], &dataelement->data[0], dataelement->datalength);
	return element;
}

/* */
int capwap_vendorpayload_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_vendorpayload_element_parsing(struct capwap_message_element* element) {
	unsigned short elementlength;
	struct capwap_vendorpayload_element* data;
	struct capwap_vendorpayload_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_VENDORPAYLOAD);

	elementlength = ntohs(element->length);
	if (elementlength > sizeof(struct capwap_vendorpayload_raw_element))  {
		return NULL;
	}

	/* */
	dataraw = (struct capwap_vendorpayload_raw_element*)element->data;
	data = (struct capwap_vendorpayload_element*)capwap_alloc(sizeof(struct capwap_vendorpayload_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->vendorid = ntohl(dataraw->vendorid);
	data->elementid = ntohs(dataraw->elementid);
	data->datalength = elementlength - sizeof(struct capwap_vendorpayload_element);
	memcpy(&data->data[0], &dataraw->data[0], data->datalength);
	return data;
}

/* */
void capwap_vendorpayload_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
