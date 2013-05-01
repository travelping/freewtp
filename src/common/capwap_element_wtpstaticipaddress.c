#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          IP Address                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Netmask                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Gateway                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Static     |
+-+-+-+-+-+-+-+-+

Type:   49 for WTP Static IP Address Information
Length:  13

********************************************************************/

struct capwap_wtpstaticipaddress_raw_element {
	unsigned long address;
	unsigned long netmask;
	unsigned long gateway;
	unsigned char staticip;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_wtpstaticipaddress_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	struct capwap_wtpstaticipaddress_element* dataelement = (struct capwap_wtpstaticipaddress_element*)data;
	struct capwap_wtpstaticipaddress_raw_element* dataraw;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_wtpstaticipaddress_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_wtpstaticipaddress_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_wtpstaticipaddress_raw_element));
	element->type = htons(CAPWAP_ELEMENT_WTPSTATICIPADDRESS);
	element->length = htons(sizeof(struct capwap_wtpstaticipaddress_raw_element));
	
	dataraw = (struct capwap_wtpstaticipaddress_raw_element*)element->data;
	dataraw->address = dataelement->address.s_addr;
	dataraw->netmask = dataelement->netmask.s_addr;
	dataraw->gateway = dataelement->gateway.s_addr;
	dataraw->staticip = dataelement->staticip;
	
	return element;
}

/* */
int capwap_wtpstaticipaddress_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_wtpstaticipaddress_element_parsing(struct capwap_message_element* element) {
	struct capwap_wtpstaticipaddress_element* data;
	struct capwap_wtpstaticipaddress_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_WTPSTATICIPADDRESS);
	
	if (ntohs(element->length) != sizeof(struct capwap_wtpstaticipaddress_raw_element)) {
		return NULL;
	}

	/* */
	data = (struct capwap_wtpstaticipaddress_element*)capwap_alloc(sizeof(struct capwap_wtpstaticipaddress_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	dataraw = (struct capwap_wtpstaticipaddress_raw_element*)element->data;
	data->address.s_addr = dataraw->address;
	data->netmask.s_addr = dataraw->netmask;
	data->gateway.s_addr = dataraw->gateway;
	data->staticip = dataraw->staticip;
	
	return data;
}

/* */
void capwap_wtpstaticipaddress_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
