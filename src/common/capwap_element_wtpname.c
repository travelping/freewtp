#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|   Name ...
+-+-+-+-+-+-+-+-+

Type:   45 for WTP Name
Length:   >= 1

********************************************************************/

struct capwap_wtpname_raw_element {
	char name[0];
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_wtpname_element_create(void* data, unsigned long datalength) {
	unsigned short namelength;
	struct capwap_message_element* element;
	struct capwap_wtpname_raw_element* dataraw;
	struct capwap_wtpname_element* dataelement = (struct capwap_wtpname_element*)data;
	
	ASSERT(data != NULL);
	ASSERT(datalength >= sizeof(struct capwap_wtpname_element));
	
	/* Alloc block of memory */
	namelength = strlen(dataelement->name);
	element = capwap_alloc(sizeof(struct capwap_message_element) + namelength);
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + namelength);
	element->type = htons(CAPWAP_ELEMENT_WTPNAME);
	element->length = htons(namelength);
	
	dataraw = (struct capwap_wtpname_raw_element*)element->data;
	memcpy(&dataraw->name[0], &dataelement->name[0], namelength);
	return element;
}

/* */
int capwap_wtpname_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_wtpname_element_parsing(struct capwap_message_element* element) {
	unsigned short namelength;
	struct capwap_wtpname_element* data;
	struct capwap_wtpname_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_WTPNAME);

	namelength = ntohs(element->length);
	if (!namelength  || (namelength > CAPWAP_WTPNAME_MAXLENGTH))  {
		return NULL;
	}

	/* */
	dataraw = (struct capwap_wtpname_raw_element*)element->data;
	data = (struct capwap_wtpname_element*)capwap_alloc(sizeof(struct capwap_wtpname_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	memcpy(&data->name[0], &dataraw->name[0], namelength);
	data->name[namelength] = 0;
	return data;
}

/* */
void capwap_wtpname_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
