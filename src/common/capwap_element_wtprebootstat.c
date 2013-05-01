#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Reboot Count          |      AC Initiated Count       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Link Failure Count       |       SW Failure Count        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       HW Failure Count        |      Other Failure Count      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Unknown Failure Count     |Last Failure Ty|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   48 for WTP Reboot Statistics
Length:   15

********************************************************************/

struct capwap_wtprebootstat_raw_element {
	unsigned short rebootcount;
	unsigned short acinitiatedcount;
	unsigned short linkfailurecount;
	unsigned short swfailurecount;
	unsigned short hwfailurecount;
	unsigned short otherfailurecount;
	unsigned short unknownfailurecount;
	unsigned char lastfailuretype;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_wtprebootstat_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	struct capwap_wtprebootstat_raw_element* dataraw;
	struct capwap_wtprebootstat_element* dataelement = (struct capwap_wtprebootstat_element*)data;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_wtprebootstat_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_wtprebootstat_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_wtprebootstat_raw_element));
	element->type = htons(CAPWAP_ELEMENT_WTPREBOOTSTAT);
	element->length = htons(sizeof(struct capwap_wtprebootstat_raw_element));
	
	dataraw = (struct capwap_wtprebootstat_raw_element*)element->data;
	dataraw->rebootcount = htons(dataelement->rebootcount);
	dataraw->acinitiatedcount = htons(dataelement->acinitiatedcount);
	dataraw->linkfailurecount = htons(dataelement->linkfailurecount);
	dataraw->swfailurecount = htons(dataelement->swfailurecount);
	dataraw->hwfailurecount = htons(dataelement->hwfailurecount);
	dataraw->otherfailurecount = htons(dataelement->otherfailurecount);
	dataraw->unknownfailurecount = htons(dataelement->unknownfailurecount);
	dataraw->lastfailuretype = dataelement->lastfailuretype;

	return element;
}

/* */
int capwap_wtprebootstat_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_wtprebootstat_element_parsing(struct capwap_message_element* element) {
	struct capwap_wtprebootstat_element* data;
	struct capwap_wtprebootstat_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_WTPREBOOTSTAT);

	if (ntohs(element->length) != sizeof(struct capwap_wtprebootstat_raw_element))  {
		return NULL;
	}

	/* */
	dataraw = (struct capwap_wtprebootstat_raw_element*)element->data;
	data = (struct capwap_wtprebootstat_element*)capwap_alloc(sizeof(struct capwap_wtprebootstat_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->rebootcount = ntohs(dataraw->rebootcount);
	data->acinitiatedcount = ntohs(dataraw->acinitiatedcount);
	data->linkfailurecount = ntohs(dataraw->linkfailurecount);
	data->swfailurecount = ntohs(dataraw->swfailurecount);
	data->hwfailurecount = ntohs(dataraw->hwfailurecount);
	data->otherfailurecount = ntohs(dataraw->otherfailurecount);
	data->unknownfailurecount = ntohs(dataraw->unknownfailurecount);
	data->lastfailuretype = dataraw->lastfailuretype;
	return data;
}

/* */
void capwap_wtprebootstat_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
