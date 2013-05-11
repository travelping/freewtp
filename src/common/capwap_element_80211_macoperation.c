#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |    Reserved   |         RTS Threshold         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Short Retry  |  Long Retry   |    Fragmentation Threshold    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Tx MSDU Lifetime                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Rx MSDU Lifetime                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1030 for IEEE 802.11 MAC Operation

Length:   16

********************************************************************/

struct capwap_80211_macoperation_raw_element {
	unsigned char radioid;
	unsigned char reserved;
	unsigned short rtsthreshold;
	unsigned char shortretry;
	unsigned char longretry;
	unsigned short fragthreshold;
	unsigned long txmsdulifetime;
	unsigned long rxmsdulifetime;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_80211_macoperation_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	struct capwap_80211_macoperation_raw_element* dataraw;
	struct capwap_80211_macoperation_element* dataelement = (struct capwap_80211_macoperation_element*)data;

	ASSERT(data != NULL);
	ASSERT(datalength >= sizeof(struct capwap_80211_macoperation_element));

	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_80211_macoperation_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_80211_macoperation_raw_element));
	element->type = htons(CAPWAP_ELEMENT_80211_MACOPERATION);
	element->length = htons(sizeof(struct capwap_80211_macoperation_raw_element));
	dataraw = (struct capwap_80211_macoperation_raw_element*)element->data;
	
	dataraw->radioid = dataelement->radioid;
	dataraw->rtsthreshold = htons(dataelement->rtsthreshold);
	dataraw->shortretry = dataelement->shortretry;
	dataraw->longretry = dataelement->longretry;
	dataraw->fragthreshold = htons(dataelement->fragthreshold);
	dataraw->txmsdulifetime = htonl(dataelement->txmsdulifetime);
	dataraw->rxmsdulifetime = htonl(dataelement->rxmsdulifetime);
	return element;
}

/* */
int capwap_80211_macoperation_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_80211_macoperation_element_parsing(struct capwap_message_element* element) {
	struct capwap_80211_macoperation_element* data;
	struct capwap_80211_macoperation_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_80211_MACOPERATION);
	
	if (ntohs(element->length) != 16) {
		return NULL;
	}

	dataraw = (struct capwap_80211_macoperation_raw_element*)element->data;

	/* */
	data = (struct capwap_80211_macoperation_element*)capwap_alloc(sizeof(struct capwap_80211_macoperation_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->radioid = dataraw->radioid;
	data->rtsthreshold = ntohs(dataraw->rtsthreshold);
	data->shortretry = dataraw->shortretry;
	data->longretry = dataraw->longretry;
	data->fragthreshold = ntohs(dataraw->fragthreshold);
	data->txmsdulifetime = ntohl(dataraw->txmsdulifetime);
	data->rxmsdulifetime = ntohl(dataraw->rxmsdulifetime);
	return data;
}

/* */
void capwap_80211_macoperation_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
