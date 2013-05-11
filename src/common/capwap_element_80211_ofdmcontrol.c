#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |    Reserved   | Current Chan  |  Band Support |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         TI Threshold                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1033 for IEEE 802.11 OFDM Control

Length:   8

********************************************************************/

struct capwap_80211_ofdmcontrol_raw_element {
	unsigned char radioid;
	unsigned char reserved;
	unsigned char currentchannel;
	unsigned char bandsupport;
	unsigned long tithreshold;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_80211_ofdmcontrol_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	struct capwap_80211_ofdmcontrol_raw_element* dataraw;
	struct capwap_80211_ofdmcontrol_element* dataelement = (struct capwap_80211_ofdmcontrol_element*)data;

	ASSERT(data != NULL);
	ASSERT(datalength >= sizeof(struct capwap_80211_ofdmcontrol_element));

	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_80211_ofdmcontrol_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_80211_ofdmcontrol_raw_element));
	element->type = htons(CAPWAP_ELEMENT_80211_OFDMCONTROL);
	element->length = htons(sizeof(struct capwap_80211_ofdmcontrol_raw_element));
	dataraw = (struct capwap_80211_ofdmcontrol_raw_element*)element->data;

	dataraw->radioid = dataelement->radioid;
	dataraw->currentchannel = dataelement->currentchannel;
	dataraw->bandsupport = dataelement->bandsupport;
	dataraw->tithreshold = htonl(dataelement->tithreshold);
	return element;
}

/* */
int capwap_80211_ofdmcontrol_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_80211_ofdmcontrol_element_parsing(struct capwap_message_element* element) {
	struct capwap_80211_ofdmcontrol_element* data;
	struct capwap_80211_ofdmcontrol_raw_element* dataraw;

	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_80211_OFDMCONTROL);

	if (ntohs(element->length) != 8) {
		return NULL;
	}

	dataraw = (struct capwap_80211_ofdmcontrol_raw_element*)element->data;

	/* */
	data = (struct capwap_80211_ofdmcontrol_element*)capwap_alloc(sizeof(struct capwap_80211_ofdmcontrol_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->radioid = dataraw->radioid;
	data->currentchannel = ntohs(dataraw->currentchannel);
	data->bandsupport = ntohs(dataraw->bandsupport);
	data->tithreshold = ntohl(dataraw->tithreshold);
	return data;
}

/* */
void capwap_80211_ofdmcontrol_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
