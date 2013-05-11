#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |   Diversity   |    Combiner   |  Antenna Cnt  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Antenna Selection...
+-+-+-+-+-+-+-+-+

Type:   1025 for IEEE 802.11 Antenna

Length:   >= 5

********************************************************************/

struct capwap_80211_antenna_raw_element {
	unsigned char radioid;
	unsigned char diversity;
	unsigned char combiner;
	unsigned char antennacount;
	unsigned char antennaselections[0];
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_80211_antenna_element_create(void* data, unsigned long datalength) {
	int i;
	unsigned short antennalength;
	struct capwap_message_element* element;
	struct capwap_80211_antenna_raw_element* dataraw;
	struct capwap_80211_antenna_element* dataelement = (struct capwap_80211_antenna_element*)data;

	ASSERT(data != NULL);
	ASSERT(datalength >= sizeof(struct capwap_80211_antenna_element));

	/* Alloc block of memory */
	antennalength = dataelement->antennacount * sizeof(unsigned char);
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_80211_antenna_raw_element) + antennalength);
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_80211_antenna_raw_element) + antennalength);
	element->type = htons(CAPWAP_ELEMENT_80211_ANTENNA);
	element->length = htons(sizeof(struct capwap_80211_antenna_raw_element) + antennalength);
	dataraw = (struct capwap_80211_antenna_raw_element*)element->data;

	dataraw->radioid = dataelement->radioid;
	dataraw->diversity = dataelement->diversity;
	dataraw->combiner = dataelement->combiner;
	dataraw->antennacount = dataelement->antennacount;
	for (i = 0; i < dataelement->antennacount; i++) {
		dataraw->antennaselections[i] = dataelement->antennaselections[i];
	}

	return element;
}

/* */
int capwap_80211_antenna_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_80211_antenna_element_parsing(struct capwap_message_element* element) {
	int i;
	unsigned short antennalength;
	struct capwap_80211_antenna_element* data;
	struct capwap_80211_antenna_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_80211_ANTENNA);

	antennalength = ntohs(element->length);
	if (antennalength < 5) {
		return NULL;
	}

	antennalength -= sizeof(struct capwap_80211_antenna_raw_element);
	if (antennalength > CAPWAP_ANTENNASELECTIONS_MAXLENGTH) {
		return NULL;
	}

	dataraw = (struct capwap_80211_antenna_raw_element*)element->data;

	/* */
	data = (struct capwap_80211_antenna_element*)capwap_alloc(sizeof(struct capwap_80211_antenna_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->radioid = dataraw->radioid;
	data->diversity = dataraw->diversity;
	data->combiner = dataraw->combiner;
	data->antennacount = dataraw->antennacount;
	for (i = 0; i < dataraw->antennacount; i++) {
		data->antennaselections[i] = dataraw->antennaselections[i];
	}

	return data;
}

/* */
void capwap_80211_antenna_element_free(void* data) {
	ASSERT(data != NULL);

	capwap_free(data);
}
