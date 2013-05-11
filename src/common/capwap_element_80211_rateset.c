#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |                 Rate Set...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1034 for IEEE 802.11 Rate Set

Length:   >= 3

********************************************************************/

struct capwap_80211_rateset_raw_element {
	unsigned char radioid;
	unsigned char rateset[0];
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_80211_rateset_element_create(void* data, unsigned long datalength) {
	int i;
	unsigned short ratesetlength;
	struct capwap_message_element* element;
	struct capwap_80211_rateset_raw_element* dataraw;
	struct capwap_80211_rateset_element* dataelement = (struct capwap_80211_rateset_element*)data;

	ASSERT(data != NULL);
	ASSERT(datalength >= sizeof(struct capwap_80211_rateset_element));

	/* Alloc block of memory */
	ratesetlength = dataelement->ratesetcount * sizeof(unsigned char);
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_80211_rateset_raw_element) + ratesetlength);
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_80211_rateset_raw_element) + ratesetlength);
	element->type = htons(CAPWAP_ELEMENT_80211_RATESET);
	element->length = htons(sizeof(struct capwap_80211_rateset_raw_element) + ratesetlength);
	dataraw = (struct capwap_80211_rateset_raw_element*)element->data;

	dataraw->radioid = dataelement->radioid;
	for (i = 0; i < dataelement->ratesetcount; i++) {
		dataraw->rateset[i] = dataelement->rateset[i];
	}

	return element;
}

/* */
int capwap_80211_rateset_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_80211_rateset_element_parsing(struct capwap_message_element* element) {
	int i;
	unsigned short ratesetlength;
	struct capwap_80211_rateset_element* data;
	struct capwap_80211_rateset_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_80211_RATESET);

	ratesetlength = ntohs(element->length);
	if (ratesetlength < 3) {
		return NULL;
	}

	ratesetlength -= sizeof(struct capwap_80211_rateset_raw_element);
	if (ratesetlength > CAPWAP_SUPPORTEDRATES_MAXLENGTH) {
		return NULL;
	}

	dataraw = (struct capwap_80211_rateset_raw_element*)element->data;

	/* */
	data = (struct capwap_80211_rateset_element*)capwap_alloc(sizeof(struct capwap_80211_rateset_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->radioid = dataraw->radioid;
	data->ratesetcount = ratesetlength;
	for (i = 0; i < ratesetlength; i++) {
		data->rateset[i] = dataraw->rateset[i];
	}

	return data;
}

/* */
void capwap_80211_rateset_element_free(void* data) {
	ASSERT(data != NULL);

	capwap_free(data);
}
