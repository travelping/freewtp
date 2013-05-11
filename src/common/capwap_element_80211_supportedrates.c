#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |               Supported Rates...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1040 for IEEE 802.11 Supported Rates

Length:   >= 3

********************************************************************/

struct capwap_80211_supportedrates_raw_element {
	unsigned char radioid;
	unsigned char supportedrates[0];
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_80211_supportedrates_element_create(void* data, unsigned long datalength) {
	int i;
	unsigned short supportedrateslength;
	struct capwap_message_element* element;
	struct capwap_80211_supportedrates_raw_element* dataraw;
	struct capwap_80211_supportedrates_element* dataelement = (struct capwap_80211_supportedrates_element*)data;

	ASSERT(data != NULL);
	ASSERT(datalength >= sizeof(struct capwap_80211_supportedrates_element));

	/* Alloc block of memory */
	supportedrateslength = dataelement->supportedratescount * sizeof(unsigned char);
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_80211_supportedrates_raw_element) + supportedrateslength);
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_80211_supportedrates_raw_element) + supportedrateslength);
	element->type = htons(CAPWAP_ELEMENT_80211_SUPPORTEDRATES);
	element->length = htons(sizeof(struct capwap_80211_supportedrates_raw_element) + supportedrateslength);
	dataraw = (struct capwap_80211_supportedrates_raw_element*)element->data;

	dataraw->radioid = dataelement->radioid;
	for (i = 0; i < dataelement->supportedratescount; i++) {
		dataraw->supportedrates[i] = dataelement->supportedrates[i];
	}

	return element;
}

/* */
int capwap_80211_supportedrates_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_80211_supportedrates_element_parsing(struct capwap_message_element* element) {
	int i;
	unsigned short supportedrateslength;
	struct capwap_80211_supportedrates_element* data;
	struct capwap_80211_supportedrates_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_80211_SUPPORTEDRATES);

	supportedrateslength = ntohs(element->length);
	if (supportedrateslength < 3) {
		return NULL;
	}

	supportedrateslength -= sizeof(struct capwap_80211_supportedrates_raw_element);
	if (supportedrateslength > CAPWAP_SUPPORTEDRATES_MAXLENGTH) {
		return NULL;
	}

	dataraw = (struct capwap_80211_supportedrates_raw_element*)element->data;

	/* */
	data = (struct capwap_80211_supportedrates_element*)capwap_alloc(sizeof(struct capwap_80211_supportedrates_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->radioid = dataraw->radioid;
	data->supportedratescount = supportedrateslength;
	for (i = 0; i < supportedrateslength; i++) {
		data->supportedrates[i] = dataraw->supportedrates[i];
	}

	return data;
}

/* */
void capwap_80211_supportedrates_element_free(void* data) {
	ASSERT(data != NULL);

	capwap_free(data);
}
