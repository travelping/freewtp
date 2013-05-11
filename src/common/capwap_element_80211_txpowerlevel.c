#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Radio ID   |   Num Levels  |        Power Level [n]        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1042 for IEEE 802.11 Tx Power Level

Length:   >= 4

********************************************************************/

struct capwap_80211_txpowerlevel_raw_element {
	unsigned char radioid;
	unsigned char numlevels;
	unsigned short powerlevel[0];
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_80211_txpowerlevel_element_create(void* data, unsigned long datalength) {
	int i;
	unsigned short txpowerlength;
	struct capwap_message_element* element;
	struct capwap_80211_txpowerlevel_raw_element* dataraw;
	struct capwap_80211_txpowerlevel_element* dataelement = (struct capwap_80211_txpowerlevel_element*)data;

	ASSERT(data != NULL);
	ASSERT(datalength >= sizeof(struct capwap_80211_txpowerlevel_element));

	/* Alloc block of memory */
	txpowerlength = dataelement->numlevels * sizeof(unsigned char);
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_80211_txpowerlevel_raw_element) + txpowerlength);
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_80211_txpowerlevel_raw_element) + txpowerlength);
	element->type = htons(CAPWAP_ELEMENT_80211_TXPOWERLEVEL);
	element->length = htons(sizeof(struct capwap_80211_txpowerlevel_raw_element) + txpowerlength);
	dataraw = (struct capwap_80211_txpowerlevel_raw_element*)element->data;

	dataraw->radioid = dataelement->radioid;
	dataraw->numlevels = dataelement->numlevels;
	for (i = 0; i < dataelement->numlevels; i++) {
		dataraw->powerlevel[i] = htons(dataelement->powerlevel[i]);
	}

	return element;
}

/* */
int capwap_80211_txpowerlevel_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_80211_txpowerlevel_element_parsing(struct capwap_message_element* element) {
	int i;
	unsigned short txpowerlength;
	struct capwap_80211_txpowerlevel_element* data;
	struct capwap_80211_txpowerlevel_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_80211_TXPOWERLEVEL);

	txpowerlength = ntohs(element->length);
	if (txpowerlength < 4) {
		return NULL;
	}

	txpowerlength -= sizeof(struct capwap_80211_txpowerlevel_raw_element);
	if (txpowerlength > (CAPWAP_TXPOWERLEVEL_MAXLENGTH * sizeof(unsigned short))) {
		return NULL;
	}

	dataraw = (struct capwap_80211_txpowerlevel_raw_element*)element->data;
	if ((dataraw->numlevels < 1) || (dataraw->numlevels > CAPWAP_TXPOWERLEVEL_MAXLENGTH)) {
		return NULL;
	}

	/* */
	data = (struct capwap_80211_txpowerlevel_element*)capwap_alloc(sizeof(struct capwap_80211_txpowerlevel_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->radioid = dataraw->radioid;
	data->numlevels = dataraw->numlevels;
	for (i = 0; i < dataraw->numlevels; i++) {
		data->powerlevel[i] = dataraw->powerlevel[i];
	}

	return data;
}

/* */
void capwap_80211_txpowerlevel_element_free(void* data) {
	ASSERT(data != NULL);

	capwap_free(data);
}
