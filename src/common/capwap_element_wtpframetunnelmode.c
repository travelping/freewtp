#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|Reservd|N|E|L|U|
+-+-+-+-+-+-+-+-+

Type:   41 for WTP Frame Tunnel Mode
Length:   1

********************************************************************/

struct capwap_wtpframetunnelmode_raw_element {
	unsigned char mode;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_wtpframetunnelmode_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	struct capwap_wtpframetunnelmode_raw_element* dataraw;
	struct capwap_wtpframetunnelmode_element* dataelement = (struct capwap_wtpframetunnelmode_element*)data;
	
	ASSERT(data != NULL);
	ASSERT(datalength >= sizeof(struct capwap_wtpframetunnelmode_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_wtpframetunnelmode_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_wtpframetunnelmode_raw_element));
	element->type = htons(CAPWAP_ELEMENT_WTPFRAMETUNNELMODE);
	element->length = htons(sizeof(struct capwap_wtpframetunnelmode_raw_element));
	
	dataraw = (struct capwap_wtpframetunnelmode_raw_element*)element->data;
	dataraw->mode = dataelement->mode & CAPWAP_WTP_FRAME_TUNNEL_MODE_MASK;
	return element;
}

/* */
int capwap_wtpframetunnelmode_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_wtpframetunnelmode_element_parsing(struct capwap_message_element* element) {
	struct capwap_wtpframetunnelmode_element* data;
	struct capwap_wtpframetunnelmode_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_WTPFRAMETUNNELMODE);
	
	if (ntohs(element->length) != 1) {
		return NULL;
	}

	/* */
	dataraw = (struct capwap_wtpframetunnelmode_raw_element*)element->data;
	data = (struct capwap_wtpframetunnelmode_element*)capwap_alloc(sizeof(struct capwap_wtpframetunnelmode_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->mode = dataraw->mode & CAPWAP_WTP_FRAME_TUNNEL_MODE_MASK;
	return data;
}

/* */
void capwap_wtpframetunnelmode_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
