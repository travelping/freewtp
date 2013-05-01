#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Session ID                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Session ID                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Session ID                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Session ID                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


Type:   35 for Session ID
Length:   16

********************************************************************/

struct capwap_sessionid_raw_element {
	unsigned char id[16];
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_sessionid_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	struct capwap_sessionid_raw_element* dataraw;
	struct capwap_sessionid_element* dataelement = (struct capwap_sessionid_element*)data;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_sessionid_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_sessionid_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_sessionid_element));
	element->type = htons(CAPWAP_ELEMENT_SESSIONID);
	element->length = htons(sizeof(struct capwap_sessionid_element));
	
	dataraw = (struct capwap_sessionid_raw_element*)element->data;
	memcpy(&dataraw->id[0], &dataelement->id[0], sizeof(unsigned char) * 16);
	return element;
}

/* */
int capwap_sessionid_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_sessionid_element_parsing(struct capwap_message_element* element) {
	struct capwap_sessionid_element* data;
	struct capwap_sessionid_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_SESSIONID);

	if (ntohs(element->length) != sizeof(struct capwap_sessionid_raw_element))  {
		return NULL;
	}

	/* */
	dataraw = (struct capwap_sessionid_raw_element*)element->data;
	data = (struct capwap_sessionid_element*)capwap_alloc(sizeof(struct capwap_sessionid_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	memcpy(&data->id[0], &dataraw->id[0], sizeof(unsigned char) * 16);
	return data;
}

/* */
void capwap_sessionid_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
void capwap_sessionid_generate(struct capwap_sessionid_element* session) {
	int i;

	ASSERT(session != NULL);

	for (i = 0; i < 16; i++) {
		session->id[i] = (unsigned char)capwap_get_rand(256);
	}
}

/* */
void capwap_sessionid_printf(struct capwap_sessionid_element* session, char* string) {
	int i;
	char* pos = string;

	ASSERT(session != NULL);
	ASSERT(string != NULL);

	for (i = 0; i < 16; i++) {
		sprintf(pos, "%02x", session->id[i]);
		pos += 2;
	}

	*pos = 0;
}
