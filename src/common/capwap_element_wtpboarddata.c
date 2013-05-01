#include "capwap.h"
#include "capwap_array.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Vendor Identifier                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Board Data Sub-Element...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Board Data Type        |       Board Data Length       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Board Data Value...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   38 for WTP Board Data
Length:   >=14

********************************************************************/

struct capwap_wtpboarddata_raw_element {
	unsigned long vendor;
	char data[0];
} __attribute__((__packed__));

struct capwap_wtpboarddata_raw_board_subelement {
	unsigned short type;
	unsigned short length;
	char data[0];
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_wtpboarddata_element_create(void* data, unsigned long datalength) {
	char* pos;
	unsigned long i;
	unsigned short length;
	struct capwap_message_element* element;
	struct capwap_wtpboarddata_raw_element* dataraw;
	struct capwap_wtpboarddata_element* dataelement = (struct capwap_wtpboarddata_element*)data;
	
	ASSERT(data != NULL);
	ASSERT(datalength >= sizeof(struct capwap_wtpboarddata_element));
	ASSERT(dataelement->boardsubelement != NULL);
	
	/* Calc length packet */
	length = sizeof(struct capwap_wtpboarddata_raw_element);
	for (i = 0; i < dataelement->boardsubelement->count; i++) {
		struct capwap_wtpboarddata_board_subelement* board = (struct capwap_wtpboarddata_board_subelement*)capwap_array_get_item_pointer(dataelement->boardsubelement, i);
		length += sizeof(struct capwap_wtpboarddata_raw_board_subelement) + board->length;
	}

	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + length);
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + length);
	element->type = htons(CAPWAP_ELEMENT_WTPBOARDDATA);
	element->length = htons(length);
	
	/* */
	dataraw = (struct capwap_wtpboarddata_raw_element*)element->data;
	dataraw->vendor = htonl(dataelement->vendor);
	pos = dataraw->data;
	
	/* Board Sub-Element */
	for (i = 0; i < dataelement->boardsubelement->count; i++) {
		struct capwap_wtpboarddata_raw_board_subelement* boardraw = (struct capwap_wtpboarddata_raw_board_subelement*)pos;
		struct capwap_wtpboarddata_board_subelement* board = (struct capwap_wtpboarddata_board_subelement*)capwap_array_get_item_pointer(dataelement->boardsubelement, i);
		
		boardraw->type = htons(board->type);
		boardraw->length = htons(board->length);
		memcpy(boardraw->data, board->data, board->length);
		
		pos += sizeof(struct capwap_wtpboarddata_raw_board_subelement) + board->length;
	}
	
	return element;
}

/* */
int capwap_wtpboarddata_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_wtpboarddata_element_parsing(struct capwap_message_element* element) {
	long i;
	char* pos;
	long length;
	struct capwap_wtpboarddata_element* data;
	struct capwap_wtpboarddata_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_WTPBOARDDATA);
	
	length = (long)ntohs(element->length);
	if (length < 14) {
		capwap_logging_debug("Invalid WTP Board Data element");
		return NULL;
	}

	/* */
	dataraw = (struct capwap_wtpboarddata_raw_element*)element->data;
	data = (struct capwap_wtpboarddata_element*)capwap_alloc(sizeof(struct capwap_wtpboarddata_element));
	data->boardsubelement = capwap_array_create(sizeof(struct capwap_wtpboarddata_board_subelement), 0);
	
	/* */
	data->vendor = ntohl(dataraw->vendor);
	
	pos = dataraw->data;
	length -= sizeof(struct capwap_wtpboarddata_raw_element);

	/* Board Subelement */
	i = 0;
	while (length > 0) {
		struct capwap_wtpboarddata_board_subelement* board = (struct capwap_wtpboarddata_board_subelement*)capwap_array_get_item_pointer(data->boardsubelement, i);
		struct capwap_wtpboarddata_raw_board_subelement* boardraw = (struct capwap_wtpboarddata_raw_board_subelement*)pos;
		unsigned short boardlength = ntohs(boardraw->length);
		unsigned short boardrawlength = sizeof(struct capwap_wtpboarddata_raw_board_subelement) + boardlength;
		
		if ((boardlength > CAPWAP_BOARD_SUBELEMENT_MAXDATA) || (length < boardrawlength)) {
			capwap_logging_debug("Invalid WTP Board Data element");
			capwap_wtpboarddata_element_free(data);
			return NULL;
		}
		
		/* */
		board->type = ntohs(boardraw->type);
		board->length = boardlength;
		memcpy(board->data, boardraw->data, boardlength);

		/* */
		i++;
		pos += boardrawlength;
		length -= boardrawlength;
	}
	
	return data;
}

/* */
void capwap_wtpboarddata_element_free(void* data) {
	struct capwap_wtpboarddata_element* dataelement = (struct capwap_wtpboarddata_element*)data;

	ASSERT(dataelement != NULL);
	ASSERT(dataelement->boardsubelement != NULL);
	
	capwap_array_free(dataelement->boardsubelement);
	capwap_free(dataelement);
}
