#ifndef __CAPWAP_ELEMENT_WTPBOARDDATA_HEADER__
#define __CAPWAP_ELEMENT_WTPBOARDDATA_HEADER__

#define CAPWAP_ELEMENT_WTPBOARDDATA			38

struct capwap_wtpboarddata_element {
	unsigned long vendor;
	struct capwap_array* boardsubelement;
};

#define CAPWAP_BOARD_SUBELEMENT_MODELNUMBER			0
#define CAPWAP_BOARD_SUBELEMENT_SERIALNUMBER		1
#define CAPWAP_BOARD_SUBELEMENT_ID					2
#define CAPWAP_BOARD_SUBELEMENT_REVISION			3
#define CAPWAP_BOARD_SUBELEMENT_MACADDRESS			4
#define CAPWAP_BOARD_SUBELEMENT_MAXDATA				1024

struct capwap_wtpboarddata_board_subelement {
	unsigned short type;
	unsigned short length;
	char data[CAPWAP_BOARD_SUBELEMENT_MAXDATA];
};

struct capwap_message_element* capwap_wtpboarddata_element_create(void* data, unsigned long datalength);
int capwap_wtpboarddata_element_validate(struct capwap_message_element* element);
void* capwap_wtpboarddata_element_parsing(struct capwap_message_element* element);
void capwap_wtpboarddata_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_WTPBOARDDATA_ELEMENT(x)			({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_WTPBOARDDATA);	\
															f->create(x, sizeof(struct capwap_wtpboarddata_element));	\
														})
														
#endif /* __CAPWAP_ELEMENT_WTPBOARDDATA_HEADER__ */
