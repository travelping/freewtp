#ifndef __CAPWAP_ELEMENT_WTPDESCRIPTOR_HEADER__
#define __CAPWAP_ELEMENT_WTPDESCRIPTOR_HEADER__

#define CAPWAP_ELEMENT_WTPDESCRIPTOR			39

struct capwap_wtpdescriptor_element {
	unsigned char maxradios;
	unsigned char radiosinuse;
	struct capwap_array* encryptsubelement;
	struct capwap_array* descsubelement;
};

struct capwap_wtpdescriptor_encrypt_subelement {
	unsigned char wbid;
	unsigned short capabilities;
};

#define CAPWAP_WTPDESC_SUBELEMENT_HARDWAREVERSION			0
#define CAPWAP_WTPDESC_SUBELEMENT_SOFTWAREVERSION			1
#define CAPWAP_WTPDESC_SUBELEMENT_BOOTVERSION				2
#define CAPWAP_WTPDESC_SUBELEMENT_OTHERVERSION				3
#define CAPWAP_WTPDESC_SUBELEMENT_MAXDATA					1024

struct capwap_wtpdescriptor_desc_subelement {
	unsigned long vendor;
	unsigned short type;
	unsigned short length;
	char data[CAPWAP_WTPDESC_SUBELEMENT_MAXDATA];
};

struct capwap_message_element* capwap_wtpdescriptor_element_create(void* data, unsigned long datalength);
int capwap_wtpdescriptor_element_validate(struct capwap_message_element* element);
void* capwap_wtpdescriptor_element_parsing(struct capwap_message_element* element);
void capwap_wtpdescriptor_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_WTPDESCRIPTOR_ELEMENT(x)			({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_WTPDESCRIPTOR);	\
															f->create(x, sizeof(struct capwap_wtpdescriptor_element));	\
														})
														
#endif /* __CAPWAP_ELEMENT_WTPDESCRIPTOR_HEADER__ */
