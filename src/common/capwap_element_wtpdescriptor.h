#ifndef __CAPWAP_ELEMENT_WTPDESCRIPTOR_HEADER__
#define __CAPWAP_ELEMENT_WTPDESCRIPTOR_HEADER__

#define CAPWAP_ELEMENT_WTPDESCRIPTOR						39

struct capwap_wtpdescriptor_element {
	uint8_t maxradios;
	uint8_t radiosinuse;
	struct capwap_array* encryptsubelement;
	struct capwap_array* descsubelement;
};

#define CAPWAP_WTPDESC_SUBELEMENT_WBID_MASK					0x1f

struct capwap_wtpdescriptor_encrypt_subelement {
	uint8_t wbid;
	uint16_t capabilities;
};

#define CAPWAP_WTPDESC_SUBELEMENT_TYPE_FIRST				0
#define CAPWAP_WTPDESC_SUBELEMENT_HARDWAREVERSION			0
#define CAPWAP_WTPDESC_SUBELEMENT_SOFTWAREVERSION			1
#define CAPWAP_WTPDESC_SUBELEMENT_BOOTVERSION				2
#define CAPWAP_WTPDESC_SUBELEMENT_OTHERVERSION				3
#define CAPWAP_WTPDESC_SUBELEMENT_TYPE_LAST					3

#define CAPWAP_WTPDESC_SUBELEMENT_MAXDATA					1024

struct capwap_wtpdescriptor_desc_subelement {
	uint32_t vendor;
	uint16_t type;
	uint8_t* data;
};

extern struct capwap_message_elements_ops capwap_element_wtpdescriptor_ops;

#endif /* __CAPWAP_ELEMENT_WTPDESCRIPTOR_HEADER__ */
