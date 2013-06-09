#ifndef __CAPWAP_ELEMENT_IMAGEIDENTIFIER_HEADER__
#define __CAPWAP_ELEMENT_IMAGEIDENTIFIER_HEADER__

#define CAPWAP_ELEMENT_IMAGEIDENTIFIER			25

#define CAPWAP_IMAGEIDENTIFIER_MAXLENGTH		1024

struct capwap_imageidentifier_element {
	uint32_t vendor;
	uint8_t* name;
};

extern struct capwap_message_elements_ops capwap_element_imageidentifier_ops;

#endif /* __CAPWAP_ELEMENT_IMAGEIDENTIFIER_HEADER__ */
