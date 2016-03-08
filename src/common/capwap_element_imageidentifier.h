#ifndef __CAPWAP_ELEMENT_IMAGEIDENTIFIER_HEADER__
#define __CAPWAP_ELEMENT_IMAGEIDENTIFIER_HEADER__

#define CAPWAP_ELEMENT_IMAGEIDENTIFIER_VENDOR			0
#define CAPWAP_ELEMENT_IMAGEIDENTIFIER_TYPE			25
#define CAPWAP_ELEMENT_IMAGEIDENTIFIER				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_IMAGEIDENTIFIER_VENDOR, .type = CAPWAP_ELEMENT_IMAGEIDENTIFIER_TYPE }


#define CAPWAP_IMAGEIDENTIFIER_MAXLENGTH		1024

struct capwap_imageidentifier_element {
	uint32_t vendor;
	uint8_t* name;
};

extern const struct capwap_message_elements_ops capwap_element_imageidentifier_ops;

#endif /* __CAPWAP_ELEMENT_IMAGEIDENTIFIER_HEADER__ */
