#ifndef __CAPWAP_ELEMENT_IMAGE_DATA_HEADER__
#define __CAPWAP_ELEMENT_IMAGE_DATA_HEADER__

#define CAPWAP_ELEMENT_IMAGEDATA					24

#define CAPWAP_IMAGEDATA_TYPE_DATA_IS_INCLUDED		1
#define CAPWAP_IMAGEDATA_TYPE_DATA_EOF				2
#define CAPWAP_IMAGEDATA_TYPE_ERROR					5

struct capwap_imagedata_element {
	uint8_t type;
	uint16_t length;
	uint8_t* data;
};

extern struct capwap_message_elements_ops capwap_element_imagedata_ops;

#endif /* __CAPWAP_ELEMENT_IMAGE_DATA_HEADER__ */
