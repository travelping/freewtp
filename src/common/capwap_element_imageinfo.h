#ifndef __CAPWAP_ELEMENT_IMAGE_INFO_HEADER__
#define __CAPWAP_ELEMENT_IMAGE_INFO_HEADER__

#define CAPWAP_ELEMENT_IMAGEINFO_VENDOR					0
#define CAPWAP_ELEMENT_IMAGEINFO_TYPE					26
#define CAPWAP_ELEMENT_IMAGEINFO						(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_IMAGEINFO_VENDOR, .type = CAPWAP_ELEMENT_IMAGEINFO_TYPE }


#define CAPWAP_IMAGEINFO_HASH_LENGTH				16

struct capwap_imageinfo_element {
	uint32_t length;
	uint8_t hash[CAPWAP_IMAGEINFO_HASH_LENGTH];
};

extern const struct capwap_message_elements_ops capwap_element_imageinfo_ops;

#endif /* __CAPWAP_ELEMENT_IMAGE_INFO_HEADER__ */
