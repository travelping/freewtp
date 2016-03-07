#ifndef __CAPWAP_ELEMENT_INIT_DOWNLOAD_HEADER__
#define __CAPWAP_ELEMENT_INIT_DOWNLOAD_HEADER__

#define CAPWAP_ELEMENT_INITIATEDOWNLOAD		27

struct capwap_initdownload_element {
	uint8_t dummy;
};

extern const struct capwap_message_elements_ops capwap_element_initdownload_ops;

#endif /* __CAPWAP_ELEMENT_INIT_DOWNLOAD_HEADER__ */
