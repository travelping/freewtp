#ifndef __CAPWAP_ELEMENT_INIT_DOWNLOAD_HEADER__
#define __CAPWAP_ELEMENT_INIT_DOWNLOAD_HEADER__

#define CAPWAP_ELEMENT_INITIATEDOWNLOAD		27

#define CAPWAP_LIMITED_ECN_SUPPORT			0
#define CAPWAP_FULL_ECN_SUPPORT				1

struct capwap_initdownload_element {
	uint8_t dummy;
};

extern struct capwap_message_elements_ops capwap_element_initdownload_ops;

#endif /* __CAPWAP_ELEMENT_INIT_DOWNLOAD_HEADER__ */
