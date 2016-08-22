#ifndef __CAPWAP_ELEMENT_INIT_DOWNLOAD_HEADER__
#define __CAPWAP_ELEMENT_INIT_DOWNLOAD_HEADER__

#define CAPWAP_ELEMENT_INITIATEDOWNLOAD_VENDOR		0
#define CAPWAP_ELEMENT_INITIATEDOWNLOAD_TYPE		27
#define CAPWAP_ELEMENT_INITIATEDOWNLOAD			(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_INITIATEDOWNLOAD_VENDOR, .type = CAPWAP_ELEMENT_INITIATEDOWNLOAD_TYPE }


struct capwap_initdownload_element {
	uint8_t dummy;
};

extern const struct capwap_message_elements_ops capwap_element_initdownload_ops;

#endif /* __CAPWAP_ELEMENT_INIT_DOWNLOAD_HEADER__ */
