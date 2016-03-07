#ifndef __CAPWAP_ELEMENT_DATA_TRANSFER_MODE_HEADER__
#define __CAPWAP_ELEMENT_DATA_TRANSFER_MODE_HEADER__

#define CAPWAP_ELEMENT_DATATRANSFERMODE			14

#define CAPWAP_DATATRANSFERMODE_MODE_CRASH_DUMP				1
#define CAPWAP_DATATRANSFERMODE_MODE_MEMORY_DUMP			2

struct capwap_datatransfermode_element {
	uint8_t mode;
};

extern const struct capwap_message_elements_ops capwap_element_datatransfermode_ops;

#endif /* __CAPWAP_ELEMENT_DATA_TRANSFER_MODE_HEADER__ */
