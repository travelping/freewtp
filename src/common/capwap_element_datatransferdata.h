#ifndef __CAPWAP_ELEMENT_DATA_TRANSFER_DATA_HEADER__
#define __CAPWAP_ELEMENT_DATA_TRANSFER_DATA_HEADER__

#define CAPWAP_ELEMENT_DATATRANSFERDATA				13

#define CAPWAP_DATATRANSFERDATA_TYPE_DATA_IS_INCLUDED		1
#define CAPWAP_DATATRANSFERDATA_TYPE_DATA_EOF				2
#define CAPWAP_DATATRANSFERDATA_TYPE_ERROR					5

#define CAPWAP_DATATRANSFERDATA_MODE_CRASH_DUMP				1
#define CAPWAP_DATATRANSFERDATA_MODE_MEMORY_DUMP			2

struct capwap_datatransferdata_element {
	uint8_t type;
	uint8_t mode;
	uint16_t length;
	uint8_t* data;
};

extern const struct capwap_message_elements_ops capwap_element_datatransferdata_ops;

#endif /* __CAPWAP_ELEMENT_DATA_TRANSFER_DATA_HEADER__ */
