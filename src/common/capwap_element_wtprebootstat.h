#ifndef __CAPWAP_ELEMENT_WTPREBOOTSTAT_HEADER__
#define __CAPWAP_ELEMENT_WTPREBOOTSTAT_HEADER__

#define CAPWAP_ELEMENT_WTPREBOOTSTAT			48

#define CAPWAP_NOTAVAILABLE_REBOOT_COUNT		65535
#define CAPWAP_NOTAVAILABLE_ACINIT_COUNT		65535

#define CAPWAP_LAST_FAILURE_NOTSUPPORTED 		0
#define CAPWAP_LAST_FAILURE_ACINITIATED			1
#define CAPWAP_LAST_FAILURE_LINK				2
#define CAPWAP_LAST_FAILURE_SOFTWARE			3
#define CAPWAP_LAST_FAILURE_HARDWARE			4
#define CAPWAP_LAST_FAILURE_OTHER				5
#define CAPWAP_LAST_FAILURE_UNKNOWN				255

struct capwap_wtprebootstat_element {
	uint16_t rebootcount;
	uint16_t acinitiatedcount;
	uint16_t linkfailurecount;
	uint16_t swfailurecount;
	uint16_t hwfailurecount;
	uint16_t otherfailurecount;
	uint16_t unknownfailurecount;
	uint8_t lastfailuretype;
};

extern struct capwap_message_elements_ops capwap_element_wtprebootstat_ops;

#endif /* __CAPWAP_ELEMENT_WTPREBOOTSTAT_HEADER__ */
