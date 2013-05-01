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
	unsigned short rebootcount;
	unsigned short acinitiatedcount;
	unsigned short linkfailurecount;
	unsigned short swfailurecount;
	unsigned short hwfailurecount;
	unsigned short otherfailurecount;
	unsigned short unknownfailurecount;
	unsigned char lastfailuretype;
};

struct capwap_message_element* capwap_wtprebootstat_element_create(void* data, unsigned long datalength);
int capwap_wtprebootstat_element_validate(struct capwap_message_element* element);
void* capwap_wtprebootstat_element_parsing(struct capwap_message_element* element);
void capwap_wtprebootstat_element_free(void* data);


/* Helper */
#define CAPWAP_CREATE_WTPREBOOTSTAT_ELEMENT(x)			({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_WTPREBOOTSTAT);	\
															f->create(x, sizeof(struct capwap_wtprebootstat_element));	\
														})

#endif /* __CAPWAP_ELEMENT_WTPREBOOTSTAT_HEADER__ */
