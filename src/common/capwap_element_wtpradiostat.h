#ifndef __CAPWAP_ELEMENT_WTPRADIOSTAT_HEADER__
#define __CAPWAP_ELEMENT_WTPRADIOSTAT_HEADER__

#define CAPWAP_ELEMENT_WTPRADIOSTAT						47

#define CAPWAP_WTPRADIOSTAT_FAILER_TYPE_STATNOTSUPP		0
#define CAPWAP_WTPRADIOSTAT_FAILER_TYPE_SWFAIL			1
#define CAPWAP_WTPRADIOSTAT_FAILER_TYPE_HWFAIL			2
#define CAPWAP_WTPRADIOSTAT_FAILER_TYPE_OTHERFAIL		3
#define CAPWAP_WTPRADIOSTAT_FAILER_TYPE_UNKNOWN			255

struct capwap_wtpradiostat_element {
	uint8_t radioid;
	uint8_t lastfailtype;
	uint16_t resetcount;
	uint16_t swfailercount;
	uint16_t hwfailercount;
	uint16_t otherfailercount;
	uint16_t unknownfailercount;
	uint16_t configupdatecount;
	uint16_t channelchangecount;
	uint16_t bandchangecount;
	uint16_t currentnoisefloor;
};

extern const struct capwap_message_elements_ops capwap_element_wtpradiostat_ops;

#endif /* __CAPWAP_ELEMENT_WTPRADIOSTAT_HEADER__ */
