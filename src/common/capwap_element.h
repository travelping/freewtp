#ifndef __CAPWAP_ELEMENT_HEADER__
#define __CAPWAP_ELEMENT_HEADER__

#include "capwap_array.h"
#include "capwap_list.h"

/* Standard message elements 1 -> 52 (1 - 1023) */
#define CAPWAP_MESSAGE_ELEMENTS_START				1
#define CAPWAP_MESSAGE_ELEMENTS_STOP				53
#define CAPWAP_MESSAGE_ELEMENTS_COUNT				((CAPWAP_MESSAGE_ELEMENTS_STOP - CAPWAP_MESSAGE_ELEMENTS_START) + 1)
#define IS_MESSAGE_ELEMENTS(x)						(((x >= CAPWAP_MESSAGE_ELEMENTS_START) && (x <= CAPWAP_MESSAGE_ELEMENTS_STOP)) ? 1 : 0)

/* 802.11 message elements 1024 -> 1024 (1024 - 2047) */
#define CAPWAP_80211_MESSAGE_ELEMENTS_START			1024
#define CAPWAP_80211_MESSAGE_ELEMENTS_STOP			1048
#define CAPWAP_80211_MESSAGE_ELEMENTS_COUNT			((CAPWAP_80211_MESSAGE_ELEMENTS_STOP - CAPWAP_80211_MESSAGE_ELEMENTS_START) + 1)
#define IS_80211_MESSAGE_ELEMENTS(x)				(((x >= CAPWAP_80211_MESSAGE_ELEMENTS_START) && (x <= CAPWAP_80211_MESSAGE_ELEMENTS_STOP)) ? 1 : 0)

/* Message element */
struct capwap_message_element {
	unsigned short type;
	unsigned short length;
	char data[0];
} __attribute__((__packed__));

typedef struct capwap_message_element*(*capwap_create_message_element)(void* data, unsigned long length);
typedef int(*capwap_validate_message_element)(struct capwap_message_element* element);
typedef void*(*capwap_parsing_message_element)(struct capwap_message_element* element);
typedef void(*capwap_free_message_element)(void*);

struct capwap_message_elements_func {
	capwap_create_message_element create;
	capwap_validate_message_element check;
	capwap_parsing_message_element parsing;
	capwap_free_message_element free;
};

struct capwap_message_elements_func* capwap_get_message_element(unsigned long code);

/*********************************************************************************************************************/
/* Standard message elements */
#include "capwap_element_acdescriptor.h"				/* 00001 */
#include "capwap_element_acipv4list.h"					/* 00002 */
#include "capwap_element_acipv6list.h"					/* 00003 */
#include "capwap_element_acname.h"						/* 00004 */
#include "capwap_element_acnamepriority.h" 				/* 00005 */
/* 00006 */
/* 00007 */
/* 00008 */
/* Reserved */											/* 00009 */
#include "capwap_element_controlipv4.h"					/* 00010 */
#include "capwap_element_controlipv6.h"					/* 00011 */
#include "capwap_element_timers.h"						/* 00012 */
/* 00013 */
/* 00014 */
/* 00015 */
#include "capwap_element_decrypterrorreportperiod.h"	/* 00016 */
/* 00017 */
/* 00018 */
/* Reserved */											/* 00019 */
#include "capwap_element_discoverytype.h"				/* 00020 */
/* 00021 */
/* 00022 */
#include "capwap_element_idletimeout.h"					/* 00023 */
/* 00024 */
#include "capwap_element_imageidentifier.h"				/* 00025 */
/* 00026 */
/* 00027 */
#include "capwap_element_location.h"					/* 00028 */
#include "capwap_element_maximumlength.h"				/* 00029 */
#include "capwap_element_localipv4.h"					/* 00030 */
#include "capwap_element_radioadmstate.h"				/* 00031 */
#include "capwap_element_radiooprstate.h"				/* 00032 */
#include "capwap_element_resultcode.h"					/* 00033 */
#include "capwap_element_returnedmessage.h"				/* 00034 */
#include "capwap_element_sessionid.h"					/* 00035 */
#include "capwap_element_statisticstimer.h"				/* 00036 */
#include "capwap_element_vendorpayload.h"				/* 00037 */
#include "capwap_element_wtpboarddata.h"				/* 00038 */
#include "capwap_element_wtpdescriptor.h"				/* 00039 */
#include "capwap_element_wtpfallback.h"					/* 00040 */
#include "capwap_element_wtpframetunnelmode.h"			/* 00041 */
/* Reserved */											/* 00042 */
/* Reserved */											/* 00043 */
#include "capwap_element_wtpmactype.h"					/* 00044 */
#include "capwap_element_wtpname.h"						/* 00045 */
/* Reserved */											/* 00046 */
/* 00047 */
#include "capwap_element_wtprebootstat.h"				/* 00048 */
#include "capwap_element_wtpstaticipaddress.h"			/* 00049 */
#include "capwap_element_localipv6.h"					/* 00050 */
#include "capwap_element_transport.h"					/* 00051 */
#include "capwap_element_mtudiscovery.h"				/* 00052 */
#include "capwap_element_ecnsupport.h"					/* 00053 */

/* IEEE 802.11 message elements */
#include "capwap_element_80211_wtpradioinformation.h"	/* 01048 */

/*********************************************************************************************************************/
struct capwap_element_discovery_request {
	struct capwap_discoverytype_element* discoverytype;
	struct capwap_wtpboarddata_element* wtpboarddata;
	struct capwap_wtpdescriptor_element* wtpdescriptor;
	struct capwap_wtpframetunnelmode_element* wtpframetunnel;
	struct capwap_wtpmactype_element* wtpmactype;
	struct capwap_mtudiscovery_element* mtudiscovery;
	struct capwap_vendorpayload_element* vendorpayload;
	
	union {
		struct {
			struct capwap_array* wtpradioinformation;
		} ieee80211;
	} binding;
};

void capwap_init_element_discovery_request(struct capwap_element_discovery_request* element, unsigned short binding);
int capwap_parsing_element_discovery_request(struct capwap_element_discovery_request* element, struct capwap_list_item* item);
void capwap_free_element_discovery_request(struct capwap_element_discovery_request* element, unsigned short binding);

/* */
struct capwap_element_discovery_response {
	struct capwap_acdescriptor_element* acdescriptor;
	struct capwap_acname_element* acname;
	struct capwap_array* controlipv4;
	struct capwap_array* controlipv6;
	struct capwap_vendorpayload_element* vendorpayload;
	
	union {
		struct {
			struct capwap_array* wtpradioinformation;
		} ieee80211;
	} binding;
};

void capwap_init_element_discovery_response(struct capwap_element_discovery_response* element, unsigned short binding);
int capwap_parsing_element_discovery_response(struct capwap_element_discovery_response* element, struct capwap_list_item* item);
void capwap_free_element_discovery_response(struct capwap_element_discovery_response* element, unsigned short binding);

/* */
struct capwap_element_join_request {
	struct capwap_location_element* locationdata;
	struct capwap_wtpboarddata_element* wtpboarddata;
	struct capwap_wtpdescriptor_element* wtpdescriptor;
	struct capwap_wtpname_element* wtpname;
	struct capwap_sessionid_element* sessionid;
	struct capwap_wtpframetunnelmode_element* wtpframetunnel;
	struct capwap_wtpmactype_element* wtpmactype;
	struct capwap_ecnsupport_element* ecnsupport;
	struct capwap_localipv4_element* localipv4;
	struct capwap_localipv6_element* localipv6;
	struct capwap_transport_element* trasport;
	struct capwap_maximumlength_element* maxiumlength;
	struct capwap_wtprebootstat_element* wtprebootstat;
	struct capwap_vendorpayload_element* vendorpayload;
	
	union {
		struct {
			struct capwap_array* wtpradioinformation;
		} ieee80211;
	} binding;
};

void capwap_init_element_join_request(struct capwap_element_join_request* element, unsigned short binding);
int capwap_parsing_element_join_request(struct capwap_element_join_request* element, struct capwap_list_item* item);
void capwap_free_element_join_request(struct capwap_element_join_request* element, unsigned short binding);

/* */
struct capwap_element_join_response {
	struct capwap_resultcode_element* resultcode;
	struct capwap_array* returnedmessage;
	struct capwap_acdescriptor_element* acdescriptor;
	struct capwap_acname_element* acname;
	struct capwap_ecnsupport_element* ecnsupport;
	struct capwap_array* controlipv4;
	struct capwap_array* controlipv6;
	struct capwap_localipv4_element* localipv4;
	struct capwap_localipv6_element* localipv6;
	capwap_acipv4list_element_array* acipv4list;
	capwap_acipv6list_element_array* acipv6list;
	struct capwap_transport_element* trasport;
	struct capwap_imageidentifier_element* imageidentifier;
	struct capwap_maximumlength_element* maxiumlength;
	struct capwap_vendorpayload_element* vendorpayload;

	union {
		struct {
			struct capwap_array* wtpradioinformation;
		} ieee80211;
	} binding;
};

void capwap_init_element_join_response(struct capwap_element_join_response* element, unsigned short binding);
int capwap_parsing_element_join_response(struct capwap_element_join_response* element, struct capwap_list_item* item);
void capwap_free_element_join_response(struct capwap_element_join_response* element, unsigned short binding);

/* */
struct capwap_element_configurationstatus_request {
	struct capwap_acname_element* acname;
	struct capwap_array* radioadmstatus;
	struct capwap_statisticstimer_element* statisticstimer;
	struct capwap_wtprebootstat_element* wtprebootstat;
	struct capwap_array* acnamepriority;
	struct capwap_transport_element* trasport;
	struct capwap_wtpstaticipaddress_element* wtpstaticipaddress;
	struct capwap_vendorpayload_element* vendorpayload;
};

void capwap_init_element_configurationstatus_request(struct capwap_element_configurationstatus_request* element, unsigned short binding);
int capwap_parsing_element_configurationstatus_request(struct capwap_element_configurationstatus_request* element, struct capwap_list_item* item);
void capwap_free_element_configurationstatus_request(struct capwap_element_configurationstatus_request* element, unsigned short binding);

/* */
struct capwap_element_configurationstatus_response {
	struct capwap_timers_element* timers;
	struct capwap_array* decrypterrorresultperiod;
	struct capwap_idletimeout_element* idletimeout;
	struct capwap_wtpfallback_element* wtpfallback;
	capwap_acipv4list_element_array* acipv4list;
	capwap_acipv6list_element_array* acipv6list;
	struct capwap_array* radiooprstatus;
	struct capwap_wtpstaticipaddress_element* wtpstaticipaddress;
	struct capwap_vendorpayload_element* vendorpayload;
};

void capwap_init_element_configurationstatus_response(struct capwap_element_configurationstatus_response* element, unsigned short binding);
int capwap_parsing_element_configurationstatus_response(struct capwap_element_configurationstatus_response* element, struct capwap_list_item* item);
void capwap_free_element_configurationstatus_response(struct capwap_element_configurationstatus_response* element, unsigned short binding);

/* */
struct capwap_element_changestateevent_request {
	struct capwap_array* radiooprstatus;
	struct capwap_resultcode_element* resultcode;
	struct capwap_array* returnedmessage;
	struct capwap_vendorpayload_element* vendorpayload;
};

void capwap_init_element_changestateevent_request(struct capwap_element_changestateevent_request* element, unsigned short binding);
int capwap_parsing_element_changestateevent_request(struct capwap_element_changestateevent_request* element, struct capwap_list_item* item);
void capwap_free_element_changestateevent_request(struct capwap_element_changestateevent_request* element, unsigned short binding);

/* */
struct capwap_element_changestateevent_response {
	struct capwap_vendorpayload_element* vendorpayload;
};

void capwap_init_element_changestateevent_response(struct capwap_element_changestateevent_response* element, unsigned short binding);
int capwap_parsing_element_changestateevent_response(struct capwap_element_changestateevent_response* element, struct capwap_list_item* item);
void capwap_free_element_changestateevent_response(struct capwap_element_changestateevent_response* element, unsigned short binding);

/* */
struct capwap_element_echo_request {
	struct capwap_vendorpayload_element* vendorpayload;
};

void capwap_init_element_echo_request(struct capwap_element_echo_request* element, unsigned short binding);
int capwap_parsing_element_echo_request(struct capwap_element_echo_request* element, struct capwap_list_item* item);
void capwap_free_element_echo_request(struct capwap_element_echo_request* element, unsigned short binding);

/* */
struct capwap_element_echo_response {
	struct capwap_vendorpayload_element* vendorpayload;
};

void capwap_init_element_echo_response(struct capwap_element_echo_response* element, unsigned short binding);
int capwap_parsing_element_echo_response(struct capwap_element_echo_response* element, struct capwap_list_item* item);
void capwap_free_element_echo_response(struct capwap_element_echo_response* element, unsigned short binding);

/* */
struct capwap_element_reset_request {
	struct capwap_imageidentifier_element* imageidentifier;
	struct capwap_vendorpayload_element* vendorpayload;
};

void capwap_init_element_reset_request(struct capwap_element_reset_request* element, unsigned short binding);
int capwap_parsing_element_reset_request(struct capwap_element_reset_request* element, struct capwap_list_item* item);
void capwap_free_element_reset_request(struct capwap_element_reset_request* element, unsigned short binding);

/* */
struct capwap_element_reset_response {
	struct capwap_resultcode_element* resultcode;	
	struct capwap_vendorpayload_element* vendorpayload;
};

void capwap_init_element_reset_response(struct capwap_element_reset_response* element, unsigned short binding);
int capwap_parsing_element_reset_response(struct capwap_element_reset_response* element, struct capwap_list_item* item);
void capwap_free_element_reset_response(struct capwap_element_reset_response* element, unsigned short binding);

#endif /* __CAPWAP_ELEMENT_HEADER__ */
