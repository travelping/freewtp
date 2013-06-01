#ifndef __CAPWAP_ELEMENT_HEADER__
#define __CAPWAP_ELEMENT_HEADER__

#include "capwap_rfc.h"
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

/* */
typedef void* capwap_message_elements_handle;
struct capwap_write_message_elements_ops {
	int (*write_u8)(capwap_message_elements_handle handle, uint8_t data);
	int (*write_u16)(capwap_message_elements_handle handle, uint16_t data);
	int (*write_u32)(capwap_message_elements_handle handle, uint32_t data);
	int (*write_block)(capwap_message_elements_handle handle, uint8_t* data, unsigned short length);
};

struct capwap_read_message_elements_ops {
	unsigned short (*read_ready)(capwap_message_elements_handle handle);
	int (*read_u8)(capwap_message_elements_handle handle, uint8_t* data);
	int (*read_u16)(capwap_message_elements_handle handle, uint16_t* data);
	int (*read_u32)(capwap_message_elements_handle handle, uint32_t* data);
	int (*read_block)(capwap_message_elements_handle handle, uint8_t* data, unsigned short length);
};

struct capwap_message_elements_ops {
	/* Build message element */
	void (*create_message_element)(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func);

	/* Parsing message element */
	void* (*parsing_message_element)(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func);
	void (*free_parsed_message_element)(void*);
};

struct capwap_message_elements_ops* capwap_get_message_element_ops(unsigned short code);

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
#include "capwap_element_80211_addwlan.h"				/* 01024 */
#include "capwap_element_80211_antenna.h"				/* 01025 */
#include "capwap_element_80211_assignbssid.h"			/* 01026 */
#include "capwap_element_80211_deletewlan.h"			/* 01027 */
#include "capwap_element_80211_directsequencecontrol.h"	/* 01028 */
#include "capwap_element_80211_ie.h"					/* 01029 */
#include "capwap_element_80211_macoperation.h"			/* 01030 */
#include "capwap_element_80211_miccountermeasures.h"	/* 01031 */
#include "capwap_element_80211_multidomaincapability.h"	/* 01032 */
#include "capwap_element_80211_ofdmcontrol.h"			/* 01033 */
#include "capwap_element_80211_rateset.h"				/* 01034 */
#include "capwap_element_80211_rsnaerrorreport.h"		/* 01035 */
#include "capwap_element_80211_station.h"				/* 01036 */
#include "capwap_element_80211_stationqos.h"			/* 01037 */
#include "capwap_element_80211_stationkey.h"			/* 01038 */
#include "capwap_element_80211_statistics.h"			/* 01039 */
#include "capwap_element_80211_supportedrates.h"		/* 01040 */
#include "capwap_element_80211_txpower.h"				/* 01041 */
#include "capwap_element_80211_txpowerlevel.h"			/* 01042 */
#include "capwap_element_80211_updatestationqos.h"		/* 01043 */
#include "capwap_element_80211_updatewlan.h"			/* 01044 */
#include "capwap_element_80211_wtpqos.h"				/* 01045 */
#include "capwap_element_80211_wtpradioconf.h"			/* 01046 */
#include "capwap_element_80211_wtpradiofailalarm.h"		/* 01047 */
#include "capwap_element_80211_wtpradioinformation.h"	/* 01048 */

/*********************************************************************************************************************/
struct capwap_message_elements {
	struct capwap_acdescriptor_element* acdescriptor;
	struct capwap_acipv4list_element* acipv4list;
	struct capwap_acipv6list_element* acipv6list;
	struct capwap_acname_element* acname;
	struct capwap_array* acnamepriority;
	struct capwap_array* controlipv4;
	struct capwap_array* controlipv6;
	struct capwap_timers_element* timers;
	struct capwap_array* decrypterrorreportperiod;
	struct capwap_discoverytype_element* discoverytype;
	struct capwap_idletimeout_element* idletimeout;
	struct capwap_imageidentifier_element* imageidentifier;
	struct capwap_location_element* location;
	struct capwap_maximumlength_element* maximumlength;
	struct capwap_localipv4_element* localipv4;
	struct capwap_array* radioadmstate;
	struct capwap_array* radiooprstate;
	struct capwap_resultcode_element* resultcode;
	struct capwap_array* returnedmessage;
	struct capwap_sessionid_element* sessionid; 
	struct capwap_statisticstimer_element* statisticstimer;
	struct capwap_vendorpayload_element* vendorpayload;
	struct capwap_wtpboarddata_element* wtpboarddata;
	struct capwap_wtpdescriptor_element* wtpdescriptor;
	struct capwap_wtpfallback_element* wtpfallback;
	struct capwap_wtpframetunnelmode_element* wtpframetunnel;
	struct capwap_wtpmactype_element* wtpmactype;
	struct capwap_wtpname_element* wtpname;
	struct capwap_wtprebootstat_element* wtprebootstat;
	struct capwap_wtpstaticipaddress_element* wtpstaticipaddress;
	struct capwap_localipv6_element* localipv6;
	struct capwap_transport_element* transport;
	struct capwap_mtudiscovery_element* mtudiscovery;
	struct capwap_ecnsupport_element* ecnsupport;

	union {
		struct {
			struct capwap_array* antenna;
			struct capwap_array* directsequencecontrol;
			struct capwap_array* macoperation;
			struct capwap_array* multidomaincapability;
			struct capwap_array* ofdmcontrol;
			struct capwap_array* rateset;
			struct capwap_array* supportedrates;
			struct capwap_array* txpower;
			struct capwap_array* txpowerlevel;
			struct capwap_array* wtpradioinformation;
		} ieee80211;
	};
};

struct capwap_parsed_packet {
	struct capwap_packet_rxmng* rxmngpacket;
	struct capwap_connection* connection;
	struct capwap_message_elements messageelements;
};

int capwap_parsing_packet(struct capwap_packet_rxmng* rxmngpacket, struct capwap_connection* connection, struct capwap_parsed_packet* packet);
int capwap_validate_parsed_packet(struct capwap_parsed_packet* packet, struct capwap_array* returnedmessage);
void capwap_free_parsed_packet(struct capwap_parsed_packet* packet);

#endif /* __CAPWAP_ELEMENT_HEADER__ */
