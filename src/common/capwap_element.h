#ifndef __CAPWAP_ELEMENT_HEADER__
#define __CAPWAP_ELEMENT_HEADER__

#include "capwap_array.h"
#include "capwap_list.h"

struct capwap_message_element_id
{
	uint32_t vendor;
	uint16_t type;
};

/* */
typedef void* capwap_message_elements_handle;
struct capwap_write_message_elements_ops {
	int (*write_u8)(capwap_message_elements_handle handle, uint8_t data);
	int (*write_u16)(capwap_message_elements_handle handle, uint16_t data);
	int (*write_u32)(capwap_message_elements_handle handle, uint32_t data);
	int (*write_block)(capwap_message_elements_handle handle, const uint8_t* data, unsigned short length);
};

struct capwap_read_message_elements_ops {
	unsigned short (*read_ready)(capwap_message_elements_handle handle);
	int (*read_u8)(capwap_message_elements_handle handle, uint8_t* data);
	int (*read_u16)(capwap_message_elements_handle handle, uint16_t* data);
	int (*read_u32)(capwap_message_elements_handle handle, uint32_t* data);
	int (*read_block)(capwap_message_elements_handle handle, uint8_t* data, unsigned short length);
};

struct capwap_message_elements_ops
{
	int category;

	/* Build message element */
	void (*create)(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func);

	/* Parsing message element */
	void* (*parse)(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func);

	/* Memory management */
	void* (*clone)(void*);
	void (*free)(void*);
};

const struct capwap_message_elements_ops *capwap_get_message_element_ops(const struct capwap_message_element_id id);

/*********************************************************************************************************************/

/* Standard message elements */
#include "capwap_element_acdescriptor.h"				/* 00001 */
#include "capwap_element_acipv4list.h"					/* 00002 */
#include "capwap_element_acipv6list.h"					/* 00003 */
#include "capwap_element_acname.h"						/* 00004 */
#include "capwap_element_acnamepriority.h" 				/* 00005 */
#include "capwap_element_actimestamp.h"					/* 00006 */
#include "capwap_element_addmacacl.h"					/* 00007 */
#include "capwap_element_addstation.h"					/* 00008 */
/* Reserved */											/* 00009 */
#include "capwap_element_controlipv4.h"					/* 00010 */
#include "capwap_element_controlipv6.h"					/* 00011 */
#include "capwap_element_timers.h"						/* 00012 */
#include "capwap_element_datatransferdata.h"			/* 00013 */
#include "capwap_element_datatransfermode.h"			/* 00014 */
#include "capwap_element_decrypterrorreport.h"			/* 00015 */
#include "capwap_element_decrypterrorreportperiod.h"	/* 00016 */
#include "capwap_element_deletemacacl.h"				/* 00017 */
#include "capwap_element_deletestation.h"				/* 00018 */
/* Reserved */											/* 00019 */
#include "capwap_element_discoverytype.h"				/* 00020 */
#include "capwap_element_duplicateipv4.h"				/* 00021 */
#include "capwap_element_duplicateipv6.h"				/* 00022 */
#include "capwap_element_idletimeout.h"					/* 00023 */
#include "capwap_element_imagedata.h"					/* 00024 */
#include "capwap_element_imageidentifier.h"				/* 00025 */
#include "capwap_element_imageinfo.h"					/* 00026 */
#include "capwap_element_initdownload.h"				/* 00027 */
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
#include "capwap_element_wtpradiostat.h"				/* 00047 */
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

#include "capwap_vendor_travelping.h"

/*********************************************************************************************************************/
#define CAPWAP_MESSAGE_ELEMENT_SINGLE			0
#define CAPWAP_MESSAGE_ELEMENT_ARRAY			1
int capwap_get_message_element_category(uint16_t type);

struct capwap_message_element_itemlist
{
	struct capwap_message_element_id id;
	int category;
	void* data;
};

struct capwap_parsed_packet {
	struct capwap_packet_rxmng* rxmngpacket;
	struct capwap_list* messages;
};

/* */
#define PARSING_COMPLETE						0
#define UNRECOGNIZED_MESSAGE_ELEMENT			1
#define INVALID_MESSAGE_ELEMENT					2

int capwap_parsing_packet(struct capwap_packet_rxmng* rxmngpacket, struct capwap_parsed_packet* packet);
int capwap_validate_parsed_packet(struct capwap_parsed_packet* packet, struct capwap_array* returnedmessage);
void capwap_free_parsed_packet(struct capwap_parsed_packet* packet);

struct capwap_list_item *capwap_get_message_element(struct capwap_parsed_packet *packet,
				      const struct capwap_message_element_id id);
void *capwap_get_message_element_data(struct capwap_parsed_packet *packet,
				      const struct capwap_message_element_id id);

#endif /* __CAPWAP_ELEMENT_HEADER__ */
