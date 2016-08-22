#ifndef __CAPWAP_ELEMENT_HEADER__
#define __CAPWAP_ELEMENT_HEADER__

#include "array.h"
#include "list.h"

struct capwap_message_element_id
{
	uint32_t vendor;
	uint16_t type;
};

#define message_element_id_eq(a, b)			\
	(((a).vendor == (b).vendor) && ((a).type == (b).type))

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
#include "element_acdescriptor.h"				/* 00001 */
#include "element_acipv4list.h"					/* 00002 */
#include "element_acipv6list.h"					/* 00003 */
#include "element_acname.h"						/* 00004 */
#include "element_acnamepriority.h" 				/* 00005 */
#include "element_actimestamp.h"					/* 00006 */
#include "element_addmacacl.h"					/* 00007 */
#include "element_addstation.h"					/* 00008 */
/* Reserved */											/* 00009 */
#include "element_controlipv4.h"					/* 00010 */
#include "element_controlipv6.h"					/* 00011 */
#include "element_timers.h"						/* 00012 */
#include "element_datatransferdata.h"			/* 00013 */
#include "element_datatransfermode.h"			/* 00014 */
#include "element_decrypterrorreport.h"			/* 00015 */
#include "element_decrypterrorreportperiod.h"	/* 00016 */
#include "element_deletemacacl.h"				/* 00017 */
#include "element_deletestation.h"				/* 00018 */
/* Reserved */											/* 00019 */
#include "element_discoverytype.h"				/* 00020 */
#include "element_duplicateipv4.h"				/* 00021 */
#include "element_duplicateipv6.h"				/* 00022 */
#include "element_idletimeout.h"					/* 00023 */
#include "element_imagedata.h"					/* 00024 */
#include "element_imageidentifier.h"				/* 00025 */
#include "element_imageinfo.h"					/* 00026 */
#include "element_initdownload.h"				/* 00027 */
#include "element_location.h"					/* 00028 */
#include "element_maximumlength.h"				/* 00029 */
#include "element_localipv4.h"					/* 00030 */
#include "element_radioadmstate.h"				/* 00031 */
#include "element_radiooprstate.h"				/* 00032 */
#include "element_resultcode.h"					/* 00033 */
#include "element_returnedmessage.h"				/* 00034 */
#include "element_sessionid.h"					/* 00035 */
#include "element_statisticstimer.h"				/* 00036 */
#include "element_vendorpayload.h"				/* 00037 */
#include "element_wtpboarddata.h"				/* 00038 */
#include "element_wtpdescriptor.h"				/* 00039 */
#include "element_wtpfallback.h"					/* 00040 */
#include "element_wtpframetunnelmode.h"			/* 00041 */
/* Reserved */											/* 00042 */
/* Reserved */											/* 00043 */
#include "element_wtpmactype.h"					/* 00044 */
#include "element_wtpname.h"						/* 00045 */
/* Reserved */											/* 00046 */
#include "element_wtpradiostat.h"				/* 00047 */
#include "element_wtprebootstat.h"				/* 00048 */
#include "element_wtpstaticipaddress.h"			/* 00049 */
#include "element_localipv6.h"					/* 00050 */
#include "element_transport.h"					/* 00051 */
#include "element_mtudiscovery.h"				/* 00052 */
#include "element_ecnsupport.h"					/* 00053 */

/* IEEE 802.11 message elements */
#include "element_80211_addwlan.h"				/* 01024 */
#include "element_80211_antenna.h"				/* 01025 */
#include "element_80211_assignbssid.h"			/* 01026 */
#include "element_80211_deletewlan.h"			/* 01027 */
#include "element_80211_directsequencecontrol.h"	/* 01028 */
#include "element_80211_ie.h"					/* 01029 */
#include "element_80211_macoperation.h"			/* 01030 */
#include "element_80211_miccountermeasures.h"	/* 01031 */
#include "element_80211_multidomaincapability.h"	/* 01032 */
#include "element_80211_ofdmcontrol.h"			/* 01033 */
#include "element_80211_rateset.h"				/* 01034 */
#include "element_80211_rsnaerrorreport.h"		/* 01035 */
#include "element_80211_station.h"				/* 01036 */
#include "element_80211_stationqos.h"			/* 01037 */
#include "element_80211_stationkey.h"			/* 01038 */
#include "element_80211_statistics.h"			/* 01039 */
#include "element_80211_supportedrates.h"		/* 01040 */
#include "element_80211_txpower.h"				/* 01041 */
#include "element_80211_txpowerlevel.h"			/* 01042 */
#include "element_80211_updatestationqos.h"		/* 01043 */
#include "element_80211_updatewlan.h"			/* 01044 */
#include "element_80211_wtpqos.h"				/* 01045 */
#include "element_80211_wtpradioconf.h"			/* 01046 */
#include "element_80211_wtpradiofailalarm.h"		/* 01047 */
#include "element_80211_wtpradioinformation.h"		/* 01048 */
#include "element_80211_supported_mac_profiles.h"	/* 01060 */
#include "element_80211_mac_profile.h"			/* 01061 */

#include "vendor_travelping.h"

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
