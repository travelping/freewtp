#ifndef __AC_JSON_HEADER__
#define __AC_JSON_HEADER__

#include "capwap_array.h"
#include <json-c/json.h>

#define IEEE80211_BINDING_JSON_ROOT					"WTPRadio"

struct ac_json_ieee80211_item {
	int valid;
	struct capwap_80211_addwlan_element* addwlan;
	struct capwap_80211_antenna_element* antenna;
	struct capwap_80211_assignbssid_element* assignbssid;
	struct capwap_80211_deletewlan_element* deletewlan;
	struct capwap_80211_directsequencecontrol_element* directsequencecontrol;
	struct capwap_array* iearray;
	struct capwap_80211_macoperation_element* macoperation;
	struct capwap_80211_miccountermeasures_element* miccountermeasures;
	struct capwap_80211_multidomaincapability_element* multidomaincapability;
	struct capwap_80211_ofdmcontrol_element* ofdmcontrol;
	struct capwap_80211_rateset_element* rateset;
	struct capwap_80211_rsnaerrorreport_element* rsnaerrorreport;
	struct capwap_80211_statistics_element* statistics;
	struct capwap_80211_supportedrates_element* supportedrates;
	struct capwap_80211_txpower_element* txpower;
	struct capwap_80211_txpowerlevel_element* txpowerlevel;
	struct capwap_80211_updatewlan_element* updatewlan;
	struct capwap_80211_wtpqos_element* wtpqos;
	struct capwap_80211_wtpradioconf_element* wtpradioconf;
	struct capwap_80211_wtpradiofailalarm_element* wtpradiofailalarm;
	struct capwap_80211_wtpradioinformation_element* wtpradioinformation;
};

struct ac_json_ieee80211_wtpradio {
	struct ac_json_ieee80211_item items[RADIOID_MAX_COUNT];
};

/* JSON IEEE 802.11 message elements */
#include "ac_80211_json_addwlan.h"
#include "ac_80211_json_antenna.h"
#include "ac_80211_json_assignbssid.h"
#include "ac_80211_json_deletewlan.h"
#include "ac_80211_json_directsequencecontrol.h"
#include "ac_80211_json_ie.h"
#include "ac_80211_json_macoperation.h"
#include "ac_80211_json_miccountermeasures.h"
#include "ac_80211_json_multidomaincapability.h"
#include "ac_80211_json_ofdmcontrol.h"
#include "ac_80211_json_rateset.h"
#include "ac_80211_json_rsnaerrorreport.h"
#include "ac_80211_json_statistics.h"
#include "ac_80211_json_supportedrates.h"
#include "ac_80211_json_txpower.h"
#include "ac_80211_json_txpowerlevel.h"
#include "ac_80211_json_updatewlan.h"
#include "ac_80211_json_wtpqos.h"
#include "ac_80211_json_wtpradioconf.h"
#include "ac_80211_json_wtpradiofailalarm.h"
#include "ac_80211_json_wtpradioinformation.h"

/* */
struct ac_json_ieee80211_ops {
	/* Message Element Type */
	struct capwap_message_element_id type;

	/* Message Element JSON Type */
	char* json_type;

	/* Build message element */
	void* (*create)(struct json_object* jsonparent, uint16_t radioid);
	int (*add_message_element)(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite);

	/* Build JSON */
	void (*create_json)(struct json_object* jsonparent, void* data);
};

/* */
void ac_json_ieee80211_init(struct ac_json_ieee80211_wtpradio* wtpradio);
void ac_json_ieee80211_free(struct ac_json_ieee80211_wtpradio* wtpradio);

/* */
int ac_json_ieee80211_addmessageelement(struct ac_json_ieee80211_wtpradio *wtpradio,
					const struct capwap_message_element_id id,
					void *data, int overwrite);
int ac_json_ieee80211_parsingmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, struct capwap_message_element_itemlist* messageelement);
int ac_json_ieee80211_parsingjson(struct ac_json_ieee80211_wtpradio* wtpradio, struct json_object* jsonroot);

/* */
struct json_object* ac_json_ieee80211_getjson(struct ac_json_ieee80211_wtpradio* wtpradio);
void ac_json_ieee80211_buildpacket(struct ac_json_ieee80211_wtpradio* wtpradio, struct capwap_packet_txmng* txmngpacket);



#endif /* __AC_JSON_HEADER__ */
