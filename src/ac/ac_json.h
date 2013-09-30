#ifndef __AC_JSON_HEADER__
#define __AC_JSON_HEADER__

#include "capwap_array.h"

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

/* */
void ac_json_ieee80211_init(struct ac_json_ieee80211_wtpradio* wtpradio);
int ac_json_ieee80211_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, struct capwap_message_element_itemlist* messageelement);
struct json_object* ac_json_ieee80211_getjson(struct ac_json_ieee80211_wtpradio* wtpradio);
void ac_json_ieee80211_free(struct ac_json_ieee80211_wtpradio* wtpradio);


#endif /* __AC_JSON_HEADER__ */
