#include "ac.h"
#include "ac_json.h"

/* */
static void* ac_json_80211_wtpradiofailalarm_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	return NULL;	/* TODO */
}

/* */
static int ac_json_80211_wtpradiofailalarm_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_wtpradiofailalarm_element* wtpradiofailalarm = (struct capwap_80211_wtpradiofailalarm_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[wtpradiofailalarm->radioid - 1];
	struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM);

	if (item->wtpradiofailalarm) {
		if (!overwrite) {
			return 0;
		}

		ops->free_message_element(item->wtpradiofailalarm);
	}

	item->valid = 1;
	item->wtpradiofailalarm = (struct capwap_80211_wtpradiofailalarm_element*)ops->clone_message_element(wtpradiofailalarm);

	return 1;
}

/* */
static void ac_json_80211_wtpradiofailalarm_createjson(struct json_object* jsonparent, void* data) {
	/* TODO */
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_wtpradiofailalarm_ops = {
	.type = CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM,
	.json_type = "IEEE80211WTPRadioFailAlarm",
	.create_message_element = ac_json_80211_wtpradiofailalarm_createmessageelement,
	.add_message_element = ac_json_80211_wtpradiofailalarm_addmessageelement,
	.create_json = ac_json_80211_wtpradiofailalarm_createjson
};
