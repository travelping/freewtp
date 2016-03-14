#include "ac.h"
#include "ac_json.h"

/*
IEEE80211WTPRadioFailAlarm: {
	Type: [int],
	Status: [int]
}
*/

/* */
static void* ac_json_80211_wtpradiofailalarm_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	struct json_object* jsonitem;
	struct capwap_80211_wtpradiofailalarm_element* wtpradiofailalarm;

	wtpradiofailalarm = (struct capwap_80211_wtpradiofailalarm_element*)capwap_alloc(sizeof(struct capwap_80211_wtpradiofailalarm_element));
	memset(wtpradiofailalarm, 0, sizeof(struct capwap_80211_wtpradiofailalarm_element));
	wtpradiofailalarm->radioid = radioid;

	/* */
	jsonitem = compat_json_object_object_get(jsonparent, "Type");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		wtpradiofailalarm->type = (uint8_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(wtpradiofailalarm);
		return NULL;
	}

	/* */
	jsonitem = compat_json_object_object_get(jsonparent, "Status");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		wtpradiofailalarm->status = (uint8_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(wtpradiofailalarm);
		return NULL;
	}

	return wtpradiofailalarm;
}

/* */
static int ac_json_80211_wtpradiofailalarm_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_wtpradiofailalarm_element* wtpradiofailalarm = (struct capwap_80211_wtpradiofailalarm_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[wtpradiofailalarm->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM);

	if (item->wtpradiofailalarm) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->wtpradiofailalarm);
	}

	item->valid = 1;
	item->wtpradiofailalarm = (struct capwap_80211_wtpradiofailalarm_element*)ops->clone(wtpradiofailalarm);

	return 1;
}

/* */
static void ac_json_80211_wtpradiofailalarm_createjson(struct json_object* jsonparent, void* data) {
	struct json_object* jsonitem;
	struct capwap_80211_wtpradiofailalarm_element* wtpradiofailalarm = (struct capwap_80211_wtpradiofailalarm_element*)data;

	jsonitem = json_object_new_object();
	json_object_object_add(jsonitem, "Type", json_object_new_int((int)wtpradiofailalarm->type));
	json_object_object_add(jsonitem, "Status", json_object_new_int((int)wtpradiofailalarm->status));
	json_object_object_add(jsonparent, "IEEE80211WTPRadioFailAlarm", jsonitem);
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_wtpradiofailalarm_ops = {
	.type = CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM,
	.json_type = "IEEE80211WTPRadioFailAlarm",
	.create = ac_json_80211_wtpradiofailalarm_createmessageelement,
	.add_message_element = ac_json_80211_wtpradiofailalarm_addmessageelement,
	.create_json = ac_json_80211_wtpradiofailalarm_createjson
};
