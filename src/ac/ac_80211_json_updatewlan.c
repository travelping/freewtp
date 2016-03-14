#include "ac.h"
#include "ac_json.h"

/* */
static void* ac_json_80211_updatewlan_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	return NULL;	/* TODO */
}

/* */
static int ac_json_80211_updatewlan_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_updatewlan_element* updatewlan = (struct capwap_80211_updatewlan_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[updatewlan->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_UPDATE_WLAN);

	if (item->updatewlan) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->updatewlan);
	}

	item->valid = 1;
	item->updatewlan = (struct capwap_80211_updatewlan_element*)ops->clone(updatewlan);

	return 1;
}

/* */
static void ac_json_80211_updatewlan_createjson(struct json_object* jsonparent, void* data) {
	/* TODO */
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_updatewlan_ops = {
	.type = CAPWAP_ELEMENT_80211_UPDATE_WLAN,
	.json_type = "IEEE80211UpdateWLAN",
	.create = ac_json_80211_updatewlan_createmessageelement,
	.add_message_element = ac_json_80211_updatewlan_addmessageelement,
	.create_json = ac_json_80211_updatewlan_createjson
};
