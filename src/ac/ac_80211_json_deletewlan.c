#include "ac.h"
#include "ac_json.h"

/* */
static void* ac_json_80211_deletewlan_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	return NULL;	/* TODO */
}

/* */
static int ac_json_80211_deletewlan_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_deletewlan_element* deletewlan = (struct capwap_80211_deletewlan_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[deletewlan->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_DELETE_WLAN);

	if (item->deletewlan) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->deletewlan);
	}

	item->valid = 1;
	item->deletewlan = (struct capwap_80211_deletewlan_element*)ops->clone(deletewlan);

	return 1;
}

/* */
static void ac_json_80211_deletewlan_createjson(struct json_object* jsonparent, void* data) {
	/* TODO */
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_deletewlan_ops = {
	.type = CAPWAP_ELEMENT_80211_DELETE_WLAN,
	.json_type = "IEEE80211DeleteWLAN",
	.create = ac_json_80211_deletewlan_createmessageelement,
	.add_message_element = ac_json_80211_deletewlan_addmessageelement,
	.create_json = ac_json_80211_deletewlan_createjson
};
