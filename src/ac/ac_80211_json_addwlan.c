#include "ac.h"
#include "ac_json.h"

/* */
static void* ac_json_80211_addwlan_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	return NULL;	/* TODO */
}

/* */
static int ac_json_80211_addwlan_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_addwlan_element* addwlan = (struct capwap_80211_addwlan_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[addwlan->radioid - 1];
	const struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_ADD_WLAN);

	if (item->addwlan) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->addwlan);
	}

	item->valid = 1;
	item->addwlan = (struct capwap_80211_addwlan_element*)ops->clone(addwlan);

	return 1;
}

/* */
static void ac_json_80211_addwlan_createjson(struct json_object* jsonparent, void* data) {
	/* TODO */
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_addwlan_ops = {
	.type = CAPWAP_ELEMENT_80211_ADD_WLAN,
	.json_type = "IEEE80211AddWLAN",
	.create = ac_json_80211_addwlan_createmessageelement,
	.add_message_element = ac_json_80211_addwlan_addmessageelement,
	.create_json = ac_json_80211_addwlan_createjson
};
