#include "ac.h"
#include "ac_json.h"

/* */
static void* ac_json_80211_assignbssid_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	return NULL;	/* TODO */
}

/* */
static int ac_json_80211_assignbssid_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_assignbssid_element* assignbssid = (struct capwap_80211_assignbssid_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[assignbssid->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_ASSIGN_BSSID);

	if (item->assignbssid) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->assignbssid);
	}

	item->valid = 1;
	item->assignbssid = (struct capwap_80211_assignbssid_element*)ops->clone(assignbssid);

	return 1;
}

/* */
static void ac_json_80211_assignbssid_createjson(struct json_object* jsonparent, void* data) {
	/* TODO */
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_assignbssid_ops = {
	.type = CAPWAP_ELEMENT_80211_ASSIGN_BSSID,
	.json_type = "IEEE80211AssignBSSID",
	.create = ac_json_80211_assignbssid_createmessageelement,
	.add_message_element = ac_json_80211_assignbssid_addmessageelement,
	.create_json = ac_json_80211_assignbssid_createjson
};
