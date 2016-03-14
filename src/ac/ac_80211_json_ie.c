#include "ac.h"
#include "ac_json.h"

/* */
static void* ac_json_80211_ie_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	return NULL;	/* TODO */
}

/* */
static int ac_json_80211_ie_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_ie_element** ieclone;
	struct capwap_80211_ie_element* ie = (struct capwap_80211_ie_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[ie->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_IE);

	if (!item->iearray) {
		item->iearray = capwap_array_create(sizeof(struct capwap_80211_ie_element*), 0, 0);
	}

	item->valid = 1;
	ieclone = (struct capwap_80211_ie_element**)capwap_array_get_item_pointer(item->iearray, item->iearray->count);
	*ieclone = (struct capwap_80211_ie_element*)ops->clone(ie);

	return 1;
}

/* */
static void ac_json_80211_ie_createjson(struct json_object* jsonparent, void* data) {
	/* TODO */
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_ie_ops = {
	.type = CAPWAP_ELEMENT_80211_IE,
	.json_type = "IEEE80211IE",
	.create = ac_json_80211_ie_createmessageelement,
	.add_message_element = ac_json_80211_ie_addmessageelement,
	.create_json = ac_json_80211_ie_createjson
};
