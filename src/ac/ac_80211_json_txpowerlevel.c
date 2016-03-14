#include "ac.h"
#include "ac_json.h"

/*
IEEE80211TXPowerLevel: [
	[int]
]
*/

/* */
static void* ac_json_80211_txpowerlevel_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	int i;
	int length;
	struct capwap_80211_txpowerlevel_element* txpowerlevel;

	if (json_object_get_type(jsonparent) != json_type_array) {
		return NULL;
	}

	length = json_object_array_length(jsonparent);
	if (length > CAPWAP_TXPOWERLEVEL_MAXLENGTH) {
		return NULL;
	}

	txpowerlevel = (struct capwap_80211_txpowerlevel_element*)capwap_alloc(sizeof(struct capwap_80211_txpowerlevel_element));
	memset(txpowerlevel, 0, sizeof(struct capwap_80211_txpowerlevel_element));
	txpowerlevel->radioid = radioid;

	for (i = 0; i < length; i++) {
		struct json_object* jsonvalue = json_object_array_get_idx(jsonparent, i);
		if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_int)) {
			txpowerlevel->numlevels++;
			txpowerlevel->powerlevel[i] = (uint16_t)json_object_get_int(jsonvalue);
		}
	}

	return txpowerlevel;
}

/* */
static int ac_json_80211_txpowerlevel_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_txpowerlevel_element* txpowerlevel = (struct capwap_80211_txpowerlevel_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[txpowerlevel->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_TXPOWERLEVEL);

	if (item->txpowerlevel) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->txpowerlevel);
	}

	item->valid = 1;
	item->txpowerlevel = (struct capwap_80211_txpowerlevel_element*)ops->clone(txpowerlevel);

	return 1;
}

/* */
static void ac_json_80211_txpowerlevel_createjson(struct json_object* jsonparent, void* data) {
	int i;
	struct json_object* jsontxpower;
	struct capwap_80211_txpowerlevel_element* txpowerlevel = (struct capwap_80211_txpowerlevel_element*)data;

	jsontxpower = json_object_new_array();
	for (i = 0; i < txpowerlevel->numlevels; i++) {
		json_object_array_add(jsontxpower, json_object_new_int((int)txpowerlevel->powerlevel[i]));
	}

	json_object_object_add(jsonparent, "IEEE80211TXPowerLevel", jsontxpower);
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_txpowerlevel_ops = {
	.type = CAPWAP_ELEMENT_80211_TXPOWERLEVEL,
	.json_type = "IEEE80211TXPowerLevel",
	.create = ac_json_80211_txpowerlevel_createmessageelement,
	.add_message_element = ac_json_80211_txpowerlevel_addmessageelement,
	.create_json = ac_json_80211_txpowerlevel_createjson
};
