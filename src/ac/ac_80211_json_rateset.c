#include "ac.h"
#include "ac_json.h"

/*
IEEE80211Rateset: [
	[int]
]
*/

/* */
static void* ac_json_80211_rateset_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	int i;
	int length;
	struct capwap_80211_rateset_element* rateset;

	if (json_object_get_type(jsonparent) != json_type_array) {
		return NULL;
	}

	length = json_object_array_length(jsonparent);
	if ((length < CAPWAP_RATESET_MINLENGTH) || (length > CAPWAP_RATESET_MAXLENGTH)) {
		return NULL;
	}

	rateset = (struct capwap_80211_rateset_element*)capwap_alloc(sizeof(struct capwap_80211_rateset_element));
	memset(rateset, 0, sizeof(struct capwap_80211_rateset_element));
	rateset->radioid = radioid;

	for (i = 0; i < length; i++) {
		struct json_object* jsonvalue = json_object_array_get_idx(jsonparent, i);
		if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_int)) {
			rateset->ratesetcount++;
			rateset->rateset[i] = (uint8_t)json_object_get_int(jsonvalue);
		}
	}

	return rateset;
}

/* */
static int ac_json_80211_rateset_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_rateset_element* rateset = (struct capwap_80211_rateset_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[rateset->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_RATESET);

	if (item->rateset) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->rateset);
	}

	item->valid = 1;
	item->rateset = (struct capwap_80211_rateset_element*)ops->clone(rateset);

	return 1;
}

/* */
static void ac_json_80211_rateset_createjson(struct json_object* jsonparent, void* data) {
	int i;
	struct json_object* jsonrates;
	struct capwap_80211_rateset_element* rateset = (struct capwap_80211_rateset_element*)data;

	jsonrates = json_object_new_array();
	for (i = 0; i < rateset->ratesetcount; i++) {
		json_object_array_add(jsonrates, json_object_new_int((int)rateset->rateset[i]));
	}

	json_object_object_add(jsonparent, "IEEE80211Rateset", jsonrates);
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_rateset_ops = {
	.type = CAPWAP_ELEMENT_80211_RATESET,
	.json_type = "IEEE80211Rateset",
	.create = ac_json_80211_rateset_createmessageelement,
	.add_message_element = ac_json_80211_rateset_addmessageelement,
	.create_json = ac_json_80211_rateset_createjson
};
