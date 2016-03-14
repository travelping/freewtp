#include "ac.h"
#include "ac_json.h"

/*
IEEE80211SupportedRates: [
	[int]
]
*/

/* */
static void* ac_json_80211_supportedrates_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	int i;
	int length;
	struct capwap_80211_supportedrates_element* supportedrates;

	if (json_object_get_type(jsonparent) != json_type_array) {
		return NULL;
	}

	length = json_object_array_length(jsonparent);
	if ((length < CAPWAP_SUPPORTEDRATES_MINLENGTH) || (length > CAPWAP_SUPPORTEDRATES_MAXLENGTH)) {
		return NULL;
	}

	supportedrates = (struct capwap_80211_supportedrates_element*)capwap_alloc(sizeof(struct capwap_80211_supportedrates_element));
	memset(supportedrates, 0, sizeof(struct capwap_80211_supportedrates_element));
	supportedrates->radioid = radioid;

	for (i = 0; i < length; i++) {
		struct json_object* jsonvalue = json_object_array_get_idx(jsonparent, i);
		if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_int)) {
			supportedrates->supportedratescount++;
			supportedrates->supportedrates[i] = (uint8_t)json_object_get_int(jsonvalue);
		}
	}

	return supportedrates;
}

/* */
static int ac_json_80211_supportedrates_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_supportedrates_element* supportedrates = (struct capwap_80211_supportedrates_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[supportedrates->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_SUPPORTEDRATES);

	if (item->supportedrates) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->supportedrates);
	}

	item->valid = 1;
	item->supportedrates = (struct capwap_80211_supportedrates_element*)ops->clone(supportedrates);

	return 1;
}

/* */
static void ac_json_80211_supportedrates_createjson(struct json_object* jsonparent, void* data) {
	int i;
	struct json_object* jsonrates;
	struct capwap_80211_supportedrates_element* supportedrates = (struct capwap_80211_supportedrates_element*)data;

	jsonrates = json_object_new_array();
	for (i = 0; i < supportedrates->supportedratescount; i++) {
		json_object_array_add(jsonrates, json_object_new_int((int)supportedrates->supportedrates[i]));
	}

	json_object_object_add(jsonparent, "IEEE80211SupportedRates", jsonrates);
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_supportedrates_ops = {
	.type = CAPWAP_ELEMENT_80211_SUPPORTEDRATES,
	.json_type = "IEEE80211SupportedRates",
	.create = ac_json_80211_supportedrates_createmessageelement,
	.add_message_element = ac_json_80211_supportedrates_addmessageelement,
	.create_json = ac_json_80211_supportedrates_createjson
};
