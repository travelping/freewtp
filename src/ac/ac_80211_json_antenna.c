#include "ac.h"
#include "ac_json.h"

/*
IEEE80211Antenna: {
	Diversity: [bool],
	Combiner: [int],
	AntennaSelection: [
		[int]
	]
}
*/

/* */
static void* ac_json_80211_antenna_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	struct json_object* jsonitem;
	struct capwap_80211_antenna_element* antenna;

	antenna = (struct capwap_80211_antenna_element*)capwap_alloc(sizeof(struct capwap_80211_antenna_element));
	memset(antenna, 0, sizeof(struct capwap_80211_antenna_element));
	antenna->radioid = radioid;

	/* */
	jsonitem = compat_json_object_object_get(jsonparent, "Diversity");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_boolean)) {
		antenna->diversity = (json_object_get_boolean(jsonitem) ? CAPWAP_ANTENNA_DIVERSITY_ENABLE : CAPWAP_ANTENNA_DIVERSITY_DISABLE);
	} else {
		capwap_free(antenna);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "Combiner");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		antenna->combiner = (uint8_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(antenna);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "AntennaSelection");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_array)) {
		int i;
		int length;

		antenna->selections = capwap_array_create(sizeof(uint8_t), 0, 1);

		length = json_object_array_length(jsonitem);
		for (i = 0; i < length; i++) {
			struct json_object* jsonvalue = json_object_array_get_idx(jsonitem, i);
			if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_int)) {
				uint8_t* value = (uint8_t*)capwap_array_get_item_pointer(antenna->selections, antenna->selections->count);
				*value = (uint8_t)json_object_get_int(jsonvalue);
			}
		}
	} else {
		capwap_free(antenna);
		return NULL;
	}

	return antenna;
}

/* */
static int ac_json_80211_antenna_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_antenna_element* antenna = (struct capwap_80211_antenna_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[antenna->radioid - 1];
	const struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_ANTENNA);

	if (item->antenna) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->antenna);
	}

	item->valid = 1;
	item->antenna = (struct capwap_80211_antenna_element*)ops->clone(antenna);

	return 1;
}

/* */
static void ac_json_80211_antenna_createjson(struct json_object* jsonparent, void* data) {
	int i;
	struct json_object* jsonantenna;
	struct json_object* jsonitem;
	struct capwap_80211_antenna_element* antenna = (struct capwap_80211_antenna_element*)data;

	jsonantenna = json_object_new_array();
	for (i = 0; i < antenna->selections->count; i++) {
		json_object_array_add(jsonantenna, json_object_new_int((int)*(uint8_t*)capwap_array_get_item_pointer(antenna->selections, i)));
	}

	jsonitem = json_object_new_object();
	json_object_object_add(jsonitem, "Diversity", json_object_new_boolean((antenna->diversity == CAPWAP_ANTENNA_DIVERSITY_ENABLE) ? 1 : 0));
	json_object_object_add(jsonitem, "Combiner", json_object_new_int((int)antenna->combiner));
	json_object_object_add(jsonitem, "AntennaSelection", jsonantenna);
	json_object_object_add(jsonparent, "IEEE80211Antenna", jsonitem);
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_antenna_ops = {
	.type = CAPWAP_ELEMENT_80211_ANTENNA,
	.json_type = "IEEE80211Antenna",
	.create = ac_json_80211_antenna_createmessageelement,
	.add_message_element = ac_json_80211_antenna_addmessageelement,
	.create_json = ac_json_80211_antenna_createjson
};
