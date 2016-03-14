#include "ac.h"
#include "ac_json.h"

/*
IEEE80211WTPRadioInformation: {
	Mode: [int]
}
*/

/* */
static void* ac_json_80211_wtpradioinformation_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	struct json_object* jsonitem;
	struct capwap_80211_wtpradioinformation_element* wtpradioinformation;

	wtpradioinformation = (struct capwap_80211_wtpradioinformation_element*)capwap_alloc(sizeof(struct capwap_80211_wtpradioinformation_element));
	memset(wtpradioinformation, 0, sizeof(struct capwap_80211_wtpradioinformation_element));
	wtpradioinformation->radioid = radioid;

	/* */
	jsonitem = compat_json_object_object_get(jsonparent, "Mode");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		wtpradioinformation->radiotype = (uint32_t)json_object_get_int(jsonitem) & CAPWAP_RADIO_TYPE_MASK;
	} else {
		capwap_free(wtpradioinformation);
		return NULL;
	}

	return wtpradioinformation;
}

/* */
static int ac_json_80211_wtpradioinformation_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_wtpradioinformation_element* wtpradioinformation = (struct capwap_80211_wtpradioinformation_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[wtpradioinformation->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION);

	if (item->wtpradioinformation) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->wtpradioinformation);
	}

	item->valid = 1;
	item->wtpradioinformation = (struct capwap_80211_wtpradioinformation_element*)ops->clone(wtpradioinformation);

	return 1;
}

/* */
static void ac_json_80211_wtpradioinformation_createjson(struct json_object* jsonparent, void* data) {
	struct json_object* jsonitem;
	struct capwap_80211_wtpradioinformation_element* wtpradioinformation = (struct capwap_80211_wtpradioinformation_element*)data;

	jsonitem = json_object_new_object();
	json_object_object_add(jsonitem, "Mode", json_object_new_int((int)wtpradioinformation->radiotype));
	json_object_object_add(jsonparent, "IEEE80211WTPRadioInformation", jsonitem);
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_wtpradioinformation_ops = {
	.type = CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION,
	.json_type = "IEEE80211WTPRadioInformation",
	.create = ac_json_80211_wtpradioinformation_createmessageelement,
	.add_message_element = ac_json_80211_wtpradioinformation_addmessageelement,
	.create_json = ac_json_80211_wtpradioinformation_createjson
};
