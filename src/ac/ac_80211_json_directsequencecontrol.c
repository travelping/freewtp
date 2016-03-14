#include "ac.h"
#include "ac_json.h"

/*
IEEE80211DirectSequenceControl: {
	CurrentChan: [int],
	CurrentCCA: [int],
	EnergyDetectThreshold: [int]
}
*/

/* */
static void* ac_json_80211_directsequencecontrol_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	struct json_object* jsonitem;
	struct capwap_80211_directsequencecontrol_element* directsequencecontrol;

	directsequencecontrol = (struct capwap_80211_directsequencecontrol_element*)capwap_alloc(sizeof(struct capwap_80211_directsequencecontrol_element));
	memset(directsequencecontrol, 0, sizeof(struct capwap_80211_directsequencecontrol_element));
	directsequencecontrol->radioid = radioid;

	/* */
	jsonitem = compat_json_object_object_get(jsonparent, "CurrentChan");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		directsequencecontrol->currentchannel = (uint8_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(directsequencecontrol);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "CurrentCCA");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		directsequencecontrol->currentcca = (uint8_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(directsequencecontrol);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "EnergyDetectThreshold");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		directsequencecontrol->enerydetectthreshold = (uint32_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(directsequencecontrol);
		return NULL;
	}

	return directsequencecontrol;
}

/* */
static int ac_json_80211_directsequencecontrol_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_directsequencecontrol_element* directsequencecontrol = (struct capwap_80211_directsequencecontrol_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[directsequencecontrol->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL);

	if (item->directsequencecontrol) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->directsequencecontrol);
	}

	item->valid = 1;
	item->directsequencecontrol = (struct capwap_80211_directsequencecontrol_element*)ops->clone(directsequencecontrol);

	return 1;
}

/* */
static void ac_json_80211_directsequencecontrol_createjson(struct json_object* jsonparent, void* data) {
	struct json_object* jsonitem;
	struct capwap_80211_directsequencecontrol_element* directsequencecontrol = (struct capwap_80211_directsequencecontrol_element*)data;

	jsonitem = json_object_new_object();
	json_object_object_add(jsonitem, "CurrentChan", json_object_new_int((int)directsequencecontrol->currentchannel));
	json_object_object_add(jsonitem, "CurrentCCA", json_object_new_int((int)directsequencecontrol->currentcca));
	json_object_object_add(jsonitem, "EnergyDetectThreshold", json_object_new_int((int)directsequencecontrol->enerydetectthreshold));
	json_object_object_add(jsonparent, "IEEE80211DirectSequenceControl", jsonitem);
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_directsequencecontrol_ops = {
	.type = CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL,
	.json_type = "IEEE80211DirectSequenceControl",
	.create = ac_json_80211_directsequencecontrol_createmessageelement,
	.add_message_element = ac_json_80211_directsequencecontrol_addmessageelement,
	.create_json = ac_json_80211_directsequencecontrol_createjson
};
