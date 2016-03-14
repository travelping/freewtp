#include "ac.h"
#include "ac_json.h"

/*
IEEE80211MultiDomainCapability: {
	FirstChannel: [int],
	NumberChannels: [int],
	MaxTxPowerLevel: [int]
}
*/

/* */
static void* ac_json_80211_multidomaincapability_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	struct json_object* jsonitem;
	struct capwap_80211_multidomaincapability_element* multidomaincapability;

	multidomaincapability = (struct capwap_80211_multidomaincapability_element*)capwap_alloc(sizeof(struct capwap_80211_multidomaincapability_element));
	memset(multidomaincapability, 0, sizeof(struct capwap_80211_multidomaincapability_element));
	multidomaincapability->radioid = radioid;

	/* */
	jsonitem = compat_json_object_object_get(jsonparent, "FirstChannel");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		multidomaincapability->firstchannel = (uint16_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(multidomaincapability);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "NumberChannels");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		multidomaincapability->numberchannels = (uint16_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(multidomaincapability);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "MaxTxPowerLevel");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		multidomaincapability->maxtxpowerlevel = (uint16_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(multidomaincapability);
		return NULL;
	}

	return multidomaincapability;
}

/* */
static int ac_json_80211_multidomaincapability_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_multidomaincapability_element* multidomaincapability = (struct capwap_80211_multidomaincapability_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[multidomaincapability->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY);

	if (item->multidomaincapability) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->multidomaincapability);
	}

	item->valid = 1;
	item->multidomaincapability = (struct capwap_80211_multidomaincapability_element*)ops->clone(multidomaincapability);

	return 1;
}

/* */
static void ac_json_80211_multidomaincapability_createjson(struct json_object* jsonparent, void* data) {
	struct json_object* jsonitem;
	struct capwap_80211_multidomaincapability_element* multidomaincapability = (struct capwap_80211_multidomaincapability_element*)data;

	jsonitem = json_object_new_object();
	json_object_object_add(jsonitem, "FirstChannel", json_object_new_int((int)multidomaincapability->firstchannel));
	json_object_object_add(jsonitem, "NumberChannels", json_object_new_int((int)multidomaincapability->numberchannels));
	json_object_object_add(jsonitem, "MaxTxPowerLevel", json_object_new_int((int)multidomaincapability->maxtxpowerlevel));
	json_object_object_add(jsonparent, "IEEE80211MultiDomainCapability", jsonitem);
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_multidomaincapability_ops = {
	.type = CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY,
	.json_type = "IEEE80211MultiDomainCapability",
	.create = ac_json_80211_multidomaincapability_createmessageelement,
	.add_message_element = ac_json_80211_multidomaincapability_addmessageelement,
	.create_json = ac_json_80211_multidomaincapability_createjson
};
