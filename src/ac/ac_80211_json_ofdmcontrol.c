#include "ac.h"
#include "ac_json.h"

/*
IEEE80211OFDMControl: {
	CurrentChan: [int],
	BandSupport: [int],
	TIThreshold: [int]
}
*/

/* */
static void* ac_json_80211_ofdmcontrol_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	struct json_object* jsonitem;
	struct capwap_80211_ofdmcontrol_element* ofdmcontrol;

	ofdmcontrol = (struct capwap_80211_ofdmcontrol_element*)capwap_alloc(sizeof(struct capwap_80211_ofdmcontrol_element));
	memset(ofdmcontrol, 0, sizeof(struct capwap_80211_ofdmcontrol_element));
	ofdmcontrol->radioid = radioid;

	/* */
	jsonitem = compat_json_object_object_get(jsonparent, "CurrentChan");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		ofdmcontrol->currentchannel = (uint8_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(ofdmcontrol);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "BandSupport");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		ofdmcontrol->bandsupport = (uint8_t)json_object_get_int(jsonitem) & CAPWAP_OFDMCONTROL_BAND_MASK;
	} else {
		capwap_free(ofdmcontrol);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "TIThreshold");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		ofdmcontrol->tithreshold = (uint32_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(ofdmcontrol);
		return NULL;
	}

	return ofdmcontrol;
}

/* */
static int ac_json_80211_ofdmcontrol_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_ofdmcontrol_element* ofdmcontrol = (struct capwap_80211_ofdmcontrol_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[ofdmcontrol->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_OFDMCONTROL);

	if (item->ofdmcontrol) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->ofdmcontrol);
	}

	item->valid = 1;
	item->ofdmcontrol = (struct capwap_80211_ofdmcontrol_element*)ops->clone(ofdmcontrol);

	return 1;
}

/* */
static void ac_json_80211_ofdmcontrol_createjson(struct json_object* jsonparent, void* data) {
	struct json_object* jsonitem;
	struct capwap_80211_ofdmcontrol_element* ofdmcontrol = (struct capwap_80211_ofdmcontrol_element*)data;

	jsonitem = json_object_new_object();
	json_object_object_add(jsonitem, "CurrentChan", json_object_new_int((int)ofdmcontrol->currentchannel));
	json_object_object_add(jsonitem, "BandSupport", json_object_new_int((int)ofdmcontrol->bandsupport));
	json_object_object_add(jsonitem, "TIThreshold", json_object_new_int((int)ofdmcontrol->tithreshold));
	json_object_object_add(jsonparent, "IEEE80211OFDMControl", jsonitem);
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_ofdmcontrol_ops = {
	.type = CAPWAP_ELEMENT_80211_OFDMCONTROL,
	.json_type = "IEEE80211OFDMControl",
	.create = ac_json_80211_ofdmcontrol_createmessageelement,
	.add_message_element = ac_json_80211_ofdmcontrol_addmessageelement,
	.create_json = ac_json_80211_ofdmcontrol_createjson
};
