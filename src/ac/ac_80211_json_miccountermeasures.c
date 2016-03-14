#include "ac.h"
#include "ac_json.h"

/* */
static void* ac_json_80211_miccountermeasures_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	return NULL;	/* TODO */
}

/* */
static int ac_json_80211_miccountermeasures_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_miccountermeasures_element* miccountermeasures = (struct capwap_80211_miccountermeasures_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[miccountermeasures->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES);

	if (item->miccountermeasures) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->miccountermeasures);
	}

	item->valid = 1;
	item->miccountermeasures = (struct capwap_80211_miccountermeasures_element*)ops->clone(miccountermeasures);

	return 1;
}

/* */
static void ac_json_80211_miccountermeasures_createjson(struct json_object* jsonparent, void* data) {
	/* TODO */
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_miccountermeasures_ops = {
	.type = CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES,
	.json_type = "IEEE80211MicCounterMeasures",
	.create = ac_json_80211_miccountermeasures_createmessageelement,
	.add_message_element = ac_json_80211_miccountermeasures_addmessageelement,
	.create_json = ac_json_80211_miccountermeasures_createjson
};
