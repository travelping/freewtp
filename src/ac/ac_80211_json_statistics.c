#include "ac.h"
#include "ac_json.h"

/* */
static void* ac_json_80211_statistics_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	return NULL;	/* TODO */
}

/* */
static int ac_json_80211_statistics_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_statistics_element* statistics = (struct capwap_80211_statistics_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[statistics->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_STATISTICS);

	if (item->statistics) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->statistics);
	}

	item->valid = 1;
	item->statistics = (struct capwap_80211_statistics_element*)ops->clone(statistics);

	return 1;
}

/* */
static void ac_json_80211_statistics_createjson(struct json_object* jsonparent, void* data) {
	/* TODO */
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_statistics_ops = {
	.type = CAPWAP_ELEMENT_80211_STATISTICS,
	.json_type = "IEEE80211Statistics",
	.create = ac_json_80211_statistics_createmessageelement,
	.add_message_element = ac_json_80211_statistics_addmessageelement,
	.create_json = ac_json_80211_statistics_createjson
};
