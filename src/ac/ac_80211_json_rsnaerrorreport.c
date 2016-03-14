#include "ac.h"
#include "ac_json.h"

/* */
static void* ac_json_80211_rsnaerrorreport_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	return NULL;	/* TODO */
}

/* */
static int ac_json_80211_rsnaerrorreport_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_rsnaerrorreport_element* rsnaerrorreport = (struct capwap_80211_rsnaerrorreport_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[rsnaerrorreport->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT);

	if (item->rsnaerrorreport) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->rsnaerrorreport);
	}

	item->valid = 1;
	item->rsnaerrorreport = (struct capwap_80211_rsnaerrorreport_element*)ops->clone(rsnaerrorreport);

	return 1;
}

/* */
static void ac_json_80211_rsnaerrorreport_createjson(struct json_object* jsonparent, void* data) {
	/* TODO */
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_rsnaerrorreport_ops = {
	.type = CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT,
	.json_type = "IEEE80211RSNAErrorReport",
	.create = ac_json_80211_rsnaerrorreport_createmessageelement,
	.add_message_element = ac_json_80211_rsnaerrorreport_addmessageelement,
	.create_json = ac_json_80211_rsnaerrorreport_createjson
};
