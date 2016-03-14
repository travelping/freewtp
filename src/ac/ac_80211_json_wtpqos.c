#include "ac.h"
#include "ac_json.h"

/*
IEEE80211WTPQoS: {
	TaggingPolicy: [int],
	Voice: {
		QueueDepth: [int],
		CWMin: [int],
		CWMax: [int],
		AIFS: [int],
		Priority8021p: [int],
		DSCP: [int]
	}
	Video: {
		QueueDepth: [int],
		CWMin: [int],
		CWMax: [int],
		AIFS: [int],
		Priority8021p: [int],
		DSCP: [int]
	}
	BestEffort: {
		QueueDepth: [int],
		CWMin: [int],
		CWMax: [int],
		AIFS: [int],
		Priority8021p: [int],
		DSCP: [int]
	}
	Background: {
		QueueDepth: [int],
		CWMin: [int],
		CWMax: [int],
		AIFS: [int],
		Priority8021p: [int],
		DSCP: [int]
	}
}
*/

/* */
static void* ac_json_80211_wtpqos_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	return NULL;	/* TODO */
}

/* */
static int ac_json_80211_wtpqos_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_wtpqos_element* wtpqos = (struct capwap_80211_wtpqos_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[wtpqos->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTP_QOS);

	if (item->wtpqos) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->wtpqos);
	}

	item->valid = 1;
	item->wtpqos = (struct capwap_80211_wtpqos_element*)ops->clone(wtpqos);

	return 1;
}

/* */
static void ac_json_80211_wtpqos_createjson(struct json_object* jsonparent, void* data) {
	/* TODO */
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_wtpqos_ops = {
	.type = CAPWAP_ELEMENT_80211_WTP_QOS,
	.json_type = "IEEE80211WTPQoS",
	.create = ac_json_80211_wtpqos_createmessageelement,
	.add_message_element = ac_json_80211_wtpqos_addmessageelement,
	.create_json = ac_json_80211_wtpqos_createjson
};
