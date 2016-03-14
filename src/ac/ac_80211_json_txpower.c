#include "ac.h"
#include "ac_json.h"

/*
IEEE80211TxPower: {
	CurrentTxPower: [int]
}
*/

/* */
static void* ac_json_80211_txpower_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	struct json_object* jsonitem;
	struct capwap_80211_txpower_element* txpower;

	txpower = (struct capwap_80211_txpower_element*)capwap_alloc(sizeof(struct capwap_80211_txpower_element));
	memset(txpower, 0, sizeof(struct capwap_80211_txpower_element));
	txpower->radioid = radioid;

	/* */
	jsonitem = compat_json_object_object_get(jsonparent, "CurrentTxPower");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		txpower->currenttxpower = (uint16_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(txpower);
		return NULL;
	}

	return txpower;
}

/* */
static int ac_json_80211_txpower_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_txpower_element* txpower = (struct capwap_80211_txpower_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[txpower->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_TXPOWER);

	if (item->txpower) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->txpower);
	}

	item->valid = 1;
	item->txpower = (struct capwap_80211_txpower_element*)ops->clone(txpower);

	return 1;
}

/* */
static void ac_json_80211_txpower_createjson(struct json_object* jsonparent, void* data) {
	struct json_object* jsonitem;
	struct capwap_80211_txpower_element* txpower = (struct capwap_80211_txpower_element*)data;

	jsonitem = json_object_new_object();
	json_object_object_add(jsonitem, "CurrentTxPower", json_object_new_int((int)txpower->currenttxpower));
	json_object_object_add(jsonparent, "IEEE80211TxPower", jsonitem);
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_txpower_ops = {
	.type = CAPWAP_ELEMENT_80211_TXPOWER,
	.json_type = "IEEE80211TxPower",
	.create = ac_json_80211_txpower_createmessageelement,
	.add_message_element = ac_json_80211_txpower_addmessageelement,
	.create_json = ac_json_80211_txpower_createjson
};
