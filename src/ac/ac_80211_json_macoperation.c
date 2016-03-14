#include "ac.h"
#include "ac_json.h"

/*
IEEE80211MACOperation: {
	RTSThreshold: [int],
	ShortRetry: [int],
	LongRetry: [int],
	FragmentationThreshold: [int],
	TxMSDULifetime: [int],
	RxMSDULifetime: [int]
}
*/

/* */
static void* ac_json_80211_macoperation_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	struct json_object* jsonitem;
	struct capwap_80211_macoperation_element* macoperation;

	macoperation = (struct capwap_80211_macoperation_element*)capwap_alloc(sizeof(struct capwap_80211_macoperation_element));
	memset(macoperation, 0, sizeof(struct capwap_80211_macoperation_element));
	macoperation->radioid = radioid;

	/* */
	jsonitem = compat_json_object_object_get(jsonparent, "RTSThreshold");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		macoperation->rtsthreshold = (uint16_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(macoperation);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "ShortRetry");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		macoperation->shortretry = (uint8_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(macoperation);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "LongRetry");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		macoperation->longretry = (uint8_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(macoperation);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "FragmentationThreshold");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		macoperation->fragthreshold = (uint16_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(macoperation);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "TxMSDULifetime");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		macoperation->txmsdulifetime = (uint32_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(macoperation);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "RxMSDULifetime");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		macoperation->rxmsdulifetime = (uint32_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(macoperation);
		return NULL;
	}

	return macoperation;
}

/* */
static int ac_json_80211_macoperation_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_macoperation_element* macoperation = (struct capwap_80211_macoperation_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[macoperation->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_MACOPERATION);

	if (item->macoperation) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->macoperation);
	}

	item->valid = 1;
	item->macoperation = (struct capwap_80211_macoperation_element*)ops->clone(macoperation);

	return 1;
}

/* */
static void ac_json_80211_macoperation_createjson(struct json_object* jsonparent, void* data) {
	struct json_object* jsonitem;
	struct capwap_80211_macoperation_element* macoperation = (struct capwap_80211_macoperation_element*)data;

	jsonitem = json_object_new_object();
	json_object_object_add(jsonitem, "RTSThreshold", json_object_new_int((int)macoperation->rtsthreshold));
	json_object_object_add(jsonitem, "ShortRetry", json_object_new_int((int)macoperation->shortretry));
	json_object_object_add(jsonitem, "LongRetry", json_object_new_int((int)macoperation->longretry));
	json_object_object_add(jsonitem, "FragmentationThreshold", json_object_new_int((int)macoperation->fragthreshold));
	json_object_object_add(jsonitem, "TxMSDULifetime", json_object_new_int((int)macoperation->txmsdulifetime));
	json_object_object_add(jsonitem, "RxMSDULifetime", json_object_new_int((int)macoperation->rxmsdulifetime));
	json_object_object_add(jsonparent, "IEEE80211MACOperation", jsonitem);
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_macoperation_ops = {
	.type = CAPWAP_ELEMENT_80211_MACOPERATION,
	.json_type = "IEEE80211MACOperation",
	.create = ac_json_80211_macoperation_createmessageelement,
	.add_message_element = ac_json_80211_macoperation_addmessageelement,
	.create_json = ac_json_80211_macoperation_createjson
};
