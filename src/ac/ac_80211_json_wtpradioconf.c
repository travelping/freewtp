#include "ac.h"
#include "ac_json.h"

/*
IEEE80211WTPRadioConfiguration: {
	ShortPreamble: [int],
	NumBSSIDs: [int],
	DTIMPeriod: [int],
	BSSID: [string],
	BeaconPeriod: [int],
	CountryString: [string]
}
*/

/* */
static void* ac_json_80211_wtpradioconf_createmessageelement(struct json_object* jsonparent, uint16_t radioid) {
	struct json_object* jsonitem;
	struct capwap_80211_wtpradioconf_element* wtpradioconf;

	wtpradioconf = (struct capwap_80211_wtpradioconf_element*)capwap_alloc(sizeof(struct capwap_80211_wtpradioconf_element));
	memset(wtpradioconf, 0, sizeof(struct capwap_80211_wtpradioconf_element));
	wtpradioconf->radioid = radioid;

	/* */
	jsonitem = compat_json_object_object_get(jsonparent, "ShortPreamble");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		wtpradioconf->shortpreamble = (uint8_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(wtpradioconf);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "NumBSSIDs");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		wtpradioconf->maxbssid = (uint8_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(wtpradioconf);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "DTIMPeriod");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		wtpradioconf->dtimperiod = (uint8_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(wtpradioconf);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "BSSID");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_string)) {
		if (!capwap_scanf_macaddress((unsigned char*)wtpradioconf->bssid, json_object_get_string(jsonitem), MACADDRESS_EUI48_LENGTH)) {
			capwap_free(wtpradioconf);
			return NULL;
		}
	} else {
		capwap_free(wtpradioconf);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "BeaconPeriod");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
		wtpradioconf->beaconperiod = (uint16_t)json_object_get_int(jsonitem);
	} else {
		capwap_free(wtpradioconf);
		return NULL;
	}

	jsonitem = compat_json_object_object_get(jsonparent, "CountryString");
	if (jsonitem && (json_object_get_type(jsonitem) == json_type_string)) {
		const char* country = json_object_get_string(jsonitem);
		if (strlen(country) == (CAPWAP_WTP_RADIO_CONF_COUNTRY_LENGTH - 1)) {
			strcpy((char*)wtpradioconf->country, country);
		} else {
			capwap_free(wtpradioconf);
			return NULL;
		}
	} else {
		capwap_free(wtpradioconf);
		return NULL;
	}

	return wtpradioconf;
}

/* */
static int ac_json_80211_wtpradioconf_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, void* data, int overwrite) {
	struct capwap_80211_wtpradioconf_element* wtpradioconf = (struct capwap_80211_wtpradioconf_element*)data;
	struct ac_json_ieee80211_item* item = &wtpradio->items[wtpradioconf->radioid - 1];
	const struct capwap_message_elements_ops *ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTP_RADIO_CONF);

	if (item->wtpradioconf) {
		if (!overwrite) {
			return 0;
		}

		ops->free(item->wtpradioconf);
	}

	item->valid = 1;
	item->wtpradioconf = (struct capwap_80211_wtpradioconf_element*)ops->clone(wtpradioconf);

	return 1;
}

/* */
static void ac_json_80211_wtpradioconf_createjson(struct json_object* jsonparent, void* data) {
	char buffer[CAPWAP_MACADDRESS_EUI48_BUFFER];
	struct json_object* jsonitem;
	struct capwap_80211_wtpradioconf_element* wtpradioconf = (struct capwap_80211_wtpradioconf_element*)data;

	jsonitem = json_object_new_object();
	json_object_object_add(jsonitem, "ShortPreamble", json_object_new_int((int)wtpradioconf->shortpreamble));
	json_object_object_add(jsonitem, "NumBSSIDs", json_object_new_int((int)wtpradioconf->maxbssid));
	json_object_object_add(jsonitem, "DTIMPeriod", json_object_new_int((int)wtpradioconf->dtimperiod));
	json_object_object_add(jsonitem, "BSSID", json_object_new_string(capwap_printf_macaddress(buffer, wtpradioconf->bssid, MACADDRESS_EUI48_LENGTH)));
	json_object_object_add(jsonitem, "BeaconPeriod", json_object_new_int((int)wtpradioconf->beaconperiod));
	json_object_object_add(jsonitem, "CountryString", json_object_new_string((char*)wtpradioconf->country));
	json_object_object_add(jsonparent, "IEEE80211WTPRadioConfiguration", jsonitem);
}

/* */
struct ac_json_ieee80211_ops ac_json_80211_wtpradioconf_ops = {
	.type = CAPWAP_ELEMENT_80211_WTP_RADIO_CONF,
	.json_type = "IEEE80211WTPRadioConfiguration",
	.create = ac_json_80211_wtpradioconf_createmessageelement,
	.add_message_element = ac_json_80211_wtpradioconf_addmessageelement,
	.create_json = ac_json_80211_wtpradioconf_createjson
};
