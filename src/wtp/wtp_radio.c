#include "wtp.h"
#include "capwap_hash.h"
#include "capwap_list.h"
#include "wtp_radio.h"
#include "wtp_dfa.h"
#include "wtp_kmod.h"

/* */
#define WTP_UPDATE_FREQUENCY_DSSS				1
#define WTP_UPDATE_FREQUENCY_OFDM				2
#define WTP_UPDATE_RATES					3
#define WTP_UPDATE_CONFIGURATION				4
#define WTP_UPDATE_TX_QUEUE					5

struct wtp_update_configuration_item {
	int type;
	struct wtp_radio* radio;
};

/* */
static int wtp_radio_configure_phy(struct wtp_radio* radio) {
	/* Default rate set is all supported rate */
	if (radio->radioid != radio->rateset.radioid) {
		if (radio->radioid != radio->supportedrates.radioid) {
			capwap_logging_debug("Config Phy: Supported rate not set");
			return -1;			/* Supported rate not set */
		}

		/* */
		radio->rateset.radioid = radio->radioid;
		radio->rateset.ratesetcount = radio->supportedrates.supportedratescount;
		memcpy(radio->rateset.rateset, radio->supportedrates.supportedrates, CAPWAP_RATESET_MAXLENGTH);

		/* Update rates */
		if (wifi_device_updaterates(radio->devicehandle, radio->rateset.rateset, radio->rateset.ratesetcount)) {
			capwap_logging_debug("Config Phy: update rates failed");
			return -1;
		}
	}

	/* Check channel radio */
	if (radio->radioid != radio->radioinformation.radioid) {
		capwap_logging_debug("Config Phy: RI id mismatch");
		return -1;
	} else if (radio->radioid != radio->radioconfig.radioid) {
		capwap_logging_debug("Config Phy: RC id mismatch");
		return -1;
	} else if ((!radio->directsequencecontrol.radioid && !radio->ofdmcontrol.radioid) || ((radio->directsequencecontrol.radioid == radio->radioid) && (radio->ofdmcontrol.radioid == radio->radioid))) {
		capwap_logging_debug("Config Phy: DSSS / OFDM mismatch");
		return -1;		/* Only one from DSSS and OFDM can select */
	} else if ((radio->radioid == radio->directsequencecontrol.radioid) && !(radio->radioinformation.radiotype & (CAPWAP_RADIO_TYPE_80211B | CAPWAP_RADIO_TYPE_80211G))) {
		capwap_logging_debug("Config Phy: DSSS B/G mismatch");
		return -1;
	} else if ((radio->radioid == radio->ofdmcontrol.radioid) && !(radio->radioinformation.radiotype & CAPWAP_RADIO_TYPE_80211A)) {
		capwap_logging_debug("Config Phy: OFDM A mismatch");
		return -1;
	}

	return 0;
}

/* */
static unsigned long wtp_radio_acl_item_gethash(const void* key, unsigned long hashsize) {
	uint8_t* macaddress = (uint8_t*)key;

	return (((unsigned long)macaddress[3] ^ (unsigned long)macaddress[4] ^ (unsigned long)macaddress[5]) >> 2);
}

/* */
static const void* wtp_radio_acl_item_getkey(const void* data) {
	return NULL;	// TODO
}

/* */
static int wtp_radio_acl_item_cmp(const void* key1, const void* key2) {
	return memcmp(key1, key2, MACADDRESS_EUI48_LENGTH);
}


/* */
void wtp_radio_init(void) {
	g_wtp.radios = capwap_array_create(sizeof(struct wtp_radio), 0, 1);

	g_wtp.defaultaclstations = WTP_RADIO_ACL_STATION_ALLOW;
	g_wtp.aclstations = capwap_hash_create(WTP_RADIO_ACL_HASH_SIZE);
	g_wtp.aclstations->item_gethash = wtp_radio_acl_item_gethash;
	g_wtp.aclstations->item_getkey = wtp_radio_acl_item_getkey;
	g_wtp.aclstations->item_cmp = wtp_radio_acl_item_cmp;
}

/* */
void wtp_radio_close(void) {
	int i;
	struct capwap_list_item* itemwlan;

	ASSERT(g_wtp.radios != NULL);

	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio* radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);

		if (radio->antenna.selections) {
			capwap_array_free(radio->antenna.selections);
		}

		if (radio->wlan) {
			for (itemwlan = radio->wlan->first; itemwlan != NULL; itemwlan = itemwlan->next) {
				struct wtp_radio_wlan* wlan = (struct wtp_radio_wlan*)itemwlan->item;

				/* Destroy BSS interface */
				if (wlan->wlanhandle) {
					wifi_wlan_destroy(wlan->wlanhandle);
				}
			}

			capwap_list_free(radio->wlan);
		}

		if (radio->wlanpool) {
			for (itemwlan = radio->wlanpool->first; itemwlan != NULL; itemwlan = itemwlan->next) {
				struct wtp_radio_wlanpool* wlanpool = (struct wtp_radio_wlanpool*)itemwlan->item;

				/* Destroy BSS interface */
				if (wlanpool->wlanhandle) {
					wifi_wlan_destroy(wlanpool->wlanhandle);
				}
			}

			capwap_list_free(radio->wlanpool);
		}
	}

	capwap_array_resize(g_wtp.radios, 0);
}

/* */
void wtp_radio_free(void) {
	ASSERT(g_wtp.radios != NULL);

	if (g_wtp.radios->count > 0) {
		wtp_radio_close();
	}

	capwap_array_free(g_wtp.radios);
	capwap_hash_free(g_wtp.aclstations);
}

static void push_wtp_update_configuration_item(struct capwap_array *updateitems,
					       int type, struct wtp_radio *radio)
{
	struct wtp_update_configuration_item* item;

	item = (struct wtp_update_configuration_item *)capwap_array_get_item_pointer(updateitems, updateitems->count);
	item->type = type;
	item->radio = radio;
}

/* */
static void wtp_radio_setconfiguration_80211(struct capwap_parsed_packet *packet,
					     struct capwap_array *updateitems)
{
	int i;
	struct wtp_radio* radio;
	struct capwap_list_item* search;

	/* Set radio configuration and invalidate the old values */
	for (search = packet->messages->first;
	     search != NULL;
	     search = search->next)
	{
		struct capwap_message_element_itemlist *messageelement = (struct capwap_message_element_itemlist *)search->item;
		struct capwap_array *messageelements = (struct capwap_array *)messageelement->data;

		/* Parsing only IEEE 802.11 message element */
		if (!IS_80211_MESSAGE_ELEMENTS(messageelement->id))
			continue;

		ASSERT(messageelements != NULL);
		ASSERT(messageelements->count > 0);

		switch (messageelement->id.type) {
		case CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL_TYPE:
			for (i = 0; i < messageelements->count; i++) {
				struct capwap_80211_directsequencecontrol_element *directsequencecontrol =
					*(struct capwap_80211_directsequencecontrol_element**)capwap_array_get_item_pointer(messageelements, i);

				radio = wtp_radio_get_phy(directsequencecontrol->radioid);
				if (!radio)
					continue;

				memset(&radio->directsequencecontrol, 0, sizeof(struct capwap_80211_directsequencecontrol_element));
				memset(&radio->ofdmcontrol, 0, sizeof(struct capwap_80211_ofdmcontrol_element));
			}
			break;

		case CAPWAP_ELEMENT_80211_OFDMCONTROL_TYPE:
			for (i = 0; i < messageelements->count; i++) {
				struct capwap_80211_ofdmcontrol_element* ofdmcontrol =
					*(struct capwap_80211_ofdmcontrol_element**)capwap_array_get_item_pointer(messageelements, i);

				radio = wtp_radio_get_phy(ofdmcontrol->radioid);
				if (!radio)
					continue;

				memset(&radio->directsequencecontrol, 0, sizeof(struct capwap_80211_directsequencecontrol_element));
				memset(&radio->ofdmcontrol, 0, sizeof(struct capwap_80211_ofdmcontrol_element));
			}
			break;

		case CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION_TYPE:
			for (i = 0; i < messageelements->count; i++) {
				struct capwap_80211_wtpradioinformation_element* radioinformation =
					*(struct capwap_80211_wtpradioinformation_element**)capwap_array_get_item_pointer(messageelements, i);

				radio = wtp_radio_get_phy(radioinformation->radioid);
				if (!radio)
					continue;

				memcpy(&radio->radioinformation, radioinformation, sizeof(struct capwap_80211_wtpradioinformation_element));
			}
			break;
		}
	}

	/* Update new values */
	for (search = packet->messages->first;
	     search != NULL;
	     search = search->next)
	{
		struct capwap_message_element_itemlist* messageelement = (struct capwap_message_element_itemlist*)search->item;
		struct capwap_array *messageelements = (struct capwap_array *)messageelement->data;

		/* Parsing only IEEE 802.11 message element */
		if (!IS_80211_MESSAGE_ELEMENTS(messageelement->id))
			continue;

		ASSERT(messageelements != NULL);
		ASSERT(messageelements->count > 0);

		switch (messageelement->id.type) {
		case CAPWAP_ELEMENT_80211_ANTENNA_TYPE:
			for (i = 0; i < messageelements->count; i++) {
				struct capwap_80211_antenna_element *antenna =
					*(struct capwap_80211_antenna_element**)capwap_array_get_item_pointer(messageelements, i);

				radio = wtp_radio_get_phy(antenna->radioid);
				if (!radio)
					continue;

				capwap_element_80211_antenna_copy(&radio->antenna, antenna);
			}
			break;

		case CAPWAP_ELEMENT_80211_MACOPERATION_TYPE:
			for (i = 0; i < messageelements->count; i++) {
				struct capwap_80211_macoperation_element *macoperation =
					*(struct capwap_80211_macoperation_element**)capwap_array_get_item_pointer(messageelements, i);

				radio = wtp_radio_get_phy(macoperation->radioid);
				if (!radio)
					continue;

				memcpy(&radio->macoperation, macoperation, sizeof(struct capwap_80211_macoperation_element));
			}
			break;

		case CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY_TYPE:
			for (i = 0; i < messageelements->count; i++) {
				struct capwap_80211_multidomaincapability_element *multidomaincapability =
					*(struct capwap_80211_multidomaincapability_element**)capwap_array_get_item_pointer(messageelements, i);

				radio = wtp_radio_get_phy(multidomaincapability->radioid);
				if (!radio)
					continue;

				memcpy(&radio->multidomaincapability, multidomaincapability, sizeof(struct capwap_80211_multidomaincapability_element));
			}
			break;

		case CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL_TYPE:
			for (i = 0; i < messageelements->count; i++) {
				struct capwap_80211_directsequencecontrol_element *directsequencecontrol =
					*(struct capwap_80211_directsequencecontrol_element**)capwap_array_get_item_pointer(messageelements, i);

				radio = wtp_radio_get_phy(directsequencecontrol->radioid);
				if (!radio)
					continue;

				if (radio->radioinformation.radiotype & (CAPWAP_RADIO_TYPE_80211B | CAPWAP_RADIO_TYPE_80211G)) {
					memcpy(&radio->directsequencecontrol, directsequencecontrol, sizeof(struct capwap_80211_directsequencecontrol_element));

					/* Pending change radio channel */
					push_wtp_update_configuration_item(updateitems, WTP_UPDATE_FREQUENCY_DSSS, radio);
				}
			}
			break;

		case CAPWAP_ELEMENT_80211_OFDMCONTROL_TYPE:
			for (i = 0; i < messageelements->count; i++) {
				struct capwap_80211_ofdmcontrol_element *ofdmcontrol =
					*(struct capwap_80211_ofdmcontrol_element**)capwap_array_get_item_pointer(messageelements, i);

				radio = wtp_radio_get_phy(ofdmcontrol->radioid);
				if (!radio)
					continue;

				if (radio->radioinformation.radiotype & CAPWAP_RADIO_TYPE_80211A) {
					memcpy(&radio->ofdmcontrol, ofdmcontrol, sizeof(struct capwap_80211_ofdmcontrol_element));

					/* Pending change radio channel */
					push_wtp_update_configuration_item(updateitems, WTP_UPDATE_FREQUENCY_OFDM, radio);
				}
			}
			break;

		case CAPWAP_ELEMENT_80211_RATESET_TYPE:
			for (i = 0; i < messageelements->count; i++) {
				struct capwap_80211_rateset_element *rateset =
					*(struct capwap_80211_rateset_element**)capwap_array_get_item_pointer(messageelements, i);

				radio = wtp_radio_get_phy(rateset->radioid);
				if (!radio)
					continue;

				memcpy(&radio->rateset, rateset, sizeof(struct capwap_80211_rateset_element));

				/* Pending change radio rates */
				push_wtp_update_configuration_item(updateitems, WTP_UPDATE_RATES, radio);
			}
			break;

		case CAPWAP_ELEMENT_80211_SUPPORTEDRATES_TYPE:
			for (i = 0; i < messageelements->count; i++) {
				struct capwap_80211_supportedrates_element *supportedrates =
					*(struct capwap_80211_supportedrates_element**)capwap_array_get_item_pointer(messageelements, i);

				radio = wtp_radio_get_phy(supportedrates->radioid);
				if (!radio)
					continue;

				memcpy(&radio->supportedrates, supportedrates, sizeof(struct capwap_80211_supportedrates_element));
			}
			break;

		case CAPWAP_ELEMENT_80211_TXPOWER_TYPE:
			for (i = 0; i < messageelements->count; i++) {
				struct capwap_80211_txpower_element *txpower =
					*(struct capwap_80211_txpower_element**)capwap_array_get_item_pointer(messageelements, i);

				radio = wtp_radio_get_phy(txpower->radioid);
				if (!radio)
					continue;

				memcpy(&radio->txpower, txpower, sizeof(struct capwap_80211_txpower_element));
			}
			break;

		case CAPWAP_ELEMENT_80211_WTP_QOS_TYPE:
			for (i = 0; i < messageelements->count; i++) {
				struct capwap_80211_wtpqos_element* qos =
					*(struct capwap_80211_wtpqos_element**)capwap_array_get_item_pointer(messageelements, i);

				radio = wtp_radio_get_phy(qos->radioid);
				if (!radio)
					continue;

				memcpy(&radio->qos, qos, sizeof(struct capwap_80211_wtpqos_element));

				/* Pending change radio channel */
				push_wtp_update_configuration_item(updateitems, WTP_UPDATE_TX_QUEUE, radio);
			}
			break;

		case CAPWAP_ELEMENT_80211_WTP_RADIO_CONF_TYPE:
			for (i = 0; i < messageelements->count; i++) {
				struct capwap_80211_wtpradioconf_element* radioconfig =
					*(struct capwap_80211_wtpradioconf_element**)capwap_array_get_item_pointer(messageelements, i);

				radio = wtp_radio_get_phy(radioconfig->radioid);
				if (!radio)
					continue;

				memcpy(&radio->radioconfig, radioconfig, sizeof(struct capwap_80211_wtpradioconf_element));

				/* Pending change radio configuration */
				push_wtp_update_configuration_item(updateitems, WTP_UPDATE_CONFIGURATION, radio);
			}
			break;
		}
	}
}

/* */
int wtp_radio_setconfiguration(struct capwap_parsed_packet* packet)
{
	int i;
	int result = 0;
	struct capwap_array* updateitems;

	ASSERT(packet != NULL);

	/* */
	updateitems = capwap_array_create(sizeof(struct wtp_update_configuration_item), 0, 1);

	/* */
	switch (GET_WBID_HEADER(packet->rxmngpacket->header)) {
	case CAPWAP_WIRELESS_BINDING_IEEE80211:
		wtp_radio_setconfiguration_80211(packet, updateitems);
		break;
	}

	capwap_logging_debug("wtp_radio_setconfiguration result #1: %d", result);

	/* Update radio frequency */
	for (i = 0; (i < updateitems->count) && !result; i++) {
		struct wtp_update_configuration_item* item =
			(struct wtp_update_configuration_item*)capwap_array_get_item_pointer(updateitems, i);

		switch (item->type) {
		case WTP_UPDATE_FREQUENCY_DSSS:
			result = wifi_device_setfrequency(item->radio->devicehandle, WIFI_BAND_2GHZ,
							  item->radio->radioinformation.radiotype,
							  item->radio->directsequencecontrol.currentchannel);
			break;

		case WTP_UPDATE_FREQUENCY_OFDM:
			result = wifi_device_setfrequency(item->radio->devicehandle, WIFI_BAND_5GHZ,
							  item->radio->radioinformation.radiotype,
							  item->radio->ofdmcontrol.currentchannel);
			break;
		}
	}

	capwap_logging_debug("wtp_radio_setconfiguration result #2: %d", result);

	/* Update radio configuration */
	for (i = 0; (i < updateitems->count) && !result; i++) {
		struct wtp_update_configuration_item* item =
			(struct wtp_update_configuration_item*)capwap_array_get_item_pointer(updateitems, i);

		switch (item->type) {
		case WTP_UPDATE_RATES:
			result = wifi_device_updaterates(item->radio->devicehandle,
							 item->radio->rateset.rateset,
							 item->radio->rateset.ratesetcount);
			break;

		case WTP_UPDATE_CONFIGURATION: {
			struct device_setconfiguration_params params;

			memset(&params, 0, sizeof(struct device_setconfiguration_params));
			params.shortpreamble = ((item->radio->radioconfig.shortpreamble == CAPWAP_WTP_RADIO_CONF_SHORTPREAMBLE_ENABLE) ? 1 : 0);
			params.maxbssid = item->radio->radioconfig.maxbssid;
			params.dtimperiod = item->radio->radioconfig.dtimperiod;
			memcpy(params.bssid, item->radio->radioconfig.bssid, ETH_ALEN);
			params.beaconperiod = item->radio->radioconfig.beaconperiod;
			memcpy(params.country, item->radio->radioconfig.country, WIFI_COUNTRY_LENGTH);
			result = wifi_device_setconfiguration(item->radio->devicehandle, &params);
			break;
		}

		case WTP_UPDATE_TX_QUEUE:
			result = wifi_device_settxqueue(item->radio->devicehandle, &item->radio->qos);
			break;
		}
	}

	capwap_logging_debug("wtp_radio_setconfiguration result #3: %d", result);

	/* */
	capwap_array_free(updateitems);
	return result;
}

/* */
struct wtp_radio* wtp_radio_create_phy(void) {
	struct wtp_radio* radio;

	/* Create disabled radio */
	radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, g_wtp.radios->count);
	radio->radioid = (uint8_t)g_wtp.radios->count;
	radio->status = WTP_RADIO_DISABLED;

	/* Init configuration radio */
	radio->wlan = capwap_list_create();
	radio->wlanpool = capwap_list_create();
	radio->antenna.selections = capwap_array_create(sizeof(uint8_t), 0, 1);
	return radio;
}

/* */
struct wtp_radio* wtp_radio_get_phy(uint8_t radioid) {
	int i;

	/* Check */
	if (!IS_VALID_RADIOID(radioid)) {
		return NULL;
	}

	/* Retrieve radio */
	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio* radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);
		if (radioid == radio->radioid) {
			return radio;
		}
	}

	return NULL;
}

/* */
struct wtp_radio_wlan* wtp_radio_get_wlan(struct wtp_radio* radio, uint8_t wlanid) {
	struct capwap_list_item* itemwlan;

	ASSERT(radio != NULL);

	/* Check */
	if (!IS_VALID_WLANID(wlanid)) {
		capwap_logging_debug("wtp_radio_get_wlan: invalid wlanid (%d)", wlanid);
		return NULL;
	}

	/* Retrieve BSS */
	for (itemwlan = radio->wlan->first; itemwlan != NULL; itemwlan = itemwlan->next) {
		struct wtp_radio_wlan* wlan = (struct wtp_radio_wlan*)itemwlan->item;
		capwap_logging_debug("wtp_radio_get_wlan: checking (%d .. %d)", wlanid, wlan->wlanid);
		if (wlanid == wlan->wlanid) {
			return wlan;
		}
	}

	return NULL;
}

/* */
static struct wtp_radio_wlan* __wtp_radio_search_wlan(struct wtp_radio* radio, const uint8_t* bssid) {
	struct capwap_list_item* itemwlan;

	ASSERT(radio != NULL);

	/* Retrieve BSS */
	for (itemwlan = radio->wlan->first; itemwlan != NULL; itemwlan = itemwlan->next) {
		struct wtp_radio_wlan* wlan = (struct wtp_radio_wlan*)itemwlan->item;
		if (!memcmp(bssid, wlan->wlanhandle->address, MACADDRESS_EUI48_LENGTH)) {
			return wlan;
		}
	}

	return NULL;
}

/* */
struct wtp_radio_wlan* wtp_radio_search_wlan(struct wtp_radio* radio, const uint8_t* bssid) {
	int i;

	ASSERT(bssid != NULL);

	if (radio) {
		return __wtp_radio_search_wlan(radio, bssid);
	}

	/* Search from any radio */
	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio_wlan* wlansearch = __wtp_radio_search_wlan((struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i), bssid);
		if (wlansearch) {
			return wlansearch;
		}
	}

	return NULL;
}

/* */
void wtp_radio_receive_data_packet(uint8_t radioid, unsigned short binding, const uint8_t* frame, int length) {
	struct wtp_radio* radio;
	struct wtp_radio_wlan* wlan;

	ASSERT(frame != NULL);
	ASSERT(length > 0);

	/* Get radio */
	radio = wtp_radio_get_phy(radioid);
	if (!radio) {
		return;
	}

	if ((binding == CAPWAP_WIRELESS_BINDING_IEEE80211) && (length >= sizeof(struct ieee80211_header))) {
		struct ieee80211_header* header = (struct ieee80211_header*)frame;
		const uint8_t* bssid = ieee80211_get_bssid_addr(header);

		if (bssid) {
			wlan = wtp_radio_search_wlan(radio, bssid);
			if (wlan) {
				wifi_wlan_receive_ac_frame(wlan->wlanhandle, header, length);
			}
		}
	}
}

/* */
uint32_t wtp_radio_create_wlan(struct capwap_parsed_packet* packet, struct capwap_80211_assignbssid_element* bssid) {
	struct wtp_radio* radio;
	struct wtp_radio_wlan* wlan;
	struct wtp_radio_wlanpool* wlanpool;
	struct capwap_list_item* itemwlan;
	struct capwap_list_item* itemwlanpool;
	struct wlan_startap_params params;
	struct capwap_80211_addwlan_element* addwlan;

	ASSERT(packet != NULL);

	/* Get message elements */
	addwlan = (struct capwap_80211_addwlan_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_ADD_WLAN);
	if (!addwlan) {
		capwap_logging_debug("Create WLAN: no wlan");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Get physical radio */
	radio = wtp_radio_get_phy(addwlan->radioid);
	if (!radio) {
		capwap_logging_debug("Create WLAN: no radio");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Check if virtual interface is already exist */
	wlan = wtp_radio_get_wlan(radio, addwlan->wlanid);
	if (wlan) {
		capwap_logging_debug("Create WLAN: vif already exists");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Verify exist interface into pool */
	if (!radio->wlanpool->first) {
		capwap_logging_debug("Create WLAN: not first if in pool");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Prepare physical interface for create wlan */
	if (!radio->wlan->count) {
		if (wtp_radio_configure_phy(radio)) {
			capwap_logging_debug("Create WLAN: config phy failed");
			return CAPWAP_RESULTCODE_FAILURE;
		}
	}

	/* Get interface from pool */
	itemwlanpool = capwap_itemlist_remove_head(radio->wlanpool);
	wlanpool = (struct wtp_radio_wlanpool*)itemwlanpool->item;

	/* Create interface used */
	itemwlan = capwap_itemlist_create(sizeof(struct wtp_radio_wlan));
	wlan = (struct wtp_radio_wlan*)itemwlan->item;
	wlan->wlanid = addwlan->wlanid;
	wlan->wlanhandle = wlanpool->wlanhandle;
	wlan->radio = wlanpool->radio;

	/* Wlan configuration */
	memset(&params, 0, sizeof(struct wlan_startap_params));
	params.radioid = addwlan->radioid;
	params.wlanid = addwlan->wlanid;
	params.ssid = (const char*)addwlan->ssid;
	params.ssid_hidden = addwlan->suppressssid;
	params.capability = addwlan->capability;
	params.qos = addwlan->qos;
	params.authmode = addwlan->authmode;
	params.macmode = addwlan->macmode;
	params.tunnelmode = addwlan->tunnelmode;
	params.ie = (struct capwap_array *)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_IE);

	/* Start AP */
	if (wifi_wlan_startap(wlanpool->wlanhandle, &params)) {
		capwap_logging_debug("Create WLAN: start AP failes");
		/* Set interface to pool */
		capwap_itemlist_free(itemwlan);
		capwap_itemlist_insert_before(radio->wlanpool, NULL, itemwlanpool);
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Move interface from pool to used */
	capwap_itemlist_free(itemwlanpool);
	capwap_itemlist_insert_after(radio->wlan, NULL, itemwlan);

	/* Update Event File Descriptor */
	wtp_dfa_update_fdspool(&g_wtp.fds);

	/* Retrieve macaddress of new device */
	bssid->radioid = addwlan->radioid;
	bssid->wlanid = addwlan->wlanid;
	wifi_wlan_getbssid(wlan->wlanhandle, bssid->bssid);

	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
uint32_t wtp_radio_update_wlan(struct capwap_parsed_packet* packet) {
	/* TODO */
	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
uint32_t wtp_radio_delete_wlan(struct capwap_parsed_packet* packet) {
	/* TODO */
	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
uint32_t wtp_radio_add_station(struct capwap_parsed_packet* packet) {
	struct capwap_addstation_element* addstation;
	struct capwap_80211_station_element* station80211;
	struct wtp_radio* radio;
	struct wtp_radio_wlan* wlan;
	struct station_add_params stationparams;
	int err;

	/* Get message elements */
	addstation = (struct capwap_addstation_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_ADDSTATION);
	station80211 = (struct capwap_80211_station_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_STATION);
	if (!station80211 || (addstation->radioid != station80211->radioid)) {
		capwap_logging_debug("add_station: error no station or wrong radio");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Get physical radio */
	radio = wtp_radio_get_phy(addstation->radioid);
	if (!radio) {
		capwap_logging_debug("add_station: radio_get_phy failed");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Get virtual interface */
	wlan = wtp_radio_get_wlan(radio, station80211->wlanid);
	if (!wlan) {
		capwap_logging_debug("add_station: radio_get_wlan failed (%p, %d)", radio, station80211->wlanid);
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Authorize station */
	memset(&stationparams, 0, sizeof(struct station_add_params));
	stationparams.address = station80211->address;

	err = wtp_kmod_add_station(addstation->radioid, station80211->address, station80211->wlanid);
	if (err < 0) {
		capwap_logging_debug("add_station: CAPWAP add_station failed with: %d", err);
		return CAPWAP_RESULTCODE_FAILURE;
	}

	if (wifi_station_authorize(wlan->wlanhandle, &stationparams)) {
		wtp_kmod_del_station(addstation->radioid, station80211->address);
		capwap_logging_debug("add_station: station_authorize failed");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	capwap_logging_debug("add_station: SUCCESS");
	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
uint32_t wtp_radio_delete_station(struct capwap_parsed_packet* packet) {
	struct wtp_radio* radio;
	struct capwap_deletestation_element* deletestation;

	/* Get message elements */
	deletestation = (struct capwap_deletestation_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_DELETESTATION);

	/* Get physical radio */
	radio = wtp_radio_get_phy(deletestation->radioid);
	if (!radio) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* */
	wifi_station_deauthorize(radio->devicehandle, deletestation->address);
	wtp_kmod_del_station(deletestation->radioid, deletestation->address);

	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
int wtp_radio_acl_station(const uint8_t* macaddress) {
	ASSERT(macaddress != NULL);

	/* Check if exist ACL for station */
	if (capwap_hash_search(g_wtp.aclstations, macaddress)) {
		return ((g_wtp.defaultaclstations == WTP_RADIO_ACL_STATION_ALLOW) ? WTP_RADIO_ACL_STATION_DENY : WTP_RADIO_ACL_STATION_ALLOW);
	}

	/* Default ACL station */
	return g_wtp.defaultaclstations;
}

/* */
void wtp_radio_acl_addstation(const uint8_t* macaddress) {
	ASSERT(macaddress != NULL);

	// TODO capwap_hash_add(g_wtp.aclstations, macaddress, NULL);
}

void wtp_radio_acl_deletestation(const uint8_t* macaddress) {
	ASSERT(macaddress != NULL);

	// TODO capwap_hash_delete(g_wtp.aclstations, macaddress);
}
