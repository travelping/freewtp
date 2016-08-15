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
static int wtp_radio_configure_phy(struct wtp_radio* radio)
{
	if (radio->initialized)
		return 0;

	/* Default rate set is all supported rate */
	if (radio->radioid != radio->rateset.radioid) {
		if (radio->radioid != radio->supportedrates.radioid) {
			log_printf(LOG_DEBUG, "Config Phy: Supported rate not set");
			return -1;			/* Supported rate not set */
		}

		/* */
		radio->rateset.radioid = radio->radioid;
		radio->rateset.ratesetcount = radio->supportedrates.supportedratescount;
		memcpy(radio->rateset.rateset, radio->supportedrates.supportedrates, CAPWAP_RATESET_MAXLENGTH);

		/* Update rates */
		if (wifi_device_updaterates(radio->devicehandle, radio->rateset.rateset,
					    radio->rateset.ratesetcount)) {
			log_printf(LOG_DEBUG, "Config Phy: update rates failed");
			return -1;
		}
	}

	/* Check channel radio */
	if (radio->radioid != radio->radioinformation.radioid) {
		log_printf(LOG_DEBUG, "Config Phy: RI id mismatch");
		return -1;
	} else if (radio->radioid != radio->radioconfig.radioid) {
		log_printf(LOG_DEBUG, "Config Phy: RC id mismatch");
		return -1;
	} else if ((!radio->directsequencecontrol.radioid && !radio->ofdmcontrol.radioid) ||
		   ((radio->directsequencecontrol.radioid == radio->radioid) &&
		    (radio->ofdmcontrol.radioid == radio->radioid))) {
		log_printf(LOG_DEBUG, "Config Phy: DSSS / OFDM mismatch");
		return -1;		/* Only one from DSSS and OFDM can select */
	} else if ((radio->radioid == radio->directsequencecontrol.radioid) &&
		   !(radio->radioinformation.radiotype & (CAPWAP_RADIO_TYPE_80211B | CAPWAP_RADIO_TYPE_80211G))) {
		log_printf(LOG_DEBUG, "Config Phy: DSSS B/G mismatch");
		return -1;
	} else if ((radio->radioid == radio->ofdmcontrol.radioid) &&
		   !(radio->radioinformation.radiotype & CAPWAP_RADIO_TYPE_80211A)) {
		log_printf(LOG_DEBUG, "Config Phy: OFDM A mismatch");
		return -1;
	}

	radio->initialized = 1;
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
void wtp_radio_close(void)
{
	int i;

	ASSERT(g_wtp.radios != NULL);

	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio* radio =
			(struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);

		if (radio->antenna.selections) {
			capwap_array_free(radio->antenna.selections);
		}

		for (i = 0; i < radio->wlan->count; i++) {
			struct wtp_radio_wlan *wlan =
				(struct wtp_radio_wlan *)capwap_array_get_item_pointer(radio->wlan, i);

			/* Destroy BSS interface */
			if (wlan->wlanhandle)
				wifi_wlan_destroy(wlan->wlanhandle);

		}
		capwap_array_free(radio->wlan);
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

/* */
void wtp_radio_reset()
{
	int i, j;

	if (!g_wtp.radios)
		return;

	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio* radio =
			(struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);

		for (j = 0; j < radio->wlan->count; j++) {
			struct wtp_radio_wlan *wlan =
				(struct wtp_radio_wlan *)capwap_array_get_item_pointer(radio->wlan, j);

			/* Destroy WLAN interface */
			if (wlan->wlanhandle)
				wifi_wlan_stopap(wlan->wlanhandle);

			wlan->in_use = 0;
		}

		radio->initialized = 0;
	}
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
		if (!IS_80211_MESSAGE_ELEMENTS(messageelement->id) &&
		    !message_element_id_eq(messageelement->id, CAPWAP_ELEMENT_80211N_RADIO_CONF))
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
		if (!IS_80211_MESSAGE_ELEMENTS(messageelement->id) &&
		    !message_element_id_eq(messageelement->id, CAPWAP_ELEMENT_80211N_RADIO_CONF))
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

		case CAPWAP_ELEMENT_80211N_RADIO_CONF_TYPE:
			for (i = 0; i < messageelements->count; i++) {
				struct capwap_80211n_radioconf_element* radioconfig =
					*(struct capwap_80211n_radioconf_element**)capwap_array_get_item_pointer(messageelements, i);

				radio = wtp_radio_get_phy(radioconfig->radioid);
				if (!radio)
					continue;

				memcpy(&radio->radioconfig, radioconfig, sizeof(struct capwap_80211n_radioconf_element));

				/* Pending change radio configuration */
#if 0
				/* TODO: handle 802.11n config */
				push_wtp_update_configuration_item(updateitems, WTP_UPDATE_80211N_CONFIG, radio);
#endif
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

	log_printf(LOG_DEBUG, "wtp_radio_setconfiguration result #1: %d", result);

	/* Update radio frequency */
	for (i = 0; (i < updateitems->count) && !result; i++) {
		struct wtp_update_configuration_item* item =
			(struct wtp_update_configuration_item*)capwap_array_get_item_pointer(updateitems, i);

		switch (item->type) {
		case WTP_UPDATE_FREQUENCY_DSSS:
			result = wifi_device_setfrequency(item->radio->devicehandle, WIFI_BAND_2GHZ,
							  item->radio->radioinformation.radiotype,
							  item->radio->directsequencecontrol.currentchannel);
			log_printf(LOG_DEBUG, "wtp_radio %d, set 2GHz frequency to %d, result: %d",
				   item->radio->radioid, item->radio->directsequencecontrol.currentchannel,
				   result);
			break;

		case WTP_UPDATE_FREQUENCY_OFDM:
			result = wifi_device_setfrequency(item->radio->devicehandle, WIFI_BAND_5GHZ,
							  item->radio->radioinformation.radiotype,
							  item->radio->ofdmcontrol.currentchannel);
			log_printf(LOG_DEBUG, "wtp_radio %d, set 5GHz frequency to %d, result: %d",
				   item->radio->radioid, item->radio->ofdmcontrol.currentchannel,
				   result);
			break;
		}
	}

	/* Update radio configuration */
	for (i = 0; (i < updateitems->count) && !result; i++) {
		struct wtp_update_configuration_item* item =
			(struct wtp_update_configuration_item*)capwap_array_get_item_pointer(updateitems, i);

		switch (item->type) {
		case WTP_UPDATE_RATES:
			result = wifi_device_updaterates(item->radio->devicehandle,
							 item->radio->rateset.rateset,
							 item->radio->rateset.ratesetcount);
			log_printf(LOG_DEBUG, "wtp_radio %d, update rates result: %d",
				   item->radio->radioid, result);
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

			log_printf(LOG_DEBUG, "wtp_radio %d, set configuration result: %d",
				   item->radio->radioid, result);
			break;
		}

		case WTP_UPDATE_TX_QUEUE:
			result = wifi_device_settxqueue(item->radio->devicehandle, &item->radio->qos);

			log_printf(LOG_DEBUG, "wtp_radio %d, set Tx queue result: %d",
				   item->radio->radioid, result);
			break;
		}
	}

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
	radio->wlan = capwap_array_create(sizeof(struct wtp_radio_wlan), 0, 1);
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
struct wtp_radio_wlan *wtp_radio_get_wlan(struct wtp_radio *radio, uint8_t wlanid)
{
	ASSERT(radio != NULL);

	/* Check */
	if (!IS_VALID_WLANID(wlanid)) {
		log_printf(LOG_DEBUG, "wtp_radio_get_wlan: invalid wlanid (%d)", wlanid);
		return NULL;
	}

	if (wlanid > radio->wlan->count) {
		log_printf(LOG_WARNING, "wtp_radio_get_wlan: invalid wlanid (%d > %lu)",
				       wlanid, radio->wlan->count);
		return NULL;
	}

	/* Retrieve BSS */
	return (struct wtp_radio_wlan *)capwap_array_get_item_pointer(radio->wlan, wlanid);
}

/* */
static struct wtp_radio_wlan *__wtp_radio_search_wlan(struct wtp_radio *radio, const uint8_t *bssid)
{
	int i;

	ASSERT(radio != NULL);
	ASSERT(radio->wlan != NULL);

	/* Retrieve BSS */
	for (i = 0; i < radio->wlan->count; i++) {
		struct wtp_radio_wlan *wlan =
			(struct wtp_radio_wlan *)capwap_array_get_item_pointer(radio->wlan, i);

		if (!wlan->wlanhandle)
			continue;

		if (!memcmp(bssid, wlan->wlanhandle->address, MACADDRESS_EUI48_LENGTH))
			return wlan;
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

static struct capwap_array *wtp_radio_set_update_keys(struct capwap_parsed_packet *packet,
						      uint8_t radioid, uint8_t wlanid)
{
	int i;
	struct capwap_array *keys;
	struct capwap_array *updatekeys = NULL;

	ASSERT(packet != NULL);

	keys = (struct capwap_array *)
		capwap_get_message_element_data(packet, CAPWAP_ELEMENT_VENDOR_TRAVELPING_80211_UPDATE_KEY);
	log_printf(LOG_DEBUG, "Set Update Keys: %p", keys);
	if (!keys)
		return NULL;

	log_printf(LOG_DEBUG, "Set Update Keys: #%ld", keys->count);
	for (i = 0; i < keys->count; i++) {
		struct capwap_vendor_travelping_80211_update_key_element *key =
			*(struct capwap_vendor_travelping_80211_update_key_element **)
			capwap_array_get_item_pointer(keys, i);

		log_printf(LOG_DEBUG, "RadioId: %d .. %d, WlanId: %d .. %d",
			   key->radioid, radioid,
			   key->wlanid, wlanid);

		if (key->radioid != radioid || key->wlanid != wlanid)
			continue;

		if (!updatekeys)
			updatekeys = capwap_array_create(sizeof(void *), 0, 0);
		if (!updatekeys) {
			log_printf(LOG_DEBUG, "Update WLAN: Out of Memory");
			return NULL;
		}
		*(void **)capwap_array_get_item_pointer(updatekeys, updatekeys->count) = key;
		log_printf(LOG_DEBUG, "Set Update Keys: Update #%ld", updatekeys->count);
	}

	return updatekeys;
}

/* source http://stackoverflow.com/a/16994674 */
static uint16_t reverse(register uint16_t x)
{
    x = (((x & 0xaaaa) >> 1) | ((x & 0x5555) << 1));
    x = (((x & 0xcccc) >> 2) | ((x & 0x3333) << 2));
    x = (((x & 0xf0f0) >> 4) | ((x & 0x0f0f) << 4));
    x = (((x & 0xff00) >> 8) | ((x & 0x00ff) << 8));
    return x;
}

/* */
uint32_t wtp_radio_create_wlan(struct capwap_parsed_packet* packet,
			       struct capwap_80211_assignbssid_element* bssid)
{
	struct wtp_radio* radio;
	struct wtp_radio_wlan* wlan;
	struct wlan_startap_params params;
	struct capwap_80211_addwlan_element* addwlan;

	ASSERT(packet != NULL);

	/* Get message elements */
	addwlan = (struct capwap_80211_addwlan_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_ADD_WLAN);
	if (!addwlan) {
		log_printf(LOG_DEBUG, "Create WLAN: no wlan");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Get physical radio */
	radio = wtp_radio_get_phy(addwlan->radioid);
	if (!radio) {
		log_printf(LOG_DEBUG, "Create WLAN: no radio");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Check if virtual interface is already exist */
	wlan = wtp_radio_get_wlan(radio, addwlan->wlanid);
	if (!wlan || !wlan->wlanhandle) {
		log_printf(LOG_DEBUG, "Create WLAN: invalid WLAN ID");
		return CAPWAP_RESULTCODE_FAILURE;
	}
	if (wlan->in_use) {
		log_printf(LOG_DEBUG, "Create WLAN: vif already exists");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Prepare physical interface for create wlan */
	if (wtp_radio_configure_phy(radio)) {
		log_printf(LOG_DEBUG, "Create WLAN: config phy failed");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Wlan configuration */
	memset(&params, 0, sizeof(struct wlan_startap_params));
	params.radioid = addwlan->radioid;
	params.wlanid = addwlan->wlanid;
	params.ssid = (const char*)addwlan->ssid;
	params.ssid_hidden = addwlan->suppressssid;
	params.capability = reverse(addwlan->capability);
	params.qos = addwlan->qos;
	params.authmode = addwlan->authmode;
	params.macmode = addwlan->macmode;
	params.tunnelmode = addwlan->tunnelmode;

	params.keyindex = addwlan->keyindex;
	params.keylength = addwlan->keylength;
	params.key = addwlan->key;

	params.ie = (struct capwap_array *)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_IE);
	params.updatekeys = wtp_radio_set_update_keys(packet, addwlan->radioid, addwlan->wlanid);

	/* Start AP */
	if (wifi_wlan_startap(wlan->wlanhandle, &params)) {
		log_printf(LOG_DEBUG, "Create WLAN: start AP failes");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Mark interface as used */
	wlan->in_use = 1;

	/* Retrieve macaddress of new device */
	bssid->radioid = addwlan->radioid;
	bssid->wlanid = addwlan->wlanid;
	wifi_wlan_getbssid(wlan->wlanhandle, bssid->bssid);

	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
uint32_t wtp_radio_update_wlan(struct capwap_parsed_packet* packet)
{
	struct wtp_radio* radio;
	struct wtp_radio_wlan* wlan;
	struct wlan_updateap_params params;
	struct capwap_80211_updatewlan_element* updatewlan;

	ASSERT(packet != NULL);

	/* Get message elements */
	updatewlan = (struct capwap_80211_updatewlan_element*)
		capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_UPDATE_WLAN);
	if (!updatewlan) {
		log_printf(LOG_DEBUG, "Update WLAN: no wlan");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Get physical radio */
	radio = wtp_radio_get_phy(updatewlan->radioid);
	if (!radio) {
		log_printf(LOG_DEBUG, "Update WLAN: no radio");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Check if virtual interface is already exist */
	wlan = wtp_radio_get_wlan(radio, updatewlan->wlanid);
	if (!wlan || !wlan->wlanhandle) {
		log_printf(LOG_DEBUG, "Update WLAN: invalid WLAN ID");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	if (!wlan->in_use) {
		log_printf(LOG_DEBUG, "Update WLAN: vif does not exists");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Wlan Update Configuration */
	memset(&params, 0, sizeof(struct wlan_updateap_params));
	params.radioid = updatewlan->radioid;
	params.wlanid = updatewlan->wlanid;
	params.capability = reverse(updatewlan->capability);

	params.keyindex = updatewlan->keyindex;
	params.keystatus = updatewlan->keystatus;
	params.keylength = updatewlan->keylength;
	params.key = updatewlan->key;

	params.ie = (struct capwap_array *)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_IE);
	params.updatekeys = wtp_radio_set_update_keys(packet, updatewlan->radioid, updatewlan->wlanid);

	/* Update AP */
	if (wifi_wlan_updateap(wlan->wlanhandle, &params)) {
		log_printf(LOG_DEBUG, "Update WLAN: update AP failed");
		return CAPWAP_RESULTCODE_FAILURE;
	}

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
	struct capwap_80211n_station_info_element *station80211n;
	struct capwap_80211_stationkey_element *key;
	struct capwap_array *ie;
	struct wtp_radio* radio;
	struct wtp_radio_wlan* wlan;
	struct station_add_params stationparams;
	struct ieee80211_ht_cap ht_cap;
	uint32_t flags = 0;
	int err, i;

	/* Get message elements */
	addstation = (struct capwap_addstation_element*)
		capwap_get_message_element_data(packet, CAPWAP_ELEMENT_ADDSTATION);
	station80211 = (struct capwap_80211_station_element*)
		capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_STATION);
	station80211n = (struct capwap_80211n_station_info_element *)
		capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211N_STATION_INFO);
	key = (struct capwap_80211_stationkey_element *)
		capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_STATION_SESSION_KEY_PROFILE);
	ie = (struct capwap_array *)
		capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_IE);

	if (!station80211 || (addstation->radioid != station80211->radioid)) {
		log_printf(LOG_DEBUG, "add_station: error no station or wrong radio");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Get physical radio */
	radio = wtp_radio_get_phy(addstation->radioid);
	if (!radio) {
		log_printf(LOG_DEBUG, "add_station: radio_get_phy failed");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Get virtual interface */
	wlan = wtp_radio_get_wlan(radio, station80211->wlanid);
	if (!wlan) {
		log_printf(LOG_DEBUG, "add_station: radio_get_wlan failed (%p, %d)", radio, station80211->wlanid);
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Authorize station */
	memset(&stationparams, 0, sizeof(struct station_add_params));
	stationparams.address = station80211->address;

	log_printf(LOG_DEBUG, "Station 802.11n IE: %p", station80211n);
	if (station80211n) {
		uint16_t cap_info;

		if (memcmp(station80211->address, station80211n->address,
			   MACADDRESS_EUI48_LENGTH) != 0) {
			log_printf(LOG_DEBUG, "add_station: 802.11n Station Information MAC mismatch");
			return CAPWAP_RESULTCODE_FAILURE;
		}

		/* build 802.11n settings */
		memset(&ht_cap, 0, sizeof(ht_cap));

		cap_info = 0;
		if (station80211n->flags & CAPWAP_80211N_STATION_INFO_40MHZ_BANDWITH)
			cap_info |= IEEE80211_HT_CAP_SUP_WIDTH_20_40;
		if (station80211n->flags & CAPWAP_80211N_STATION_INFO_SHORT_GUARD_INTERVAL_AT_20MHZ)
			cap_info |= IEEE80211_HT_CAP_SGI_20;
		if (station80211n->flags & CAPWAP_80211N_STATION_INFO_SHORT_GUARD_INTERVAL_AT_40MHZ)
			cap_info |= IEEE80211_HT_CAP_SGI_40;
		if (station80211n->flags & CAPWAP_80211N_STATION_INFO_BLOCK_ACK_DELAY_MODE)
			cap_info |= IEEE80211_HT_CAP_DELAY_BA;
		if (station80211n->flags & CAPWAP_80211N_STATION_INFO_MAX_AMSDU_LENGTH_7935)
			cap_info |= IEEE80211_HT_CAP_MAX_AMSDU;
		cap_info |= ((station80211n->flags & CAPWAP_80211N_STATION_INFO_POWER_SAVE_MODE)
			     >> CAPWAP_80211N_STATION_INFO_POWER_SAVE_MODE_SHIFT)
			<< IEEE80211_HT_CAP_SM_PS_SHIFT;

		ht_cap.cap_info = __cpu_to_le16(cap_info);

		ht_cap.ampdu_params_info = (station80211n->maxrxfactor & 0x03) |
			(station80211n->minstaspaceing & 0x07) << 2;

		ht_cap.mcs.rx_highest = __cpu_to_le16(station80211n->hisuppdatarate);
		memcpy(&ht_cap.mcs.rx_mask, station80211n->mcsset, sizeof(ht_cap.mcs.rx_mask));

		stationparams.ht_cap = &ht_cap;
		stationparams.max_inactivity = g_wtp.sta_max_inactivity;
	}

	if (key) {
		if (memcmp(station80211->address, key->address,
			   MACADDRESS_EUI48_LENGTH) != 0) {
			log_printf(LOG_DEBUG, "add_station: 802.11n Station Session Key MAC mismatch");
			return CAPWAP_RESULTCODE_FAILURE;
		}

		log_printf(LOG_DEBUG, "add_station: key flags: %04x", key->flags);
		if (key->flags & 0x8000)
			flags |= STA_FLAG_AKM_ONLY;

		stationparams.key = key;
	}

	if (ie) {
		for (i = 0; i < ie->count; i++) {
			struct ieee80211_ie *rsn;
			uint8_t *data;

			struct capwap_80211_ie_element *e =
				*(struct capwap_80211_ie_element **)capwap_array_get_item_pointer(ie, i);

			if (e->radioid != station80211->radioid ||
			    e->wlanid != station80211->wlanid ||
			    e->ielength < 2)
				continue;

			rsn = (struct ieee80211_ie *)e->ie;
			if (rsn->id != IEEE80211_IE_RSN_INFORMATION)
				continue;

			data = (uint8_t *)(rsn + 1);
			data += 2; // RSN Version
			data += 4; // Group Chipher Suite
			if (*(uint16_t *)data != 1) {
				log_printf(LOG_DEBUG, "add_station: RSNE IE, wrong Pairwise Cipher Suite Count (%d)",
					   *(uint16_t *)data);
				return CAPWAP_RESULTCODE_FAILURE;
			}
			data +=2; // Pairwise Cipher Suiter Length
			stationparams.pairwise = ntohl(*(uint32_t *)data);

			break;
		}
	}

	err = wtp_kmod_add_station(addstation->radioid, station80211->address, station80211->wlanid, flags);
	if (err < 0) {
		log_printf(LOG_DEBUG, "add_station: CAPWAP add_station failed with: %d", err);
		return CAPWAP_RESULTCODE_FAILURE;
	}

	if (wifi_station_authorize(wlan->wlanhandle, &stationparams)) {
		wtp_kmod_del_station(addstation->radioid, station80211->address);
		log_printf(LOG_DEBUG, "add_station: station_authorize failed");
		return CAPWAP_RESULTCODE_FAILURE;
	}

	log_printf(LOG_DEBUG, "add_station: SUCCESS");
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
