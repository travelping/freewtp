#include "ac.h"
#include "ac_session.h"
#include "ac_wlans.h"
#include "ac_backend.h"

/* */
static void ac_stations_delete_station_from_global_cache(struct ac_session_data_t* sessiondata, uint8_t* address) {
	struct ac_session_data_t* ownersession;

	ASSERT(sessiondata != NULL);
	ASSERT(address != NULL);

	/* */
	capwap_rwlock_wrlock(&g_ac.stationslock);

	/* Can delete global reference only if match session handler */
	ownersession = (struct ac_session_data_t*)capwap_hash_search(g_ac.stations, address);
	if (ownersession == sessiondata) {
		capwap_hash_delete(g_ac.stations, address);
	}

	capwap_rwlock_exit(&g_ac.stationslock);
}

/* */
static void ac_stations_reset_station(struct ac_session_data_t* sessiondata, struct ac_station* station, struct ac_wlan* wlan) {
	ASSERT(sessiondata != NULL);
	ASSERT(station != NULL);

	/* Remove reference from current WLAN */
	if (station->wlan) {
		capwap_itemlist_remove(station->wlan->stations, station->wlanitem);
	}

	/* Remove timers */
	if (station->idtimeout != CAPWAP_TIMEOUT_INDEX_NO_SET) {
		capwap_timeout_deletetimer(sessiondata->timeout, station->idtimeout);
		station->idtimeout = CAPWAP_TIMEOUT_INDEX_NO_SET;
	}

	/* */
	station->flags = 0;

	/* Set WLAN */
	station->wlan = wlan;
	if (station->wlan) {
		capwap_itemlist_insert_after(wlan->stations, NULL, station->wlanitem);
	}
}

/* */
static void ac_stations_destroy_station(struct ac_session_data_t* sessiondata, struct ac_station* station) {
	char buffer[CAPWAP_MACADDRESS_EUI48_BUFFER];

	ASSERT(sessiondata != NULL);
	ASSERT(station != NULL);

	/* */
	capwap_logging_info("Destroy station: %s", capwap_printf_macaddress(buffer, station->address, MACADDRESS_EUI48_LENGTH));

	/* Remove reference from Global Cache Stations List */
	ac_stations_delete_station_from_global_cache(sessiondata, station->address);

	/* Remove reference from WLAN */
	ac_stations_reset_station(sessiondata, station, NULL);

	/* */
	capwap_hash_delete(sessiondata->wlans->stations, station->address);

	/* Free station reference with itemlist */
	capwap_itemlist_free(station->wlanitem);
}

/* */
static unsigned long ac_wlans_item_gethash(const void* key, unsigned long keysize, unsigned long hashsize) {
	uint8_t* macaddress = (uint8_t*)key;

	ASSERT(keysize == MACADDRESS_EUI48_LENGTH);

	return (unsigned long)(macaddress[3] ^ macaddress[4] ^ macaddress[5]);
}

/* */
void ac_wlans_init(struct ac_session_data_t* sessiondata) {
	ASSERT(sessiondata != NULL);

	/* */
	sessiondata->wlans = (struct ac_wlans*)capwap_alloc(sizeof(struct ac_wlans));
	memset(sessiondata->wlans, 0, sizeof(struct ac_wlans));

	/* */
	sessiondata->wlans->stations = capwap_hash_create(AC_WLANS_STATIONS_HASH_SIZE, AC_WLANS_STATIONS_KEY_SIZE, ac_wlans_item_gethash, NULL, NULL);
}

/* */
void ac_wlans_destroy(struct ac_session_data_t* sessiondata) {
	int i;
	struct capwap_list* items;

	ASSERT(sessiondata != NULL);
	ASSERT(sessiondata->wlans != NULL);

	/* */
	for (i = 0; i < RADIOID_MAX_COUNT; i++) {
		if (sessiondata->wlans->wlans[i]) {
			items = sessiondata->wlans->wlans[i];

			/* Delete WLANS */
			while (items->first) {
				ac_wlans_delete_bssid(sessiondata, i + 1, ((struct ac_wlan*)items->first->item)->bssid);
			}

			/* */
			capwap_list_free(items); 
		} 
	}

	/* */
	ASSERT(sessiondata->wlans->stations->count == 0);

	/* */
	capwap_hash_free(sessiondata->wlans->stations);
	capwap_free(sessiondata->wlans);
}

/* */
int ac_wlans_assign_bssid(struct ac_session_data_t* sessiondata, struct ac_wlan* wlan) {
	char buffer[CAPWAP_MACADDRESS_EUI48_BUFFER];

	ASSERT(sessiondata != NULL);
	ASSERT(sessiondata->wlans != NULL);
	ASSERT(wlan != NULL);
	ASSERT(IS_VALID_RADIOID(wlan->radioid));
	ASSERT(IS_VALID_WLANID(wlan->wlanid));

	/* */
	if (ac_wlans_get_bssid(sessiondata, wlan->radioid, wlan->bssid)) {
		return 0;
	}

	/* */
	wlan->session = sessiondata->session;
	wlan->sessiondata = sessiondata;

	/* Create WLAN list */
	if (!sessiondata->wlans->wlans[wlan->radioid - 1]) {
		sessiondata->wlans->wlans[wlan->radioid - 1] = capwap_list_create();
	}

	/* Append WLAN to list */
	capwap_itemlist_insert_after(sessiondata->wlans->wlans[wlan->radioid - 1], NULL, wlan->wlanitem);

	/* */
	capwap_logging_info("Added new wlan with radioid: %d, wlanid: %d, bssid: %s", (int)wlan->radioid, (int)wlan->wlanid, capwap_printf_macaddress(buffer, wlan->bssid, MACADDRESS_EUI48_LENGTH));
	return 1;
}

/* */
struct ac_wlan* ac_wlans_create_bssid(uint8_t radioid, uint8_t wlanid, const uint8_t* bssid, struct capwap_80211_addwlan_element* addwlan) {
	struct ac_wlan* wlan;
	struct capwap_list_item* wlanitem;

	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(IS_VALID_WLANID(wlanid));
	ASSERT(bssid != NULL);

	/* */
	wlanitem = capwap_itemlist_create(sizeof(struct ac_wlan));
	wlan = (struct ac_wlan*)wlanitem->item;
	memset(wlan, 0, sizeof(struct ac_wlan));

	/* Init WLAN */
	wlan->wlanitem = wlanitem;
	memcpy(wlan->bssid, bssid, MACADDRESS_EUI48_LENGTH);
	wlan->radioid = radioid;
	wlan->wlanid = wlanid;
	wlan->stations = capwap_list_create();

	/* Set capability */
	wlan->capability = addwlan->capability;

	wlan->keyindex = addwlan->keyindex;
	wlan->keystatus = addwlan->keystatus;
	wlan->keylength = addwlan->keylength;
	if (addwlan->key && (addwlan->keylength > 0)) {
		wlan->key = (uint8_t*)capwap_clone(addwlan->key, wlan->keylength);
	}

	memcpy(wlan->grouptsc, addwlan->grouptsc, CAPWAP_ADD_WLAN_GROUPTSC_LENGTH);

	wlan->qos = addwlan->qos;
	wlan->authmode = addwlan->authmode;
	wlan->macmode = addwlan->macmode;
	wlan->tunnelmode = addwlan->tunnelmode;

	wlan->suppressssid = addwlan->suppressssid;
	wlan->ssid = (uint8_t*)capwap_duplicate_string((const char*)addwlan->ssid);

	return wlan;
}

/* */
struct ac_wlan* ac_wlans_get_bssid(struct ac_session_data_t* sessiondata, uint8_t radioid, const uint8_t* bssid) {
	struct capwap_list_item* search;
	struct ac_wlan* wlan = NULL;

	ASSERT(sessiondata != NULL);
	ASSERT(sessiondata->wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(bssid != NULL);

	/* */
	if (sessiondata->wlans->wlans[radioid - 1]) {
		search = sessiondata->wlans->wlans[radioid - 1]->first;
		while (search) {
			struct ac_wlan* item = (struct ac_wlan*)search->item;

			if (!memcmp(bssid, item->bssid, MACADDRESS_EUI48_LENGTH)) {
				wlan = item;
				break;
			}

			/* Next */
			search = search->next;
		}
	}

	return wlan;
}

/* */
struct ac_wlan* ac_wlans_get_bssid_with_wlanid(struct ac_session_data_t* sessiondata, uint8_t radioid, uint8_t wlanid) {
	struct capwap_list_item* search;
	struct ac_wlan* wlan = NULL;

	ASSERT(sessiondata != NULL);
	ASSERT(sessiondata->wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(IS_VALID_WLANID(wlanid));

	/* */
	if (sessiondata->wlans->wlans[radioid - 1]) {
		search = sessiondata->wlans->wlans[radioid - 1]->first;
		while (search) {
			struct ac_wlan* item = (struct ac_wlan*)search->item;

			if (wlanid == item->wlanid) {
				wlan = item;
				break;
			}

			/* Next */
			search = search->next;
		}
	}

	return wlan;
}

/* */
static void ac_wlans_destroy_bssid(struct ac_session_data_t* sessiondata, struct ac_wlan* wlan) {
	/* Free capability */
	if (wlan->key) {
		capwap_free(wlan->key);
	}

	if (wlan->ssid) {
		capwap_free(wlan->ssid);
	}

	/* Remove stations */
	while (wlan->stations->first) {
		ac_stations_destroy_station(sessiondata, (struct ac_station*)wlan->stations->first->item);
	}

	/* */
	capwap_list_free(wlan->stations);
}

/* */
void ac_wlans_delete_bssid(struct ac_session_data_t* sessiondata, uint8_t radioid, const uint8_t* bssid) {
	struct capwap_list_item* search;

	ASSERT(sessiondata != NULL);
	ASSERT(sessiondata->wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(bssid != NULL);

	/* */
	if (sessiondata->wlans->wlans[radioid - 1]) {
		search = sessiondata->wlans->wlans[radioid - 1]->first;
		while (search) {
			struct ac_wlan* item = (struct ac_wlan*)search->item;

			if (!memcmp(bssid, item->bssid, MACADDRESS_EUI48_LENGTH)) {
				ac_wlans_destroy_bssid(sessiondata, item);
				capwap_itemlist_free(capwap_itemlist_remove(sessiondata->wlans->wlans[radioid - 1], search));
				break;
			}

			/* Next */
			search = search->next;
		}
	}
}

/* */
struct ac_station* ac_stations_get_station(struct ac_session_data_t* sessiondata, uint8_t radioid, const uint8_t* bssid, const uint8_t* address) {
	struct ac_station* station;

	ASSERT(sessiondata != NULL);
	ASSERT(sessiondata->wlans != NULL);
	ASSERT(address != NULL);

	/* Get station */
	station = (struct ac_station*)capwap_hash_search(sessiondata->wlans->stations, address);
	if (station && (station->flags & AC_STATION_FLAGS_ENABLED) && ((radioid == RADIOID_ANY) || (radioid == station->wlan->radioid)) && (!bssid || !memcmp(bssid, station->wlan->bssid, MACADDRESS_EUI48_LENGTH))) {
		return station;
	}

	return NULL;
}

/* */
struct ac_station* ac_stations_create_station(struct ac_session_data_t* sessiondata, uint8_t radioid, const uint8_t* bssid, const uint8_t* address) {
	char buffer1[CAPWAP_MACADDRESS_EUI48_BUFFER];
	char buffer2[CAPWAP_MACADDRESS_EUI48_BUFFER];
	struct ac_wlan* wlan;
	struct ac_session_data_t* ownersession;
	struct ac_station* station;
	struct capwap_list_item* stationitem;

	ASSERT(sessiondata != NULL);
	ASSERT(sessiondata->wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(bssid != NULL);
	ASSERT(address != NULL);

	/* */
	capwap_printf_macaddress(buffer1, bssid, MACADDRESS_EUI48_LENGTH);
	capwap_printf_macaddress(buffer2, address, MACADDRESS_EUI48_LENGTH);
	capwap_logging_info("Create station to radioid: %d, bssid: %s, station address: %s", (int)radioid, buffer1, buffer2);

	/* Get session that owns the station */
	capwap_rwlock_rdlock(&g_ac.stationslock);
	ownersession = (struct ac_session_data_t*)capwap_hash_search(g_ac.stations, address);
	capwap_rwlock_exit(&g_ac.stationslock);

	/* If request change owner of station */
	if (ownersession != sessiondata) {
		/* Release station from old owner */
		if (ownersession) {
			ac_session_data_send_action(ownersession, AC_SESSION_DATA_ACTION_ROAMING_STATION, 0, (void*)address, MACADDRESS_EUI48_LENGTH);
		}

		/* Set station into Global Cache Stations List */
		capwap_rwlock_wrlock(&g_ac.stationslock);
		capwap_hash_add(g_ac.stations, address, sessiondata);
		capwap_rwlock_exit(&g_ac.stationslock);
	}

	/* */
	wlan = ac_wlans_get_bssid(sessiondata, radioid, bssid);
	station = (struct ac_station*)capwap_hash_search(sessiondata->wlans->stations, address);
	if (!station) {
		stationitem = capwap_itemlist_create(sizeof(struct ac_station));
		station = (struct ac_station*)stationitem->item;
		memset(station, 0, sizeof(struct ac_station));

		/* */
		station->idtimeout = CAPWAP_TIMEOUT_INDEX_NO_SET;
		memcpy(station->address, address, MACADDRESS_EUI48_LENGTH);
		station->wlanitem = stationitem;

		/* */
		capwap_hash_add(sessiondata->wlans->stations, address, station);
	}

	/* Set station to WLAN */
	ac_stations_reset_station(sessiondata, station, wlan);
	station->flags |= AC_STATION_FLAGS_ENABLED;

	return station;
}

/* */
void ac_stations_delete_station(struct ac_session_data_t* sessiondata, struct ac_station* station) {
	ASSERT(sessiondata != NULL);
	ASSERT(sessiondata->wlans != NULL);
	ASSERT(station != NULL);

	/* Deauthorize station */
	ac_stations_deauthorize_station(sessiondata, station);

	/* Destroy station reference */
	ac_stations_destroy_station(sessiondata, station);
}

/* */
void ac_stations_authorize_station(struct ac_session_data_t* sessiondata, struct ac_station* station) {
	struct ac_notify_station_configuration_ieee8011_add_station notify;

	ASSERT(sessiondata != NULL);
	ASSERT(sessiondata->wlans != NULL);
	ASSERT(station != NULL);

	/* Active Station only if Authenticated, Associated and not Authrizated */
	if ((station->flags & AC_STATION_FLAGS_AUTHENTICATED) && (station->flags & AC_STATION_FLAGS_ASSOCIATE) && !(station->flags & AC_STATION_FLAGS_AUTHORIZED)) {
		memset(&notify, 0, sizeof(struct ac_notify_station_configuration_ieee8011_add_station));
		notify.radioid = station->wlan->radioid;
		memcpy(notify.address, station->address, MACADDRESS_EUI48_LENGTH);
		notify.wlanid = station->wlan->wlanid;
		notify.associationid = station->aid;
		notify.capabilities = station->capability;
		notify.supportedratescount = station->supportedratescount;
		memcpy(notify.supportedrates, station->supportedrates, station->supportedratescount);

		ac_session_send_action(sessiondata->session, AC_SESSION_ACTION_STATION_CONFIGURATION_IEEE80211_ADD_STATION, 0, &notify, sizeof(struct ac_notify_station_configuration_ieee8011_add_station));
	}
}

/* */
void ac_stations_deauthorize_station(struct ac_session_data_t* sessiondata, struct ac_station* station) {
	int responselength;
	uint8_t buffer[IEEE80211_MTU];
	struct ieee80211_deauthentication_params ieee80211_params;
	struct ac_notify_station_configuration_ieee8011_delete_station notify;

	ASSERT(sessiondata != NULL);
	ASSERT(sessiondata->wlans != NULL);
	ASSERT(station != NULL);

	if (station->flags & AC_STATION_FLAGS_AUTHORIZED) {
		/* Deauthorize station */
		memset(&notify, 0, sizeof(struct ac_notify_station_configuration_ieee8011_delete_station));
		notify.radioid = station->wlan->radioid;
		memcpy(notify.address, station->address, MACADDRESS_EUI48_LENGTH);

		/* */
		station->flags &= ~(AC_STATION_FLAGS_AUTHENTICATED | AC_STATION_FLAGS_ASSOCIATE | AC_STATION_FLAGS_AUTHORIZED);
		ac_session_send_action(sessiondata->session, AC_SESSION_ACTION_STATION_CONFIGURATION_IEEE80211_DELETE_STATION, 0, &notify, sizeof(struct ac_notify_station_configuration_ieee8011_delete_station));
	} else if (station->flags & AC_STATION_FLAGS_AUTHENTICATED) {
		/* Create deauthentication packet */
		memset(&ieee80211_params, 0, sizeof(struct ieee80211_deauthentication_params));
		memcpy(ieee80211_params.bssid, station->wlan->bssid, MACADDRESS_EUI48_LENGTH);
		memcpy(ieee80211_params.station, station->address, MACADDRESS_EUI48_LENGTH);
		ieee80211_params.reasoncode = IEEE80211_REASON_PREV_AUTH_NOT_VALID;

		/* */
		responselength = ieee80211_create_deauthentication(buffer, IEEE80211_MTU, &ieee80211_params);
		if (responselength > 0) {
			station->flags &= ~(AC_STATION_FLAGS_AUTHENTICATED | AC_STATION_FLAGS_ASSOCIATE);
			ac_session_data_send_data_packet(sessiondata, station->wlan->radioid, station->wlan->wlanid, buffer, responselength, 1);
		}
	}
}

/* */
void ac_stations_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	char stationaddress[CAPWAP_MACADDRESS_EUI48_BUFFER];
	struct ac_station* station = (struct ac_station*)context;

	ASSERT(station != NULL);

	/* */
	capwap_printf_macaddress(stationaddress, station->address, MACADDRESS_EUI48_LENGTH);

	if (station->idtimeout == index) {
		switch (station->timeoutaction) {
			case AC_STATION_TIMEOUT_ACTION_DEAUTHENTICATE: {
				capwap_logging_warning("The %s station has not completed the association in time", stationaddress);
				ac_stations_delete_station((struct ac_session_data_t*)param, station);
				break;
			}
		}
	}
}
