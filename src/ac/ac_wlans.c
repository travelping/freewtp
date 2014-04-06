#include "ac.h"
#include "ac_session.h"
#include "ac_wlans.h"

/* */
static void ac_stations_delete_station_from_global_cache(struct ac_session_t* session, uint8_t* address) {
	struct ac_session_t* ownersession;

	ASSERT(session != NULL);
	ASSERT(address != NULL);

	/* */
	capwap_rwlock_wrlock(&g_ac.stationslock);

	/* Can delete global reference only if match session handler */
	ownersession = (struct ac_session_t*)capwap_hash_search(g_ac.stations, address);
	if (ownersession == session) {
		capwap_hash_delete(g_ac.stations, address);
	}

	capwap_rwlock_exit(&g_ac.stationslock);
}

/* */
static void ac_stations_destroy_station(struct ac_session_t* session, struct ac_station* station) {
	char buffer[CAPWAP_MACADDRESS_EUI48_BUFFER];

	ASSERT(session != NULL);
	ASSERT(station != NULL);

	/* */
	capwap_logging_info("Destroy station: %s", capwap_printf_macaddress(buffer, station->address, MACADDRESS_EUI48_LENGTH));

	/* Remove reference from Global Cache Stations List */
	ac_stations_delete_station_from_global_cache(session, station->address);

	/* Remove reference from WLAN */
	if (station->wlan) {
		capwap_itemlist_remove(station->wlan->stations, station->wlanitem);
	}

	/* */
	capwap_hash_delete(session->wlans->stations, station->address);

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
static void ac_stations_reset_station(struct ac_station* station, struct ac_wlan* wlan) {
	ASSERT(station != NULL);
	ASSERT(wlan != NULL);

	/* Remove reference from current WLAN */
	if (station->wlan) {
		capwap_itemlist_remove(station->wlan->stations, station->wlanitem);
	}

	/* Set WLAN */
	station->wlan = wlan;
	capwap_itemlist_insert_after(wlan->stations, NULL, station->wlanitem);
}

/* */
void ac_wlans_init(struct ac_session_t* session) {
	ASSERT(session != NULL);

	/* */
	session->wlans = (struct ac_wlans*)capwap_alloc(sizeof(struct ac_wlans));
	memset(session->wlans, 0, sizeof(struct ac_wlans));

	/* */
	session->wlans->stations = capwap_hash_create(AC_WLANS_STATIONS_HASH_SIZE, AC_WLANS_STATIONS_KEY_SIZE, ac_wlans_item_gethash, NULL, NULL);
}

/* */
void ac_wlans_destroy(struct ac_session_t* session) {
	int i;
	struct capwap_list* items;

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);

	/* */
	for (i = 0; i < RADIOID_MAX_COUNT; i++) {
		if (session->wlans->wlans[i]) {
			items = session->wlans->wlans[i];

			/* Delete WLANS */
			while (items->first) {
				ac_wlans_delete_bssid(session, i + 1, ((struct ac_wlan*)items->first->item)->bssid);
			}

			/* */
			capwap_list_free(items); 
		} 
	}

	/* */
	ASSERT(session->wlans->stations->count == 0);

	/* */
	capwap_hash_free(session->wlans->stations);
	capwap_free(session->wlans);
}

/* */
struct ac_wlan* ac_wlans_create_bssid(struct ac_session_t* session, uint8_t radioid, uint8_t wlanid, const uint8_t* bssid) {
	struct ac_wlan* wlan;
	struct capwap_list_item* wlanitem;

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(IS_VALID_WLANID(wlanid));
	ASSERT(bssid != NULL);

	/* */
	wlanitem = capwap_itemlist_create(sizeof(struct ac_wlan));
	wlan = (struct ac_wlan*)wlanitem->item;
	memset(wlan, 0, sizeof(struct ac_wlan));

	/* Init WLAN */
	memcpy(wlan->bssid, bssid, MACADDRESS_EUI48_LENGTH);
	wlan->radioid = radioid;
	wlan->wlanid = wlanid;
	wlan->stations = capwap_list_create();

	/* Create WLAN list */
	if (!session->wlans->wlans[radioid - 1]) {
		session->wlans->wlans[radioid - 1] = capwap_list_create();
	}

	/* Append WLAN to list */
	capwap_itemlist_insert_after(session->wlans->wlans[radioid - 1], NULL, wlanitem);

	return wlan;
}

/* */
struct ac_wlan* ac_wlans_get_bssid(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid) {
	struct capwap_list_item* search;
	struct ac_wlan* wlan = NULL;

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(bssid != NULL);

	/* */
	if (session->wlans->wlans[radioid - 1]) {
		search = session->wlans->wlans[radioid - 1]->first;
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
struct ac_wlan* ac_wlans_get_bssid_with_wlanid(struct ac_session_t* session, uint8_t radioid, uint8_t wlanid) {
	struct capwap_list_item* search;
	struct ac_wlan* wlan = NULL;

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(IS_VALID_WLANID(wlanid));

	/* */
	if (session->wlans->wlans[radioid - 1]) {
		search = session->wlans->wlans[radioid - 1]->first;
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
static void ac_wlans_destroy_bssid(struct ac_session_t* session, struct ac_wlan* wlan) {
	/* Free capability */
	if (wlan->key) {
		capwap_free(wlan->key);
	}

	if (wlan->ssid) {
		capwap_free(wlan->ssid);
	}

	/* Remove stations */
	while (wlan->stations->first) {
		ac_stations_destroy_station(session, (struct ac_station*)wlan->stations->first->item);
	}

	/* */
	capwap_list_free(wlan->stations);
}

/* */
void ac_wlans_delete_bssid(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid) {
	struct capwap_list_item* search;

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(bssid != NULL);

	/* */
	if (session->wlans->wlans[radioid - 1]) {
		search = session->wlans->wlans[radioid - 1]->first;
		while (search) {
			struct ac_wlan* item = (struct ac_wlan*)search->item;

			if (!memcmp(bssid, item->bssid, MACADDRESS_EUI48_LENGTH)) {
				ac_wlans_destroy_bssid(session, item);
				capwap_itemlist_free(capwap_itemlist_remove(session->wlans->wlans[radioid - 1], search));
				break;
			}

			/* Next */
			search = search->next;
		}
	}
}

/* */
void ac_wlans_set_bssid_capability(struct ac_wlan* wlan, struct capwap_80211_addwlan_element* addwlan) {
	ASSERT(wlan != NULL);
	ASSERT(addwlan != NULL);

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
}

/* */
struct ac_station* ac_stations_get_station(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid, const uint8_t* address) {
	struct ac_station* station;

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(bssid != NULL);
	ASSERT(address != NULL);

	/* Get station */
	station = (struct ac_station*)capwap_hash_search(session->wlans->stations, address);
	if (station && (radioid == station->wlan->radioid) && !memcmp(bssid, station->wlan->bssid, MACADDRESS_EUI48_LENGTH)) {
		return station;
	}

	return NULL;
}

/* */
struct ac_station* ac_stations_create_station(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid, const uint8_t* address) {
	char buffer1[CAPWAP_MACADDRESS_EUI48_BUFFER];
	char buffer2[CAPWAP_MACADDRESS_EUI48_BUFFER];
	struct ac_wlan* wlan;
	struct ac_session_t* ownersession;
	struct ac_station* station;
	struct capwap_list_item* stationitem;

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(bssid != NULL);
	ASSERT(address != NULL);

	/* */
	capwap_printf_macaddress(buffer1, bssid, MACADDRESS_EUI48_LENGTH);
	capwap_printf_macaddress(buffer2, address, MACADDRESS_EUI48_LENGTH);
	capwap_logging_info("Create station to radioid: %d, bssid: %s, station address: %s", (int)radioid, buffer1, buffer2);

	/* Get session that owns the station */
	capwap_rwlock_rdlock(&g_ac.stationslock);
	ownersession = (struct ac_session_t*)capwap_hash_search(g_ac.stations, address);
	capwap_rwlock_exit(&g_ac.stationslock);

	/* If request change owner of station */
	if (ownersession != session) {
		/* Release station from old owner */
		if (ownersession) {
			ac_session_send_action(ownersession, AC_SESSION_ACTION_ROAMING_STATION, 0, (void*)address, MACADDRESS_EUI48_LENGTH);
		}

		/* Set station into Global Cache Stations List */
		capwap_rwlock_wrlock(&g_ac.stationslock);
		capwap_hash_add(g_ac.stations, address, session);
		capwap_rwlock_exit(&g_ac.stationslock);
	}

	/* */
	wlan = ac_wlans_get_bssid(session, radioid, bssid);
	station = (struct ac_station*)capwap_hash_search(session->wlans->stations, address);
	if (!station) {
		stationitem = capwap_itemlist_create(sizeof(struct ac_station));
		station = (struct ac_station*)stationitem->item;
		memset(station, 0, sizeof(struct ac_station));

		/* */
		memcpy(station->address, address, MACADDRESS_EUI48_LENGTH);
		station->wlanitem = stationitem;

		/* */
		capwap_hash_add(session->wlans->stations, address, station);
	}

	/* Set station to WLAN */
	ac_stations_reset_station(station, wlan);

	return station;
}

/* */
void ac_stations_delete_station(struct ac_session_t* session, const uint8_t* address) {
	struct ac_station* station;

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);
	ASSERT(address != NULL);

	/* Delete station */
	station = (struct ac_station*)capwap_hash_search(session->wlans->stations, address);
	if (station) {
		ac_stations_destroy_station(session, station);
	}
}
