#include "ac.h"
#include "ac_session.h"
#include "ac_wlans.h"
#include "ac_backend.h"

/* */
static void ac_stations_reset_station(struct ac_session_t* session, struct ac_station* station, struct ac_wlan* wlan) {
	ASSERT(session != NULL);
	ASSERT(station != NULL);

	if (station->wlan) {
		if (station->aid) {
			if (station->wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
				ieee80211_aid_free(station->wlan->aidbitfield, station->aid);
			}

			station->aid = 0;
		}

		/* Remove reference from current WLAN */
		capwap_itemlist_remove(station->wlan->stations, station->wlanitem);
	}

	/* Remove timers */
	if (station->idtimeout != CAPWAP_TIMEOUT_INDEX_NO_SET) {
		capwap_timeout_deletetimer(session->timeout, station->idtimeout);
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
static void ac_stations_destroy_station(struct ac_session_t* session, struct ac_station* station) {
	struct ac_station* authoritativestation;

	ASSERT(session != NULL);
	ASSERT(station != NULL);

	/* */
	log_printf(LOG_INFO, "Destroy station: %s", station->addrtext);

	/* Remove reference from Authoritative Stations List */
	capwap_rwlock_wrlock(&g_ac.authstationslock);

	/* Can delete global reference only if match session handler */
	authoritativestation = (struct ac_station*)capwap_hash_search(g_ac.authstations, station->address);
	if (authoritativestation && (authoritativestation->session == session)) {
		capwap_hash_delete(g_ac.authstations, station->address);
	}

	capwap_rwlock_unlock(&g_ac.authstationslock);

	/* Remove reference from WLAN */
	ac_stations_reset_station(session, station, NULL);

	/* */
	capwap_hash_delete(session->wlans->stations, station->address);

	/* Free station reference with itemlist */
	capwap_itemlist_free(station->wlanitem);
}

/* */
static unsigned long ac_wlans_item_gethash(const void* key, unsigned long hashsize) {
	uint8_t* macaddress = (uint8_t*)key;

	return ((unsigned long)(macaddress[3] ^ macaddress[4] ^ macaddress[5]) % AC_WLANS_STATIONS_HASH_SIZE);
}

/* */
static const void* ac_wlans_item_getkey(const void* data) {
	return (const void*)((struct ac_station*)data)->address;
}

/* */
static int ac_wlans_item_cmp(const void* key1, const void* key2) {
	return memcmp(key1, key2, MACADDRESS_EUI48_LENGTH);
}

/* */
void ac_wlans_init(struct ac_session_t* session) {
	int i;

	ASSERT(session != NULL);
	ASSERT(session->wlans == NULL);

	/* */
	session->wlans = (struct ac_wlans*)capwap_alloc(sizeof(struct ac_wlans));
	memset(session->wlans, 0, sizeof(struct ac_wlans));

	/* */
	session->wlans->stations = capwap_hash_create(AC_WLANS_STATIONS_HASH_SIZE);
	session->wlans->stations->item_gethash = ac_wlans_item_gethash;
	session->wlans->stations->item_getkey = ac_wlans_item_getkey;
	session->wlans->stations->item_cmp = ac_wlans_item_cmp;
	
	for (i = 0; i < RADIOID_MAX_COUNT; i++) {
		session->wlans->devices[i].radioid = i + 1;
	}
}

/* */
void ac_wlans_destroy(struct ac_session_t* session) {
	int i;
	struct capwap_list* items;

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);

	/* */
	for (i = 0; i < RADIOID_MAX_COUNT; i++) {
		if (session->wlans->devices[i].wlans) {
			items = session->wlans->devices[i].wlans;

			/* Delete WLANS */
			while (items->first) {
				ac_wlans_delete_bssid(session, i + 1, ((struct ac_wlan*)items->first->item)->address);
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
int ac_wlans_assign_bssid(struct ac_session_t* session, struct ac_wlan* wlan) {
	char buffer[CAPWAP_MACADDRESS_EUI48_BUFFER];

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);
	ASSERT(wlan != NULL);
	ASSERT(wlan->device != NULL);
	ASSERT(IS_VALID_RADIOID(wlan->device->radioid));
	ASSERT(IS_VALID_WLANID(wlan->wlanid));

	/* */
	if (ac_wlans_get_bssid(session, wlan->device->radioid, wlan->address)) {
		return -1;
	}

	/* */
	wlan->session = session;

	/* Create WLAN list */
	if (!session->wlans->devices[wlan->device->radioid - 1].wlans) {
		session->wlans->devices[wlan->device->radioid - 1].wlans = capwap_list_create();
	}

	/* Append WLAN to list */
	capwap_itemlist_insert_after(session->wlans->devices[wlan->device->radioid - 1].wlans, NULL, wlan->wlanitem);

	/* */
	log_printf(LOG_INFO, "Added new wlan with radioid: %d, wlanid: %d, bssid: %s", (int)wlan->device->radioid, (int)wlan->wlanid, capwap_printf_macaddress(buffer, wlan->address, MACADDRESS_EUI48_LENGTH));
	return 0;
}

/* */
struct ac_wlan* ac_wlans_create_bssid(struct ac_device* device, uint8_t wlanid, const uint8_t* bssid, struct capwap_80211_addwlan_element* addwlan) {
	struct ac_wlan* wlan;
	struct capwap_list_item* wlanitem;

	ASSERT(device != NULL);
	ASSERT(IS_VALID_WLANID(wlanid));
	ASSERT(bssid != NULL);

	/* */
	wlanitem = capwap_itemlist_create(sizeof(struct ac_wlan));
	wlan = (struct ac_wlan*)wlanitem->item;
	memset(wlan, 0, sizeof(struct ac_wlan));

	/* Init WLAN */
	wlan->wlanitem = wlanitem;
	memcpy(wlan->address, bssid, MACADDRESS_EUI48_LENGTH);
	wlan->device = device;
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
	strcpy(wlan->ssid, (const char*)addwlan->ssid);

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
	if (session->wlans->devices[radioid - 1].wlans) {
		for (search = session->wlans->devices[radioid - 1].wlans->first; search; search = search->next) {
			struct ac_wlan* item = (struct ac_wlan*)search->item;

			if (!memcmp(bssid, item->address, MACADDRESS_EUI48_LENGTH)) {
				wlan = item;
				break;
			}
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
	if (session->wlans->devices[radioid - 1].wlans) {
		for (search = session->wlans->devices[radioid - 1].wlans->first; search; search = search->next) {
			struct ac_wlan* item = (struct ac_wlan*)search->item;

			if (wlanid == item->wlanid) {
				wlan = item;
				break;
			}
		}
	}

	return wlan;
}

/* */
void ac_wlans_free_bssid(struct ac_wlan* wlan) {
	ASSERT(wlan != NULL);

	/* Free capability */
	if (wlan->key) {
		capwap_free(wlan->key);
	}

	/* */
	capwap_list_free(wlan->stations);
	capwap_itemlist_free(wlan->wlanitem);
}

/* */
void ac_wlans_delete_bssid(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid) {
	struct capwap_list_item* search;

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(bssid != NULL);

	/* */
	if (session->wlans->devices[radioid - 1].wlans) {
		for (search = session->wlans->devices[radioid - 1].wlans->first; search; search = search->next) {
			struct ac_wlan* wlan = (struct ac_wlan*)search->item;

			if (!memcmp(bssid, wlan->address, MACADDRESS_EUI48_LENGTH)) {
				/* Remove stations */
				while (wlan->stations->first) {
					ac_stations_destroy_station(session, (struct ac_station*)wlan->stations->first->item);
				}

				/* */
				capwap_itemlist_remove(session->wlans->devices[radioid - 1].wlans, search);
				ac_wlans_free_bssid(wlan);
				break;
			}
		}
	}
}

/* */
struct ac_station* ac_stations_get_station(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid, const uint8_t* address) {
	struct ac_station* station;

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);
	ASSERT(address != NULL);

	/* Get station */
	station = (struct ac_station*)capwap_hash_search(session->wlans->stations, address);
	if (station && (station->flags & AC_STATION_FLAGS_ENABLED) && ((radioid == RADIOID_ANY) || (radioid == station->wlan->device->radioid)) && (!bssid || !memcmp(bssid, station->wlan->address, MACADDRESS_EUI48_LENGTH))) {
		return station;
	}

	return NULL;
}

/* */
struct ac_station* ac_stations_create_station(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid, const uint8_t* address) {
	char buffer1[CAPWAP_MACADDRESS_EUI48_BUFFER];
	char buffer2[CAPWAP_MACADDRESS_EUI48_BUFFER];
	struct ac_wlan* wlan;
	struct ac_station* authoritativestation;
	struct ac_station* station = NULL;
	struct ac_session_t* authoritativesession = NULL;

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(bssid != NULL);
	ASSERT(address != NULL);

	/* */
	capwap_printf_macaddress(buffer1, bssid, MACADDRESS_EUI48_LENGTH);
	capwap_printf_macaddress(buffer2, address, MACADDRESS_EUI48_LENGTH);
	log_printf(LOG_INFO, "Create station to radioid: %d, bssid: %s, station address: %s", (int)radioid, buffer1, buffer2);

	/* */
	wlan = ac_wlans_get_bssid(session, radioid, bssid);
	if (wlan) {
		station = (struct ac_station*)capwap_hash_search(session->wlans->stations, address);
		if (!station) {
			struct capwap_list_item* stationitem = capwap_itemlist_create(sizeof(struct ac_station));

			station = (struct ac_station*)stationitem->item;
			memset(station, 0, sizeof(struct ac_station));

			/* */
			station->idtimeout = CAPWAP_TIMEOUT_INDEX_NO_SET;
			memcpy(station->address, address, MACADDRESS_EUI48_LENGTH);
			capwap_printf_macaddress(station->addrtext, address, MACADDRESS_EUI48_LENGTH);
			station->wlanitem = stationitem;
			station->session = session;

			/* */
			capwap_hash_add(session->wlans->stations, (void*)station);
		}

		/* Set station to WLAN */
		ac_stations_reset_station(session, station, wlan);
		station->flags |= AC_STATION_FLAGS_ENABLED;

		/* Check Authoritative Stations List */
		capwap_rwlock_rdlock(&g_ac.authstationslock);

		authoritativestation = (struct ac_station*)capwap_hash_search(g_ac.authstations, address);
		if (authoritativestation && authoritativestation->session) {
			authoritativesession = authoritativestation->session;
		}

		capwap_rwlock_unlock(&g_ac.authstationslock);

		/* Check Authoritative Session */
		if (authoritativesession != session) {
			/* Update Authoritative Stations List */
			capwap_rwlock_wrlock(&g_ac.authstationslock);
			capwap_hash_add(g_ac.authstations, (void*)station);
			capwap_rwlock_unlock(&g_ac.authstationslock);

			/* Release Station from old Authoritative Session */
			if (authoritativesession) {
				ac_session_send_action(authoritativesession, AC_SESSION_ACTION_STATION_ROAMING, 0, (void*)address, MACADDRESS_EUI48_LENGTH);
			}
		}
	} else {
		log_printf(LOG_WARNING, "Unable to find radioid: %d, bssid: %s", (int)radioid, buffer1);
	}

	return station;
}

/* */
void ac_stations_delete_station(struct ac_session_t* session, struct ac_station* station) {
	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);
	ASSERT(station != NULL);

	/* Deauthorize station */
	ac_stations_deauthorize_station(session, station);

	/* Destroy station reference */
	ac_stations_destroy_station(session, station);
}

/* */
void ac_stations_authorize_station(struct ac_session_t* session, struct ac_station* station) {
	struct ac_notify_station_configuration_ieee8011_add_station notify;

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);
	ASSERT(station != NULL);

	/* Active Station only if Authenticated, Associated and not Authorizated */
	if ((station->flags & AC_STATION_FLAGS_AUTHENTICATED) && (station->flags & AC_STATION_FLAGS_ASSOCIATE) && !(station->flags & AC_STATION_FLAGS_AUTHORIZED)) {
		memset(&notify, 0, sizeof(struct ac_notify_station_configuration_ieee8011_add_station));
		notify.radioid = station->wlan->device->radioid;
		memcpy(notify.address, station->address, MACADDRESS_EUI48_LENGTH);
		notify.wlanid = station->wlan->wlanid;
		notify.associationid = station->aid;
		notify.capabilities = station->capability;
		notify.supportedratescount = station->supportedratescount;
		memcpy(notify.supportedrates, station->supportedrates, station->supportedratescount);

		ac_session_send_action(session, AC_SESSION_ACTION_STATION_CONFIGURATION_IEEE80211_ADD_STATION, 0, &notify, sizeof(struct ac_notify_station_configuration_ieee8011_add_station));
	}
}

/* */
void ac_stations_deauthorize_station(struct ac_session_t* session, struct ac_station* station) {
	int responselength;
	uint8_t buffer[IEEE80211_MTU];
	struct ieee80211_deauthentication_params ieee80211_params;
	struct ac_notify_station_configuration_ieee8011_delete_station notify;

	ASSERT(session != NULL);
	ASSERT(session->wlans != NULL);
	ASSERT(station != NULL);

	if (station->flags & AC_STATION_FLAGS_AUTHORIZED) {
		/* Deauthorize station */
		memset(&notify, 0, sizeof(struct ac_notify_station_configuration_ieee8011_delete_station));
		notify.radioid = station->wlan->device->radioid;
		memcpy(notify.address, station->address, MACADDRESS_EUI48_LENGTH);

		/* */
		station->flags &= ~(AC_STATION_FLAGS_AUTHENTICATED | AC_STATION_FLAGS_ASSOCIATE | AC_STATION_FLAGS_AUTHORIZED);
		ac_session_send_action(session, AC_SESSION_ACTION_STATION_CONFIGURATION_IEEE80211_DELETE_STATION, 0, &notify, sizeof(struct ac_notify_station_configuration_ieee8011_delete_station));
	} else if (station->flags & AC_STATION_FLAGS_AUTHENTICATED) {
		/* Create deauthentication packet */
		memset(&ieee80211_params, 0, sizeof(struct ieee80211_deauthentication_params));
		memcpy(ieee80211_params.bssid, station->wlan->address, MACADDRESS_EUI48_LENGTH);
		memcpy(ieee80211_params.station, station->address, MACADDRESS_EUI48_LENGTH);
		ieee80211_params.reasoncode = IEEE80211_REASON_PREV_AUTH_NOT_VALID;

		/* */
		responselength = ieee80211_create_deauthentication(buffer, IEEE80211_MTU, &ieee80211_params);
		if (responselength > 0) {
			station->flags &= ~(AC_STATION_FLAGS_AUTHENTICATED | AC_STATION_FLAGS_ASSOCIATE);
			ac_kmod_send_data(&session->sessionid, station->wlan->device->radioid, session->binding, buffer, responselength);
		}
	}
}

/* */
void ac_stations_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	struct ac_station* station = (struct ac_station*)context;

	ASSERT(station != NULL);

	if (station->idtimeout == index) {
		switch (station->timeoutaction) {
			case AC_STATION_TIMEOUT_ACTION_DEAUTHENTICATE: {
				log_printf(LOG_WARNING, "The %s station has not completed the association in time", station->addrtext);
				ac_stations_delete_station((struct ac_session_t*)param, station);
				break;
			}
		}
	}
}
