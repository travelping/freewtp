#include "ac.h"
#include "ac_session.h"
#include "ac_wlans.h"

/* */
struct ac_wlans* ac_wlans_init(void) {
	struct ac_wlans* wlans;

	/* */
	wlans = (struct ac_wlans*)capwap_alloc(sizeof(struct ac_wlans));
	memset(wlans, 0, sizeof(struct ac_wlans));

	return wlans;
}

/* */
void ac_wlans_destroy(struct ac_wlans* wlans) {
	int i;

	ASSERT(wlans != NULL);

	/* */
	for (i = 0; i < RADIOID_MAX_COUNT; i++) {
		if (wlans->wlans[i]) {
			while (wlans->wlans[i]->first) {
				struct ac_wlan* wlan = (struct ac_wlan*)wlans->wlans[i]->first->item;

				/* Delete WLAN */
				ac_wlans_delete_bssid(wlans, i + 1, wlan->bssid);
			}
			
			/* TODO */
			capwap_list_free(wlans->wlans[i]);
		}
	}

	capwap_free(wlans);
}

/* */
struct ac_wlan* ac_wlans_create_bssid(struct ac_wlans* wlans, uint8_t radioid, uint8_t wlanid, uint8_t* bssid) {
	struct ac_wlan* wlan;
	struct capwap_list_item* wlanitem;

	ASSERT(wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(IS_VALID_WLANID(wlanid));
	ASSERT(bssid != NULL);

	/* */
	wlanitem = capwap_itemlist_create(sizeof(struct ac_wlan));
	wlan = (struct ac_wlan*)wlanitem->item;
	memset(wlan, 0, sizeof(struct ac_wlan));

	/* Init WLAN */
	memcpy(wlan->bssid, bssid, MACADDRESS_EUI48_LENGTH);
	wlan->wlanid = wlanid;
	wlan->stations = capwap_list_create();

	/* Create WLAN list */
	if (!wlans->wlans[radioid - 1]) {
		wlans->wlans[radioid - 1] = capwap_list_create();
	}

	/* Append WLAN to list */
	capwap_itemlist_insert_after(wlans->wlans[radioid - 1], NULL, wlanitem);

	return wlan;
}

/* */
struct ac_wlan* ac_wlans_get_bssid(struct ac_wlans* wlans, uint8_t radioid, uint8_t* bssid) {
	struct capwap_list_item* search;
	struct ac_wlan* wlan = NULL;

	ASSERT(wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(bssid != NULL);

	/* */
	if (wlans->wlans[radioid - 1]) {
		search = wlans->wlans[radioid - 1]->first;
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
struct ac_wlan* ac_wlans_get_bssid_with_wlanid(struct ac_wlans* wlans, uint8_t radioid, uint8_t wlanid) {
	struct capwap_list_item* search;
	struct ac_wlan* wlan = NULL;

	ASSERT(wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(IS_VALID_WLANID(wlanid));

	/* */
	if (wlans->wlans[radioid - 1]) {
		search = wlans->wlans[radioid - 1]->first;
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
static void ac_wlans_destroy_bssid(struct ac_wlan* wlan) {
	/* Free capability */
	if (wlan->key) {
		capwap_free(wlan->key);
	}

	if (wlan->ssid) {
		capwap_free(wlan->ssid);
	}

	/* Remove stations */
	capwap_list_free(wlan->stations);
}

/* */
void ac_wlans_delete_bssid(struct ac_wlans* wlans, uint8_t radioid, uint8_t* bssid) {
	struct capwap_list_item* search;

	ASSERT(wlans != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(bssid != NULL);

	/* */
	if (wlans->wlans[radioid - 1]) {
		search = wlans->wlans[radioid - 1]->first;
		while (search) {
			struct ac_wlan* item = (struct ac_wlan*)search->item;

			if (!memcmp(bssid, item->bssid, MACADDRESS_EUI48_LENGTH)) {
				ac_wlans_destroy_bssid(item);
				capwap_itemlist_free(capwap_itemlist_remove(wlans->wlans[radioid - 1], search));
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
