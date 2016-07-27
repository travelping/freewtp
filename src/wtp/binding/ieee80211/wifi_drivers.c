#include "wtp.h"
#include "capwap_list.h"
#include "capwap_element.h"
#include "wifi_drivers.h"
#include "wtp_radio.h"
#include "wtp_kmod.h"

/* Declare enable wifi driver */
#ifdef ENABLE_WIFI_DRIVERS_NL80211
extern struct wifi_driver_ops wifi_driver_nl80211_ops;
#endif

static struct wifi_driver_instance wifi_driver[] = {
#ifdef ENABLE_WIFI_DRIVERS_NL80211
	{ &wifi_driver_nl80211_ops, NULL },
#endif
	{ NULL, NULL }
};

/* */
#define WIFI_STATIONS_HASH_SIZE								256

/* Wifi Manager */
static struct wifi_global g_wifiglobal;
static uint8_t g_bufferIEEE80211[IEEE80211_MTU];

/* */
static void wifi_wlan_deauthentication_station(struct wifi_wlan* wlan,
					       struct wifi_station* station,
					       uint16_t reasoncode);
static void wifi_wlan_send_mgmt_deauthentication(struct wifi_wlan* wlan,
						 const uint8_t* station,
						 uint16_t reasoncode);
static void wifi_wlan_disassociate_station(struct wifi_wlan* wlan,
					   struct wifi_station* station,
					   uint16_t reasoncode);
static void wifi_wlan_send_mgmt_disassociation(struct wifi_wlan* wlan,
					       const uint8_t* station,
					       uint16_t reasoncode);

/* device operations */
static int device_init(struct wifi_driver_instance *instance, struct wifi_device* device)
{
	return instance->ops->device_init(instance->handle, device);
}

static int device_getcapability(struct wifi_device* device, struct wifi_capability* capability)
{
	return device->instance->ops->device_getcapability(device, device->capability);
}

static void device_updatebeacons(struct wifi_device* device)
{
	device->instance->ops->device_updatebeacons(device);
}

static int device_setfrequency(struct wifi_device* device)
{
	return device->instance->ops->device_setfrequency(device);
}

static int device_settxqueue(struct wifi_device* device, int queue, int aifs,
			     int cw_min, int cw_max, int txop)
{
	return device->instance->ops->device_settxqueue(device, queue, aifs,
							cw_min, cw_max, txop);
}

static void device_deinit(struct wifi_device* device)
{
	if (device->handle)
		device->instance->ops->device_deinit(device);
	device->handle = NULL;
}

static wifi_wlan_handle wlan_create(struct wifi_device* device, struct wifi_wlan* wlan)
{
	return wlan->device->instance->ops->wlan_create(device, wlan);
}

static int wlan_startap(struct wifi_wlan* wlan)
{
	return wlan->device->instance->ops->wlan_startap(wlan);
}

static void wlan_stopap(struct wifi_wlan* wlan)
{
	wlan->device->instance->ops->wlan_stopap(wlan);
}

static int wlan_sendframe(struct wifi_wlan* wlan,
			  uint8_t* frame, int length,
			  uint32_t frequency, uint32_t duration,
			  int offchannel_tx_ok, int no_cck_rate,
			  int no_wait_ack)
{
	return wlan->device->instance->ops->wlan_sendframe(wlan, frame, length,
							   frequency, duration,
							   offchannel_tx_ok, no_cck_rate,
							   no_wait_ack);
}

static void wlan_poll_station(struct wifi_wlan* wlan, const uint8_t* address, int qos)
{
	wlan->device->instance->ops->wlan_poll_station(wlan, address, qos);
}

static void wlan_delete(struct wifi_wlan* wlan)
{
	wlan->device->instance->ops->wlan_delete(wlan);
}

static int wlan_set_key(struct wifi_wlan* wlan,
			 uint32_t alg, const uint8_t *addr,
			 int key_idx, int set_tx,
			 const uint8_t *seq, size_t seq_len,
			 const uint8_t *key, size_t key_len)
{
	return wlan->device->instance->ops->wlan_set_key(wlan, alg, addr, key_idx, set_tx,
							 seq, seq_len, key, key_len);
}

static int station_authorize(struct wifi_wlan* wlan, struct wifi_station* station)
{
	return wlan->device->instance->ops->station_authorize(wlan, station);
}

static int station_deauthorize(struct wifi_wlan* wlan, const uint8_t* address)
{
	return wlan->device->instance->ops->station_deauthorize(wlan, address);
}

static int station_get_inact_sec(struct wifi_wlan* wlan, const uint8_t* address)
{
	return wlan->device->instance->ops->station_get_inact_sec(wlan, address);
}

/* */
static int wifi_frequency_to_radiotype(uint32_t freq)
{
	if ((freq >= 2412) && (freq <= 2472))
		return CAPWAP_RADIO_TYPE_80211G;
	else if (freq == 2484)
		return CAPWAP_RADIO_TYPE_80211B;
	else if ((freq >= 4915) && (freq <= 4980))
		return CAPWAP_RADIO_TYPE_80211A;
	else if ((freq >= 5035) && (freq <= 5825))
		return CAPWAP_RADIO_TYPE_80211A;

	return -1;
}

/* */
static void wifi_wlan_getrates(struct wifi_device* device,
			       uint8_t* rates, int ratescount,
			       struct device_setrates_params* device_params)
{
	int i, j, w;
	int radiotype;
	uint32_t mode = 0;
	const struct wifi_capability* capability;

	ASSERT(device != NULL);
	ASSERT(rates != NULL);
	ASSERT(ratescount > 0);
	ASSERT(device_params != NULL);

	/* */
	memset(device_params, 0, sizeof(struct device_setrates_params));

	/* Retrieve capability */
	capability = wifi_device_getcapability(device);
	if (!capability) {
		log_printf(LOG_DEBUG, "getrates: getcapability failed");
		return;
	}

	/* Get radio type for basic rate */
	radiotype = wifi_frequency_to_radiotype(device->currentfrequency.frequency);
	if (radiotype < 0) {
		log_printf(LOG_DEBUG, "getrates: no radiotype for freq %d",
			   device->currentfrequency.frequency);
		return;
	}
	log_printf(LOG_DEBUG, "getrates: radiotype %d, freq: %d",
		   radiotype, device->currentfrequency.frequency);

	log_printf(LOG_DEBUG, "getrates: Band %d", device->currentfrequency.band);

	/* Check type of rate mode */
	for (i = 0; i < ratescount; i++) {
		if (device->currentfrequency.band == WIFI_BAND_2GHZ) {
			if (IS_IEEE80211_RATE_B(rates[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211B;
			} else if (IS_IEEE80211_RATE_G(rates[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211G;
			} else if (IS_IEEE80211_RATE_N(rates[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211N;
			}
		} else if (device->currentfrequency.band == WIFI_BAND_5GHZ) {
			if (IS_IEEE80211_RATE_A(rates[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211A;
			} else if (IS_IEEE80211_RATE_N(rates[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211N;
			}
		}
	}

	log_printf(LOG_DEBUG, "getrates: Mode %d", mode);

#if 0
	/* WTF: the AC should know what it's doing and set those rate when it want's them */

	/* Add implicit 802.11b rate with only 802.11g rate */
	if ((device->currentfrequency.band == WIFI_BAND_2GHZ) &&
	    !(mode & CAPWAP_RADIO_TYPE_80211B) &&
	    (device->currentfrequency.mode & CAPWAP_RADIO_TYPE_80211B)) {
		device_params->supportedrates[device_params->supportedratescount++] = IEEE80211_RATE_1M;
		device_params->supportedrates[device_params->supportedratescount++] = IEEE80211_RATE_2M;
		device_params->supportedrates[device_params->supportedratescount++] = IEEE80211_RATE_5_5M;
		device_params->supportedrates[device_params->supportedratescount++] = IEEE80211_RATE_11M;
	}
#endif

	log_printf(LOG_DEBUG, "getrates: Bands Count %lu", capability->bands->count);

	/* Filter band */
	for (i = 0; i < capability->bands->count; i++) {
		struct wifi_band_capability* bandcap =
			(struct wifi_band_capability*)capwap_array_get_item_pointer(capability->bands, i);

		log_printf(LOG_DEBUG, "getrates: Bandcap Band %lu", bandcap->band);

		if (bandcap->band != device->currentfrequency.band)
			continue;

		for (j = 0; j < bandcap->rate->count; j++) {
			struct wifi_rate_capability* ratecapability =
				(struct wifi_rate_capability*)capwap_array_get_item_pointer(bandcap->rate, j);

			/* Validate rate */
			for (w = 0; w < ratescount; w++) {
				if (rates[w] == ratecapability->bitrate) {
					device_params->supportedrates[device_params->supportedratescount++] = ratecapability->bitrate;
					break;
				}
			}
		}
		break;
	}

	/* Apply basic rate */
	for (i = 0; i < device_params->supportedratescount; i++) {
		int is_basic = 0;

		switch (mode) {
		case CAPWAP_RADIO_TYPE_80211A:
			is_basic = IS_IEEE80211_BASICRATE_A(device_params->supportedrates[i]);
			break;

		case CAPWAP_RADIO_TYPE_80211B:
			is_basic = IS_IEEE80211_BASICRATE_B(device_params->supportedrates[i]);
			break;

		case CAPWAP_RADIO_TYPE_80211G:
			is_basic = IS_IEEE80211_BASICRATE_G(device_params->supportedrates[i]);
			break;

		case CAPWAP_RADIO_TYPE_80211B | CAPWAP_RADIO_TYPE_80211G:
			is_basic = IS_IEEE80211_BASICRATE_BG(device_params->supportedrates[i]);
			break;
		}

		if (is_basic) {
			device_params->basicrates[device_params->basicratescount++] =
				device_params->supportedrates[i];
			device_params->supportedrates[i] |= IEEE80211_BASICRATE;
		}
	}

	/* Add implicit 802.11n rate with only 802.11a/g rate */
	if (!(mode & CAPWAP_RADIO_TYPE_80211N) && (device->currentfrequency.mode & CAPWAP_RADIO_TYPE_80211N))
		device_params->supportedrates[device_params->supportedratescount++] = IEEE80211_RATE_80211N;
}

/* */
static unsigned long wifi_hash_station_gethash(const void* key, unsigned long hashsize)
{
	uint8_t* macaddress = (uint8_t*)key;

	return ((unsigned long)macaddress[3] ^ (unsigned long)macaddress[4] ^ (unsigned long)macaddress[5]);
}

/* */
static const void* wifi_hash_station_getkey(const void* data)
{
	return (const void*)((struct wifi_station*)data)->address;
}

/* */
static int wifi_hash_station_cmp(const void* key1, const void* key2)
{
	return memcmp(key1, key2, MACADDRESS_EUI48_LENGTH);
}

/* */
static void wifi_hash_station_free(void* data)
{
	struct wifi_station* station = (struct wifi_station*)data;

	ASSERT(data != NULL);

	/* */
	log_printf(LOG_INFO, "Destroy station: " MACSTR, MAC2STR(station->address));
	capwap_free(station);
}

/* */
static struct wifi_station* wifi_station_get(struct wifi_wlan* wlan, const uint8_t* address)
{
	struct wifi_station* station;

	ASSERT(address != NULL);

	/* Get station */
	station = (struct wifi_station*)capwap_hash_search(g_wifiglobal.stations, address);
	if (station && wlan && (station->wlan != wlan))
		return NULL;

	return station;
}

/* */
static void wifi_station_clean(struct wifi_station* station)
{
	int updatebeacons = 0;

	ASSERT(station != NULL);

	if (station->wlan) {
		struct wifi_wlan* wlan = station->wlan;

		/* Delete station into wireless driver */
		if (station->flags & WIFI_STATION_FLAGS_AUTHORIZED)
			station_deauthorize(wlan, station->address);

		if (station->aid && (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL)) {
			ieee80211_aid_free(wlan->aidbitfield, station->aid);
			station->aid = 0;
		}

		if (station->flags & WIFI_STATION_FLAGS_NON_ERP) {
			wlan->device->stationsnonerpcount--;
			if (!wlan->device->stationsnonerpcount)
				updatebeacons = 1;
		}

		if (station->flags & WIFI_STATION_FLAGS_NO_SHORT_SLOT_TIME) {
			wlan->device->stationsnoshortslottimecount--;
			if (!wlan->device->stationsnoshortslottimecount &&
			    (wlan->device->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G))
				updatebeacons = 1;
		}

		if (station->flags & WIFI_STATION_FLAGS_NO_SHORT_PREAMBLE) {
			wlan->device->stationsnoshortpreamblecount--;
			if (!wlan->device->stationsnoshortpreamblecount &&
			    (wlan->device->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G))
				updatebeacons = 1;
		}

		/* Update beacons */
		if (updatebeacons)
			device_updatebeacons(wlan->device);

		/* Disconnet from WLAN */
		wlan->stationscount--;
		station->wlan = NULL;
	}

	/* Remove timers */
	ev_timer_stop(EV_DEFAULT_UC_ &station->timeout);

	/* */
	station->flags = 0;
	station->supportedratescount = 0;
}

/* */
static void wifi_station_delete(struct wifi_station* station)
{
	ASSERT(station != NULL);

	/* */
	log_printf(LOG_INFO, "Delete station: " MACSTR, MAC2STR(station->address));

	/* */
	wifi_station_clean(station);

	/* Delay delete station */
	station->timeout_action = WIFI_STATION_TIMEOUT_ACTION_DELETE;
	station->timeout.repeat = WIFI_STATION_TIMEOUT_AFTER_DEAUTHENTICATED / 1000.0;
	ev_timer_again(EV_DEFAULT_UC_ &station->timeout);
}

/* */
static struct wifi_station* wifi_station_create(struct wifi_wlan* wlan, const uint8_t* address)
{
	struct wifi_station* station;

	ASSERT(wlan != NULL);
	ASSERT(address != NULL);

	/* */
	station = wifi_station_get(NULL, address);
	if (station) {
		wtp_kmod_del_station(wlan->radioid, address);

		if (station->wlan && (station->wlan != wlan)) {
			log_printf(LOG_INFO, "Roaming station: " MACSTR, MAC2STR(address));
			if (station->flags & WIFI_STATION_FLAGS_AUTHENTICATED)
				wifi_wlan_send_mgmt_deauthentication(station->wlan,
								     address,
								     IEEE80211_REASON_PREV_AUTH_NOT_VALID);
		}

		log_printf(LOG_INFO, "Reuse station: " MACSTR, MAC2STR(address));
		wifi_station_clean(station);
	}

	/* Checks if it has reached the maximum number of stations */
	if (wlan->stationscount >= wlan->maxstationscount) {
		log_printf(LOG_WARNING, "Unable create station: reached the maximum number of stations");
		return NULL;
	}

	/* Create new station */
	if (!station) {
		log_printf(LOG_INFO, "Create new station: " MACSTR, MAC2STR(address));

		/* */
		station = (struct wifi_station*)capwap_alloc(sizeof(struct wifi_station));
		memset(station, 0, sizeof(struct wifi_station));

		/* Initialize station */
		memcpy(station->address, address, MACADDRESS_EUI48_LENGTH);

		/* Add to pool */
		capwap_hash_add(g_wifiglobal.stations, station);
	}

	/* Set station to WLAN */
	station->wlan = wlan;
	wlan->stationscount++;

	return station;
}

/* */
static void wifi_wlan_send_mgmt_deauthentication(struct wifi_wlan* wlan,
						 const uint8_t* station,
						 uint16_t reasoncode)
{
	int responselength;
	struct ieee80211_deauthentication_params ieee80211_params;

	/* Create deauthentication packet */
	memset(&ieee80211_params, 0, sizeof(struct ieee80211_deauthentication_params));
	memcpy(ieee80211_params.bssid, wlan->address, ETH_ALEN);
	memcpy(ieee80211_params.station, station, ETH_ALEN);
	ieee80211_params.reasoncode = reasoncode;

	responselength = ieee80211_create_deauthentication(g_bufferIEEE80211,
							   sizeof(g_bufferIEEE80211),
							   &ieee80211_params);
	if (responselength < 0) {
		log_printf(LOG_WARNING, "Unable to create IEEE802.11 Deauthentication "
			   "to " MACSTR " station", MAC2STR(station));
		return;
	}

	if (wlan_sendframe(wlan, g_bufferIEEE80211, responselength,
			   wlan->device->currentfrequency.frequency,
			   0, 0, 0, 0)) {
		log_printf(LOG_WARNING, "Unable to send IEEE802.11 Deauthentication "
			   "to " MACSTR " station", MAC2STR(station));
		return;
	}

	log_printf(LOG_INFO, "Sent IEEE802.11 Deauthentication to " MACSTR " station",
		   MAC2STR(station));

	/* Forwards the station deauthentication also to AC */
	wifi_wlan_send_frame(wlan, (uint8_t*)g_bufferIEEE80211, responselength, 0, 0, 0);
}

/* */
static void wifi_wlan_deauthentication_station(struct wifi_wlan* wlan,
					       struct wifi_station* station,
					       uint16_t reasoncode)
{
	ASSERT(wlan != NULL);
	ASSERT(station != NULL);

	/* Send deauthentication message */
	if (station->flags & WIFI_STATION_FLAGS_AUTHENTICATED)
		wifi_wlan_send_mgmt_deauthentication(wlan, station->address, reasoncode);

	/* delete station */
	wifi_station_delete(station);
}

/* */
static void wifi_wlan_send_mgmt_disassociation(struct wifi_wlan* wlan,
					       const uint8_t* station,
					       uint16_t reasoncode)
{
	int responselength;
	struct ieee80211_disassociation_params ieee80211_params;

	/* Create disassociation packet */
	memset(&ieee80211_params, 0, sizeof(struct ieee80211_disassociation_params));
	memcpy(ieee80211_params.bssid, wlan->address, ETH_ALEN);
	memcpy(ieee80211_params.station, station, ETH_ALEN);
	ieee80211_params.reasoncode = reasoncode;

	responselength = ieee80211_create_disassociation(g_bufferIEEE80211,
							 sizeof(g_bufferIEEE80211),
							 &ieee80211_params);
	if (responselength < 0) {
		log_printf(LOG_WARNING, "Unable to create IEEE802.11 Disassociation "
			   "to " MACSTR " station", MAC2STR(station));
		return;
	}

	if (wlan_sendframe(wlan, g_bufferIEEE80211, responselength,
			   wlan->device->currentfrequency.frequency,
			   0, 0, 0, 0)) {
		log_printf(LOG_WARNING, "Unable to send IEEE802.11 Disassociation "
			   "to " MACSTR " station", MAC2STR(station));
		return;
	}

	log_printf(LOG_INFO, "Sent IEEE802.11 Disassociation to " MACSTR " station",
		   MAC2STR(station));

	/* Forward the station disassociation also to AC */
	wifi_wlan_send_frame(wlan, (uint8_t*)g_bufferIEEE80211, responselength, 0, 0, 0);
}

/* */
static void wifi_wlan_disassociate_station(struct wifi_wlan* wlan,
					   struct wifi_station* station,
					   uint16_t reasoncode)
{
	ASSERT(wlan != NULL);
	ASSERT(station != NULL);

	/* Send deauthentication message */
	if (station->flags & WIFI_STATION_FLAGS_ASSOCIATE)
		wifi_wlan_send_mgmt_disassociation(wlan, station->address, reasoncode);
}

/* */
static void wifi_wlan_poll_station(struct wifi_wlan* wlan,
				   struct wifi_station* station)
{
	ASSERT(wlan != NULL);
	ASSERT(station != NULL);

	wlan_poll_station(wlan, station->address, station->flags & WIFI_STATION_FLAGS_WMM);
}

/* */
static void wifi_station_timeout(EV_P_ ev_timer *w, int revents)
{
	struct wifi_station *station = (struct wifi_station *)
		(((char *)w) - offsetof(struct wifi_station, timeout));
	struct wifi_wlan* wlan = (struct wifi_wlan *)w->data;
        unsigned long repeat = 0;

	log_printf(LOG_DEBUG, "%s: %s: " MACSTR " flags=0x%x timeout_action=%d",
                   wlan->virtname, __func__, MAC2STR(station->address), station->flags,
                   station->timeout_action);

        if (station->timeout_action == WIFI_STATION_TIMEOUT_ACTION_DELETE) {
		/* Free station into hash callback function */
		wifi_station_clean(station);
		capwap_hash_delete(g_wifiglobal.stations, station->address);
		return;
	}

        if ((station->flags & WIFI_STATION_FLAGS_ASSOCIATE) &&
            station->timeout_action == WIFI_STATION_TIMEOUT_ACTION_SEND_NULLFUNC) {
		int inactive_sec;

		inactive_sec = station_get_inact_sec(wlan, station->address);
		log_printf(LOG_WARNING, "Station " MACSTR ", inactive for %d seconds",
			   MAC2STR(station->address), inactive_sec);

                if (inactive_sec == -1) {
                        log_printf(LOG_DEBUG, "Check inactivity: Could not get station info "
				   "from kernel driver for " MACSTR, MAC2STR(station->address));
                        repeat = station->max_inactivity;
                } else if (inactive_sec == -ENOENT) {
                        log_printf(LOG_DEBUG, "Station " MACSTR " has lost its driver entry",
				   MAC2STR(station->address));

                        /* Avoid sending client probe on removed client */
                        station->timeout_action = WIFI_STATION_TIMEOUT_ACTION_DISASSOCIATE;
                        goto skip_poll;
                } else if (inactive_sec < station->max_inactivity) {
                        /* station activity detected; reset timeout state */
                        log_printf(LOG_DEBUG, "Station " MACSTR " has been active %is ago",
				   MAC2STR(station->address), inactive_sec);
                        station->timeout_action = WIFI_STATION_TIMEOUT_ACTION_SEND_NULLFUNC;
                        repeat = station->max_inactivity - inactive_sec;

			log_printf(LOG_DEBUG, "Station " MACSTR " has been inactive for: %d sec, max allowed: %d",
				   MAC2STR(station->address), inactive_sec, station->max_inactivity);

                } else {
                        log_printf(LOG_DEBUG, "Station " MACSTR " has been inactive too "
				   "long: %d sec, max allowed: %d",
				   MAC2STR(station->address), inactive_sec, station->max_inactivity);
		}
	}

        if ((station->flags & WIFI_STATION_FLAGS_ASSOCIATE) &&
            station->timeout_action == WIFI_STATION_TIMEOUT_ACTION_DISASSOCIATE &&
            !(station->flags & WIFI_STATION_FLAGS_POLL_PENDING)) {
                log_printf(LOG_DEBUG, "Station " MACSTR " has ACKed data poll",
			   MAC2STR(station->address));
                /* data nullfunc frame poll did not produce TX errors; assume
                 * station ACKed it */
                station->timeout_action = WIFI_STATION_TIMEOUT_ACTION_SEND_NULLFUNC;
                repeat = station->max_inactivity;
        }

skip_poll:
        if (repeat) {
                log_printf(LOG_DEBUG, "%s: register wifi_station_timeout for " MACSTR " (%lu seconds)",
                           __func__, MAC2STR(station->address), repeat);
		w->repeat = repeat;
		ev_timer_again(EV_A_ w);
                return;
        }

        if ((station->flags & WIFI_STATION_FLAGS_ASSOCIATE) &&
	    station->timeout_action == WIFI_STATION_TIMEOUT_ACTION_SEND_NULLFUNC) {
                log_printf(LOG_DEBUG, "  Polling STA");
                station->flags |= WIFI_STATION_FLAGS_POLL_PENDING;
                wifi_wlan_poll_station(wlan, station);
	} else if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL) {
		/* everything else means we go to remove the Station */
                int deauth = station->timeout_action == WIFI_STATION_TIMEOUT_ACTION_DEAUTHENTICATE;

                log_printf(LOG_DEBUG, "Timeout, sending %s info to STA " MACSTR,
			   deauth ? "deauthentication" : "disassociation", MAC2STR(station->address));

                if (deauth) {
			wifi_wlan_deauthentication_station(wlan, station, IEEE80211_REASON_PREV_AUTH_NOT_VALID);
                } else {
                        uint16_t reason =
				(station->timeout_action == WIFI_STATION_TIMEOUT_ACTION_DISASSOCIATE) ?
                                IEEE80211_REASON_DISASSOC_DUE_TO_INACTIVITY :
                                IEEE80211_REASON_PREV_AUTH_NOT_VALID;

			wifi_wlan_disassociate_station(wlan, station, reason);
                }
        } else if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT &&
		   station->timeout_action == WIFI_STATION_TIMEOUT_ACTION_DISASSOCIATE) {
		/*
		 * TODO: tell the AC about the STA timeout with a WTP Event
		 */
	}

	switch (station->timeout_action) {
        case WIFI_STATION_TIMEOUT_ACTION_SEND_NULLFUNC:
                station->timeout_action = WIFI_STATION_TIMEOUT_ACTION_DISASSOCIATE;
		w->repeat = WIFI_STATION_TIMEOUT_BEFORE_DISASSOCIATE / 1000.0;
                log_printf(LOG_DEBUG, "%s: register ap_handle_timer timeout for " MACSTR
			   " (%f seconds - TIMEOUT_BEFORE_DISASSOCIATE)",
                           __func__, MAC2STR(station->address), w->repeat);
		ev_timer_again(EV_A_ w);
                break;

        case WIFI_STATION_TIMEOUT_ACTION_DISASSOCIATE:
                station->timeout_action = WIFI_STATION_TIMEOUT_ACTION_DEAUTHENTICATE;
		w->repeat = WIFI_STATION_TIMEOUT_BEFORE_DEAUTHENTICATE / 1000.0;
                log_printf(LOG_DEBUG, "%s: register ap_handle_timer timeout for " MACSTR
			   " (%f seconds - TIMEOUT_BEFORE_DEAUTHENTICATE)",
                           __func__, MAC2STR(station->address), w->repeat);
		ev_timer_again(EV_A_ w);
		break;

        case WIFI_STATION_TIMEOUT_ACTION_DEAUTHENTICATE:
                log_printf(LOG_DEBUG, MACSTR " deauthenticated due to inactivity (timer DEAUTH/REMOVE)",
			   MAC2STR(station->address));
                break;

	default:
		break;
        }
}

/* */
void wifi_wlan_client_probe_event(struct wifi_wlan *wlan, const uint8_t *address)
{
	struct wifi_station* station;

	station = wifi_station_get(wlan, address);
	if (!station)
		return;

	if (!(station->flags & WIFI_STATION_FLAGS_POLL_PENDING))
		return;

	log_printf(LOG_DEBUG, "STA " MACSTR " ACKed pending "
                   "activity poll", MAC2STR(station->address));
	station->flags &= ~WIFI_STATION_FLAGS_POLL_PENDING;
}

/* */
static void wifi_wlan_receive_station_mgmt_probe_request(struct wifi_wlan* wlan,
							 const struct ieee80211_header_mgmt* frame,
							 int length, uint8_t rssi,
							 uint8_t snr, uint16_t rate)
{
	int ielength;
	int ssidcheck;
	int nowaitack;
	int responselength;
	struct ieee80211_ie_items ieitems;
	struct ieee80211_probe_response_params params;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->proberequest));
	if (ielength < 0)
		return;

	/* Parsing Information Elements */
	if (ieee80211_retrieve_information_elements_position(&ieitems,
							     &frame->proberequest.ie[0],
							     ielength)) {
                log_printf(LOG_DEBUG, "Could not parse ProbeReq from " MACSTR, MAC2STR(frame->sa));
		return;
	}

	/* Validate Probe Request Packet */
	if (!ieitems.ssid || !ieitems.supported_rates) {
		log_printf(LOG_DEBUG, "STA " MACSTR " sent probe request "
			   "without SSID or supported rates element", MAC2STR(frame->sa));
		return;
	}

       /* Don't reply to Probe Requests on an adjacent channel. */
	if (ieitems.dsss &&
	    (wlan->device->currentfrequency.mode & (CAPWAP_RADIO_TYPE_80211B | CAPWAP_RADIO_TYPE_80211G)) &&
	    wlan->device->currentfrequency.channel != ieitems.dsss->channel) {
		log_printf(LOG_DEBUG,
			   "Ignore Probe Request due to DS Params mismatch: chan=%u != ds.chan=%u",
			   wlan->device->currentfrequency.channel, ieitems.dsss->channel);
		return;
	}

	/* Verify the SSID */
	ssidcheck = ieee80211_is_valid_ssid(wlan->ssid, ieitems.ssid, ieitems.ssid_list);
	switch (ssidcheck) {
	case IEEE80211_WRONG_SSID:
		return;

	case IEEE80211_WILDCARD_SSID:
		if (wlan->ssid_hidden) {
			log_printf(LOG_DEBUG, "Probe Request from " MACSTR " for "
				   "broadcast SSID ignored", MAC2STR(frame->sa));
			return;
		}
		break;

	default:
		break;
	}

	/* Create probe response */
	memset(&params, 0, sizeof(struct ieee80211_probe_response_params));
	memcpy(params.bssid, wlan->address, MACADDRESS_EUI48_LENGTH);
	memcpy(params.station, frame->sa, MACADDRESS_EUI48_LENGTH);
	params.beaconperiod = wlan->device->beaconperiod;
	params.capability = wifi_wlan_check_capability(wlan, wlan->capability);
	params.ssid = wlan->ssid;
	memcpy(params.supportedrates, wlan->device->supportedrates, wlan->device->supportedratescount);
	params.supportedratescount = wlan->device->supportedratescount;
	params.mode = wlan->device->currentfrequency.mode;
	params.erpinfo = ieee80211_get_erpinfo(wlan->device->currentfrequency.mode,
					       wlan->device->olbc, wlan->device->stationsnonerpcount,
					       wlan->device->stationsnoshortpreamblecount,
					       wlan->device->shortpreamble);
	params.channel = wlan->device->currentfrequency.channel;
	params.response_ies = wlan->response_ies;
	params.response_ies_len = wlan->response_ies_len;

	responselength = ieee80211_create_probe_response(g_bufferIEEE80211,
							 sizeof(g_bufferIEEE80211), &params);
	if (responselength < 0)
		return;

	/* Send probe response */
	nowaitack = ((ssidcheck == IEEE80211_WILDCARD_SSID) &&
		     ieee80211_is_broadcast_addr(frame->da) ? 1 : 0);
	if (wlan_sendframe(wlan, g_bufferIEEE80211, responselength,
			   wlan->device->currentfrequency.frequency,
			   0, 0, 0, nowaitack)) {
		log_printf(LOG_WARNING, "Unable to send IEEE802.11 Probe Response");
		return;
	}

	/* If enable Split Mac send the probe request message to AC */
	if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT)
		wifi_wlan_send_frame(wlan, (uint8_t*)frame, length, rssi, snr, rate);
}

/* */
static void wifi_wlan_management_legacy_station(struct wifi_wlan* wlan, struct wifi_station* station)
{
	int updatebeacons = 0;

	/* Check NON ERP */
	if (wlan->device->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G) {
		int i;
		int stationnonerp = 1;

		for (i = 0; i < station->supportedratescount; i++) {
			if (IS_IEEE80211_RATE_G(station->supportedrates[i])) {
				stationnonerp = 0;
				break;
			}
		}

		if (stationnonerp) {
			station->flags |= WIFI_STATION_FLAGS_NON_ERP;
			wlan->device->stationsnonerpcount++;
			if (wlan->device->stationsnonerpcount == 1)
				updatebeacons = 1;
		}
	}

	/* Check short slot capability */
	if (!(station->capability & IEEE80211_CAPABILITY_SHORTSLOTTIME)) {
		station->flags |= WIFI_STATION_FLAGS_NO_SHORT_SLOT_TIME;
		wlan->device->stationsnoshortslottimecount++;
		if ((wlan->device->stationsnoshortslottimecount == 1) &&
		    (wlan->device->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G))
			updatebeacons = 1;
	}

	/* Check short preamble capability */
	if (!(station->capability & IEEE80211_CAPABILITY_SHORTPREAMBLE)) {
		station->flags |= WIFI_STATION_FLAGS_NO_SHORT_PREAMBLE;
		wlan->device->stationsnoshortpreamblecount++;
		if ((wlan->device->stationsnoshortpreamblecount == 1) &&
		    (wlan->device->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G))
			updatebeacons = 1;
	}

	/* Update beacon */
	if (updatebeacons)
		device_updatebeacons(wlan->device);
}

/* */
static int wifi_wlan_get_station_rates(struct wifi_station* station,
				       struct ieee80211_ie_items* ieitems)
{
	if (!ieitems->supported_rates)
		return -1;

	if (ieitems->extended_supported_rates &&
	    (ieitems->supported_rates->len +
	     ieitems->extended_supported_rates->len) > sizeof(station->supportedrates))
		return -1;

	/* */
	station->supportedratescount = ieitems->supported_rates->len;
	memcpy(station->supportedrates, ieitems->supported_rates->rates, ieitems->supported_rates->len);
	if (ieitems->extended_supported_rates) {
		station->supportedratescount += ieitems->extended_supported_rates->len;
		memcpy(&station->supportedrates[ieitems->supported_rates->len],
		       ieitems->extended_supported_rates->rates,
		       ieitems->extended_supported_rates->len);
	}

	return 0;
}

/* */
static void
wifi_wlan_receive_station_mgmt_authentication(struct wifi_wlan* wlan,
					      const struct ieee80211_header_mgmt* frame,
					      int length, uint8_t rssi,
					      uint8_t snr, uint16_t rate)
{
	int acl;
	int ielength;
	struct ieee80211_ie_items ieitems;
	int responselength;
	struct ieee80211_authentication_params ieee80211_params;
	struct wifi_station* station;
	uint16_t responsestatuscode;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->authetication));
	if (ielength < 0) {
		log_printf(LOG_INFO, "Receive invalid IEEE802.11 Authentication Request");
		return;
	}

	/* Ignore authentication packet from same AP */
	if (!memcmp(frame->sa, wlan->address, MACADDRESS_EUI48_LENGTH)) {
		log_printf(LOG_INFO, "Ignore IEEE802.11 Authentication Request from same AP");
		return;
	}

	/* Get ACL Station */
	acl = wtp_radio_acl_station(frame->sa);
	if (acl == WTP_RADIO_ACL_STATION_DENY) {
		log_printf(LOG_INFO, "Denied IEEE802.11 Authentication Request "
			   "from " MACSTR " station", MAC2STR(frame->sa));
		return;
	}

	/* Parsing Information Elements */
	if (ieee80211_retrieve_information_elements_position(&ieitems, &frame->authetication.ie[0], ielength)) {
		log_printf(LOG_INFO, "Invalid IEEE802.11 Authentication Request "
			   "from " MACSTR " station", MAC2STR(frame->sa));
		return;
	}

	/* */
	log_printf(LOG_INFO, "Receive IEEE802.11 Authentication Request "
		   "from " MACSTR " station", MAC2STR(frame->sa));

	/* Create station reference */
	station = wifi_station_create(wlan, frame->sa);
	if (station) {
		/* A station is removed if the association does not complete within a given period of time */
		ev_timer_stop(EV_DEFAULT_UC_ &station->timeout);
		ev_timer_init(&station->timeout, wifi_station_timeout,
			      WIFI_STATION_TIMEOUT_ASSOCIATION_COMPLETE / 1000.0, 0.);
		station->timeout.data = wlan;
		station->timeout_action = WIFI_STATION_TIMEOUT_ACTION_DEAUTHENTICATE;
		ev_timer_start(EV_DEFAULT_UC_ &station->timeout);
		responsestatuscode = IEEE80211_STATUS_SUCCESS;
	} else {
		responsestatuscode = IEEE80211_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
	}

	/* */
	if ((responsestatuscode != IEEE80211_STATUS_SUCCESS) ||
	    (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL)) {
		uint16_t algorithm = __le16_to_cpu(frame->authetication.algorithm);
		uint16_t transactionseqnumber = __le16_to_cpu(frame->authetication.transactionseqnumber);

		/* Check authentication algorithm */
		if (responsestatuscode == IEEE80211_STATUS_SUCCESS) {
			responsestatuscode = IEEE80211_STATUS_NOT_SUPPORTED_AUTHENTICATION_ALGORITHM;
			if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_OPEN) &&
			    (wlan->authmode == CAPWAP_ADD_WLAN_AUTHTYPE_OPEN)) {
				if (transactionseqnumber == 1) {
					responsestatuscode = IEEE80211_STATUS_SUCCESS;
					station->authalgorithm = IEEE80211_AUTHENTICATION_ALGORITHM_OPEN;
				} else {
					responsestatuscode =
						IEEE80211_STATUS_UNKNOWN_AUTHENTICATION_TRANSACTION;
				}
			} else if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_SHARED_KEY) &&
				   (wlan->authmode == CAPWAP_ADD_WLAN_AUTHTYPE_WEP)) {
				/* TODO */
			}
		}

		/* Create authentication packet */
		memset(&ieee80211_params, 0, sizeof(struct ieee80211_authentication_params));
		memcpy(ieee80211_params.bssid, wlan->address, MACADDRESS_EUI48_LENGTH);
		memcpy(ieee80211_params.station, frame->sa, MACADDRESS_EUI48_LENGTH);
		ieee80211_params.algorithm = algorithm;
		ieee80211_params.transactionseqnumber = transactionseqnumber + 1;
		ieee80211_params.statuscode = responsestatuscode;

		responselength = ieee80211_create_authentication_response(g_bufferIEEE80211,
									  sizeof(g_bufferIEEE80211),
									  &ieee80211_params);
		if (responselength < 0) {
			log_printf(LOG_WARNING, "Unable to create IEEE802.11 Authentication Response "
				   "to " MACSTR " station", MAC2STR(frame->sa));
			goto out_delete_station;
		}

		/* Send authentication response */
		if (wlan_sendframe(wlan, g_bufferIEEE80211, responselength,
				   wlan->device->currentfrequency.frequency,
				   0, 0, 0, 0)) {
			log_printf(LOG_WARNING, "Unable to send IEEE802.11 Authentication Response "
				   "to " MACSTR " station", MAC2STR(frame->sa));
			goto out_delete_station;
		}

		log_printf(LOG_INFO, "Sent IEEE802.11 Authentication Response "
			   "to " MACSTR " station with %d status code",
			   MAC2STR(frame->sa), (int)responsestatuscode);

		/* Notify authentication request message also to AC */
		wifi_wlan_send_frame(wlan, (uint8_t*)frame, length, rssi, snr, rate);

		/* Forwards the authentication response message also to AC */
		wifi_wlan_send_frame(wlan, (uint8_t*)g_bufferIEEE80211, responselength, 0, 0, 0);
	}
	else if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT)
		wifi_wlan_send_frame(wlan, (uint8_t*)frame, length, rssi, snr, rate);

	return;

out_delete_station:
	if (station)
		wifi_station_delete(station);
	return;
}

/* */
static void
wifi_wlan_receive_station_mgmt_association_request(struct wifi_wlan* wlan,
						   const struct ieee80211_header_mgmt* frame,
						   int length, uint8_t rssi,
						   uint8_t snr, uint16_t rate)
{
	int ielength;
	int responselength;
	struct ieee80211_ie_items ieitems;
	struct ieee80211_associationresponse_params params;
	struct wifi_station* station;
	uint16_t resultstatuscode;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->associationrequest));
	if (ielength < 0) {
		log_printf(LOG_INFO, "Receive invalid IEEE802.11 Association Request");
		return;
	}

	/* Get station reference */
	station = wifi_station_get(wlan, frame->sa);
	if (!station) {
		/* Invalid station, send deauthentication message */
		log_printf(LOG_INFO, "Receive IEEE802.11 Association Request "
			   "from " MACSTR " unknown station", MAC2STR(frame->sa));
		wifi_wlan_send_mgmt_deauthentication(wlan, frame->sa,
						     IEEE80211_REASON_CLASS2_FRAME_FROM_NONAUTH_STA);
		return;
	}

	/* */
	if (!(station->flags & WIFI_STATION_FLAGS_AUTHENTICATED)) {
		/* Invalid station, send deauthentication message */
		log_printf(LOG_INFO, "Receive IEEE802.11 Association Request "
			   "from " MACSTR " unauthorized station", MAC2STR(station->address));
		wifi_wlan_deauthentication_station(wlan, station,
						   IEEE80211_REASON_CLASS2_FRAME_FROM_NONAUTH_STA);
		return;
	}

	/* Parsing Information Elements */
	if (ieee80211_retrieve_information_elements_position(&ieitems,
							     &frame->associationrequest.ie[0],
							     ielength)) {
		log_printf(LOG_INFO, "Invalid IEEE802.11 Association Request "
			   "from " MACSTR " station", MAC2STR(station->address));
		wifi_wlan_deauthentication_station(wlan, station, IEEE80211_REASON_PREV_AUTH_NOT_VALID);
		return;
	}

	/* */
	log_printf(LOG_INFO, "Receive IEEE802.11 Association Request "
		   "from " MACSTR " station", MAC2STR(station->address));

	if (ieitems.wmm_ie != NULL && ieitems.wmm_ie->version == 1) {
		station->flags |= WIFI_STATION_FLAGS_WMM;
		station->qosinfo = ieitems.wmm_ie->qos_info;
	}

	/* */
	switch(wlan->macmode) {
	case CAPWAP_ADD_WLAN_MACMODE_LOCAL:
		/* Verify SSID */
		if (ieee80211_is_valid_ssid(wlan->ssid, ieitems.ssid, NULL) == IEEE80211_VALID_SSID) {
			station->capability = __le16_to_cpu(frame->associationrequest.capability);
			station->listeninterval = __le16_to_cpu(frame->associationrequest.listeninterval);
			if (!ieee80211_aid_create(wlan->aidbitfield, &station->aid)) {
				/* Get supported rates */
				if (!wifi_wlan_get_station_rates(station, &ieitems)) {
					wifi_wlan_management_legacy_station(wlan, station);
					resultstatuscode = IEEE80211_STATUS_SUCCESS;
				} else {
					resultstatuscode = IEEE80211_STATUS_UNSPECIFIED_FAILURE;
				}
			} else {
				resultstatuscode = IEEE80211_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
			}
		} else {
			resultstatuscode = IEEE80211_STATUS_UNSPECIFIED_FAILURE;
		}

		/* Create association response packet */
		memset(&params, 0, sizeof(struct ieee80211_associationresponse_params));
		memcpy(params.bssid, wlan->address, ETH_ALEN);
		memcpy(params.station, frame->sa, ETH_ALEN);
		params.capability = wifi_wlan_check_capability(wlan, wlan->capability);
		params.statuscode = resultstatuscode;
		params.aid = IEEE80211_AID_FIELD | station->aid;
		memcpy(params.supportedrates, wlan->device->supportedrates,
		       wlan->device->supportedratescount);
		params.supportedratescount = wlan->device->supportedratescount;
		params.response_ies = wlan->response_ies;
		params.response_ies_len = wlan->response_ies_len;

		responselength = ieee80211_create_associationresponse_response(g_bufferIEEE80211,
									       sizeof(g_bufferIEEE80211),
									       &params);
		if (responselength < 0) {
			log_printf(LOG_WARNING, "Unable to create IEEE802.11 Association Response "
				   "to " MACSTR " station", MAC2STR(station->address));
			wifi_wlan_deauthentication_station(wlan, station,
							   IEEE80211_REASON_PREV_AUTH_NOT_VALID);
			break;
		}

		if (wlan_sendframe(wlan, g_bufferIEEE80211, responselength,
				   wlan->device->currentfrequency.frequency,
				   0, 0, 0, 0)) {
			log_printf(LOG_WARNING, "Unable to send IEEE802.11 Association Response "
				   "to " MACSTR " station", MAC2STR(station->address));
			wifi_wlan_deauthentication_station(wlan, station,
							   IEEE80211_REASON_PREV_AUTH_NOT_VALID);
		}

		log_printf(LOG_INFO, "Sent IEEE802.11 Association Response "
			   "to " MACSTR " station with %d status code",
			   MAC2STR(station->address), (int)resultstatuscode);

		/* Notify association request message also to AC */
		wifi_wlan_send_frame(wlan, (uint8_t*)frame, length, rssi, snr, rate);

		/* Forwards the association response message also to AC */
		wifi_wlan_send_frame(wlan, (uint8_t*)g_bufferIEEE80211, responselength, 0, 0, 0);

		break;

	case CAPWAP_ADD_WLAN_MACMODE_SPLIT:
		wifi_wlan_send_frame(wlan, (uint8_t*)frame, length, rssi, snr, rate);

		/* Station information */
		station->capability = __le16_to_cpu(frame->associationresponse.capability);
		station->listeninterval = __le16_to_cpu(frame->associationrequest.listeninterval);
		break;
	}
}

/* */
static void
wifi_wlan_receive_station_mgmt_reassociation_request(struct wifi_wlan* wlan,
						     const struct ieee80211_header_mgmt* frame,
						     int length, uint8_t rssi,
						     uint8_t snr, uint16_t rate)
{
	int ielength;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->reassociationrequest));
	if (ielength < 0)
		return;

	/* TODO */
}

/* */
static void
wifi_wlan_receive_station_mgmt_disassociation(struct wifi_wlan* wlan,
					      const struct ieee80211_header_mgmt* frame,
					      int length, uint8_t rssi,
					      uint8_t snr, uint16_t rate)
{
	int ielength;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->disassociation));
	if (ielength < 0)
		return;

	/* TODO */

	/* Notify disassociation message also to AC */
	wifi_wlan_send_frame(wlan, (uint8_t*)frame, length, rssi, snr, rate);
}

/* */
static void
wifi_wlan_receive_station_mgmt_deauthentication(struct wifi_wlan* wlan,
						const struct ieee80211_header_mgmt* frame,
						int length, uint8_t rssi,
						uint8_t snr, uint16_t rate)
{
	int ielength;
	struct wifi_station* station;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->deauthetication));
	if (ielength < 0)
		return;

	/* Delete station */
	station = wifi_station_get(wlan, frame->sa);
	if (station)
		wifi_station_delete(station);

	/* Notify deauthentication message also to AC */
	wifi_wlan_send_frame(wlan, (uint8_t*)frame, length, rssi, snr, rate);
}

/* */
static void
wifi_wlan_receive_station_mgmt_frame(struct wifi_wlan* wlan,
				     const struct ieee80211_header_mgmt* frame,
				     int length, uint16_t framecontrol_subtype,
				     uint32_t frequency, uint8_t rssi,
				     uint8_t snr, uint16_t rate)
{
	int broadcast;

	/* Check frequency */
	if (frequency && (wlan->device->currentfrequency.frequency != frequency))
		return;

	/* Check if sent packet to correct AP */
	broadcast = ieee80211_is_broadcast_addr(frame->bssid);
	if (!broadcast && memcmp(frame->bssid, wlan->address, MACADDRESS_EUI48_LENGTH) != 0)
		return;

	/* */
	if (framecontrol_subtype == IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_PROBE_REQUEST) {
		 wifi_wlan_receive_station_mgmt_probe_request(wlan, frame, length,
							      rssi, snr, rate);
	}
	else if (memcmp(frame->da, wlan->address, MACADDRESS_EUI48_LENGTH) == 0) {
		switch (framecontrol_subtype) {
		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTHENTICATION:
			wifi_wlan_receive_station_mgmt_authentication(wlan, frame, length,
								      rssi, snr, rate);
			break;

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_REQUEST:
			wifi_wlan_receive_station_mgmt_association_request(wlan, frame, length,
									   rssi, snr, rate);
			break;

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_REASSOCIATION_REQUEST:
			wifi_wlan_receive_station_mgmt_reassociation_request(wlan, frame, length,
									     rssi, snr, rate);
			break;

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DISASSOCIATION:
			wifi_wlan_receive_station_mgmt_disassociation(wlan, frame, length,
								      rssi, snr, rate);
			break;

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTHENTICATION:
			wifi_wlan_receive_station_mgmt_deauthentication(wlan, frame, length,
									rssi, snr, rate);
			break;

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ACTION:
			/* TODO */
			break;
		}
	}
}

/* */
static void
wifi_wlan_receive_station_mgmt_authentication_ack(struct wifi_wlan* wlan,
						  const struct ieee80211_header_mgmt* frame,
						  int length, int ack)
{
	uint16_t algorithm;
	uint16_t transactionseqnumber;
	uint16_t statuscode;
	struct wifi_station* station;

	/* Check packet */
	if (!ack || (length < (sizeof(struct ieee80211_header) + sizeof(frame->authetication))))
		return;

	/* Get station information */
	station = wifi_station_get(wlan, frame->da);
	if (!station)
		return;

	/* */
	statuscode = __le16_to_cpu(frame->authetication.statuscode);
	if (statuscode != IEEE80211_STATUS_SUCCESS)
		return;

	algorithm = __le16_to_cpu(frame->authetication.algorithm);
	transactionseqnumber = __le16_to_cpu(frame->authetication.transactionseqnumber);

	/* Check if authenticate */
	if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_OPEN) &&
	    (transactionseqnumber == 2)) {
		log_printf(LOG_INFO, "IEEE802.11 Authentication complete "
			   "to " MACSTR " station", MAC2STR(station->address));
		station->flags |= WIFI_STATION_FLAGS_AUTHENTICATED;
	} else if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_SHARED_KEY) &&
		   (transactionseqnumber == 4)) {
		/* TODO */
	}
}

/* */
static void
wifi_wlan_receive_station_mgmt_association_response_ack(struct wifi_wlan* wlan,
							const struct ieee80211_header_mgmt* frame,
							int length, int ack)
{
	uint16_t statuscode;
	struct wifi_station* station;

	/* Check packet */
	if (!ack || (length < (sizeof(struct ieee80211_header) + sizeof(frame->associationresponse))))
		return;

	/* Get station information */
	station = wifi_station_get(wlan, frame->da);
	if (!station)
		return;

	/* */
	statuscode = __le16_to_cpu(frame->associationresponse.statuscode);
	if (statuscode != IEEE80211_STATUS_SUCCESS)
		return;

	log_printf(LOG_INFO, "IEEE802.11 Association complete "
		   "to " MACSTR " station", MAC2STR(station->address));

	/* */
	station->flags |= WIFI_STATION_FLAGS_ASSOCIATE;
	if (station->flags & WIFI_STATION_FLAGS_AUTHORIZED) {
		int result;

		/* Apply authorization if Station already authorized */
		result = station_authorize(wlan, station);
		if (!result)
			result = wifi_station_set_key(wlan, station);
		if (result)
			wifi_wlan_deauthentication_station(wlan, station, IEEE80211_REASON_PREV_AUTH_NOT_VALID);
	}
}

/* */
static void
wifi_wlan_receive_station_mgmt_ackframe(struct wifi_wlan* wlan,
					const struct ieee80211_header_mgmt* frame,
					int length, uint16_t framecontrol_subtype, int ack)
{
	/* Ignore packet if not sent to AP */
	if (memcmp(frame->bssid, wlan->address, MACADDRESS_EUI48_LENGTH) != 0)
		return;

	/* */
	switch (framecontrol_subtype) {
	case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTHENTICATION:
		wifi_wlan_receive_station_mgmt_authentication_ack(wlan, frame, length, ack);
		break;

	case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_RESPONSE:
		wifi_wlan_receive_station_mgmt_association_response_ack(wlan, frame, length, ack);
		break;

	case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTHENTICATION:
		/* TODO */
		break;
	}
}

/* */
static int
wifi_wlan_receive_ac_mgmt_authentication(struct wifi_wlan* wlan,
					 struct ieee80211_header_mgmt* frame,
					 int length)
{
	int ielength;
	struct wifi_station* station;
	uint16_t statuscode;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->authetication));
	if (ielength < 0)
		return 0;

	if (wlan->macmode != CAPWAP_ADD_WLAN_MACMODE_SPLIT)
		return 0;

	station = wifi_station_get(wlan, frame->da);
	if (!station)
		return 0;

	statuscode = __le16_to_cpu(frame->authetication.statuscode);
	if (statuscode == IEEE80211_STATUS_SUCCESS) {
		uint16_t algorithm = __le16_to_cpu(frame->authetication.algorithm);
		uint16_t transactionseqnumber = __le16_to_cpu(frame->authetication.transactionseqnumber);

		/* Get authentication algorithm */
		if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_OPEN) &&
		    (transactionseqnumber == 2))
			station->authalgorithm = IEEE80211_AUTHENTICATION_ALGORITHM_OPEN;
		else if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_SHARED_KEY) &&
			   (transactionseqnumber == 4))
			station->authalgorithm = IEEE80211_AUTHENTICATION_ALGORITHM_SHARED_KEY;
	}

	return 1;
}

/* */
static int
wifi_wlan_receive_ac_mgmt_association_response(struct wifi_wlan* wlan,
					       struct ieee80211_header_mgmt* frame,
					       int length)
{
	int ielength;
	struct ieee80211_ie_items ieitems;
	struct wifi_station* station;
	uint16_t statuscode;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->associationresponse));
	if (ielength < 0)
		return 0;

	station = wifi_station_get(wlan, frame->da);
	if (!station)
		return 0;

	switch (wlan->macmode) {
	case CAPWAP_ADD_WLAN_MACMODE_LOCAL:
		if (frame->associationresponse.statuscode != IEEE80211_STATUS_SUCCESS) {
			log_printf(LOG_INFO, "AC request deauthentication of station: " MACSTR,
				   MAC2STR(station->address));
			wifi_wlan_deauthentication_station(wlan, station, IEEE80211_REASON_PREV_AUTH_NOT_VALID);
		}
		return 0;

	case CAPWAP_ADD_WLAN_MACMODE_SPLIT:
		statuscode = __le16_to_cpu(frame->associationresponse.statuscode);
		if ((statuscode == IEEE80211_STATUS_SUCCESS) &&
		    !ieee80211_retrieve_information_elements_position(&ieitems,
								      &frame->associationresponse.ie[0],
								      ielength)) {
			/* Station information */
			station->aid = (__le16_to_cpu(frame->associationresponse.aid) & ~IEEE80211_AID_FIELD);

			/* Get supported rates */
			wifi_wlan_get_station_rates(station, &ieitems);

			/* */
			wifi_wlan_management_legacy_station(wlan, station);

			/* Assign valid WLAN capability */
			frame->associationresponse.capability =
				__cpu_to_le16(wifi_wlan_check_capability(wlan, wlan->capability));
		}
		return 1;

	default:
		break;
	}
	return 0;
}

/* */
static int
wifi_wlan_receive_ac_mgmt_reassociation_response(struct wifi_wlan* wlan,
						 struct ieee80211_header_mgmt* frame,
						 int length)
{
	int ielength;
	struct wifi_station* station;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->reassociationresponse));
	if (ielength < 0)
		return 0;

	switch (wlan->macmode) {
	case CAPWAP_ADD_WLAN_MACMODE_SPLIT:
		station = wifi_station_get(wlan, frame->da);
		if (station) {
			/* TODO */
		}
	}

	return 0;
}

/* */
static int
wifi_wlan_receive_ac_mgmt_disassociation(struct wifi_wlan* wlan,
					 struct ieee80211_header_mgmt* frame,
					 int length)
{
	int ielength;
	struct wifi_station* station;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->disassociation));
	if (ielength < 0)
		return 0;

	/* */
	station = wifi_station_get(wlan, frame->da);
	if (station) {
		/* Deautherize station */
		if (station->flags & WIFI_STATION_FLAGS_AUTHORIZED) {
			station->flags &= ~WIFI_STATION_FLAGS_AUTHORIZED;
			station_deauthorize(wlan, station->address);
		}

		/* Deassociate station */
		station->flags &= ~WIFI_STATION_FLAGS_ASSOCIATE;
	}

	return 1;
}

/* */
static int
wifi_wlan_receive_ac_mgmt_deauthentication(struct wifi_wlan* wlan,
					   struct ieee80211_header_mgmt* frame,
					   int length)
{
	int ielength;
	struct wifi_station* station;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->deauthetication));
	if (ielength < 0)
		return 0;

	/* Delete station */
	station = wifi_station_get(wlan, frame->da);
	if (station)
		wifi_station_delete(station);

	return 1;
}

/* */
static int
wifi_wlan_receive_ac_mgmt_frame(struct wifi_wlan* wlan,
				struct ieee80211_header_mgmt* frame,
				int length,
				uint16_t framecontrol_subtype)
{
	switch (framecontrol_subtype) {
	case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTHENTICATION:
		return wifi_wlan_receive_ac_mgmt_authentication(wlan, frame, length);

	case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_RESPONSE:
		return wifi_wlan_receive_ac_mgmt_association_response(wlan, frame, length);

	case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_REASSOCIATION_RESPONSE:
		return wifi_wlan_receive_ac_mgmt_reassociation_response(wlan, frame, length);

	case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DISASSOCIATION:
		return wifi_wlan_receive_ac_mgmt_disassociation(wlan, frame, length);

	case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTHENTICATION:
		return wifi_wlan_receive_ac_mgmt_deauthentication(wlan, frame, length);
	}

	return 0;
}

/* */
int wifi_driver_init()
{
	int i;

	/* Socket utils */
	memset(&g_wifiglobal, 0, sizeof(struct wifi_global));
	g_wifiglobal.sock_util = socket(AF_PACKET, SOCK_RAW, 0);
	if (g_wifiglobal.sock_util < 0) {
		return -1;
	}

	/* Initialize driver */
	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		wifi_driver[i].handle = wifi_driver[i].ops->global_init();
		if (!wifi_driver[i].handle) {
			close(g_wifiglobal.sock_util);
			return -1;
		}
	}

	/* */
	g_wifiglobal.devices = capwap_list_create();
	g_wifiglobal.stations = capwap_hash_create(WIFI_STATIONS_HASH_SIZE);
	g_wifiglobal.stations->item_gethash = wifi_hash_station_gethash;
	g_wifiglobal.stations->item_getkey = wifi_hash_station_getkey;
	g_wifiglobal.stations->item_cmp = wifi_hash_station_cmp;
	g_wifiglobal.stations->item_free = wifi_hash_station_free;

	return 0;
}

/* */
void wifi_driver_free(void)
{
	int i;
	struct capwap_list_item* itemdevice;

	/* Free devices */
	if (g_wifiglobal.devices) {
		for (itemdevice = g_wifiglobal.devices->first;
		     itemdevice != NULL;
		     itemdevice = itemdevice->next) {
			struct wifi_device* device = (struct wifi_device*)itemdevice->item;

			/* Free WLANS */
			if (device->wlans) {
				while (device->wlans->first)
					wifi_wlan_destroy((struct wifi_wlan*)device->wlans->first->item);
				capwap_list_free(device->wlans);
			}

			/* */
			device_deinit(device);

			/* Free capability */
			if (device->capability) {
				if (device->capability->bands) {
					for (i = 0; i < device->capability->bands->count; i++) {
						struct wifi_band_capability* bandcap =
							(struct wifi_band_capability *)
							capwap_array_get_item_pointer(device->capability->bands, i);

						if (bandcap->freq)
							capwap_array_free(bandcap->freq);
						if (bandcap->rate)
							capwap_array_free(bandcap->rate);
					}
					capwap_array_free(device->capability->bands);
				}

				if (device->capability->ciphers)
					capwap_array_free(device->capability->ciphers);

				capwap_free(device->capability);
			}
		}

		capwap_list_free(g_wifiglobal.devices);
	}

	/* Free stations */
	if (g_wifiglobal.stations)
		capwap_hash_free(g_wifiglobal.stations);

	/* Free driver */
	for (i = 0; wifi_driver[i].ops != NULL; i++)
		wifi_driver[i].ops->global_deinit(wifi_driver[i].handle);

	/* */
	close(g_wifiglobal.sock_util);
}

/* */
struct wifi_wlan* wifi_get_wlan(uint32_t ifindex)
{
	struct capwap_list_item* itemdevice;
	struct capwap_list_item* itemwlan;

	ASSERT(g_wifiglobal.devices != NULL);
	ASSERT(ifindex > 0);

	/* Search device */
	for (itemdevice = g_wifiglobal.devices->first;
	     itemdevice != NULL;
	     itemdevice = itemdevice->next) {
		struct wifi_device* device = (struct wifi_device*)itemdevice->item;

		/* Search wlan */
		if (!device->wlans)
			continue;

		for (itemwlan = device->wlans->first; itemwlan != NULL; itemwlan = itemwlan->next) {
			struct wifi_wlan* wlan = (struct wifi_wlan*)itemwlan->item;

			if (wlan->virtindex == ifindex)
				return wlan;
		}
	}

	return NULL;
}

/* */
struct wifi_device* wifi_device_connect(const char* ifname, const char* driver)
{
	int i;
	int length;
	struct capwap_list_item* itemdevice;
	struct wifi_device* device = NULL;

	ASSERT(ifname != NULL);
	ASSERT(driver != NULL);

	/* Check */
	length = strlen(ifname);
	if ((length <= 0) || (length >= IFNAMSIZ)) {
		log_printf(LOG_WARNING, "Wifi device name error: %s", ifname);
		return NULL;
	}

	/* Search driver */
	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		if (strcmp(driver, wifi_driver[i].ops->name) != 0)
			continue;

		itemdevice = capwap_itemlist_create(sizeof(struct wifi_device));
		device = (struct wifi_device*)itemdevice->item;
		memset(device, 0, sizeof(struct wifi_device));

		/* */
		device->global = &g_wifiglobal;
		device->instance = &wifi_driver[i];
		strcpy(device->phyname, ifname);

		/* Device init */
		if (device_init(&wifi_driver[i], device)) {
			capwap_itemlist_free(itemdevice);
			return NULL;
		}

		/* Registered new device */
		device->wlans = capwap_list_create();

		/* Device capability */
		device->capability = (struct wifi_capability*)capwap_alloc(sizeof(struct wifi_capability));
		memset(device->capability, 0, sizeof(struct wifi_capability));
		device->capability->bands = capwap_array_create(sizeof(struct wifi_band_capability), 0, 1);
		device->capability->ciphers = capwap_array_create(sizeof(struct wifi_cipher_capability), 0, 1);

		/* Retrieve device capability */
		device_getcapability(device, device->capability);

		/* Appent to device list */
		capwap_itemlist_insert_after(g_wifiglobal.devices, NULL, itemdevice);

		break;
	}

	return device;
}

/* */
const struct wifi_capability* wifi_device_getcapability(struct wifi_device* device)
{
	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);

	return device->capability;
}

/* */
int wifi_device_setconfiguration(struct wifi_device* device,
				 struct device_setconfiguration_params* params)
{
	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);
	ASSERT(params != NULL);

	/* */
	device->flags |= WIFI_DEVICE_SET_CONFIGURATION;
	device->beaconperiod = params->beaconperiod;
	device->dtimperiod = params->dtimperiod;
	device->shortpreamble = (params->shortpreamble ? 1 : 0);

	/* Update beacons */
	if (device->wlans->count)
		device_updatebeacons(device);

	return 0;
}

/* */
int wifi_device_setfrequency(struct wifi_device* device, uint32_t band,
			     uint32_t mode, uint8_t channel)
{
	int i, j;
	int result = -1;
	const struct wifi_capability* capability;
	uint32_t frequency = 0;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);

	/* Capability device */
	capability = wifi_device_getcapability(device);
	if (!capability ||
	    !(capability->flags & WIFI_CAPABILITY_RADIOTYPE) ||
	    !(capability->flags & WIFI_CAPABILITY_BANDS))
		return -1;

	/* Search frequency */
	for (i = 0; (i < capability->bands->count) && !frequency; i++) {
		struct wifi_band_capability* bandcap =
			(struct wifi_band_capability*)capwap_array_get_item_pointer(capability->bands, i);

		if (bandcap->band != band)
			continue;

		for (j = 0; j < bandcap->freq->count; j++) {
			struct wifi_freq_capability* freqcap =
				(struct wifi_freq_capability*)capwap_array_get_item_pointer(bandcap->freq, j);
			if (freqcap->channel == channel) {
				frequency = freqcap->frequency;
				break;
			}
		}
	}

	/* Configure frequency */
	if (frequency) {
		device->currentfrequency.band = band;
		device->currentfrequency.mode = mode;
		device->currentfrequency.channel = channel;
		device->currentfrequency.frequency = frequency;

		/* According to the selected band remove the invalid mode */
		if (device->currentfrequency.band == WIFI_BAND_2GHZ)
			device->currentfrequency.mode &= ~CAPWAP_RADIO_TYPE_80211A;
		else if (device->currentfrequency.band == WIFI_BAND_5GHZ)
			device->currentfrequency.mode &= ~(CAPWAP_RADIO_TYPE_80211B | CAPWAP_RADIO_TYPE_80211G);

		/* Set frequency */
		device->flags |= WIFI_DEVICE_SET_FREQUENCY;
		result = device_setfrequency(device);
	}

	/* */
	return result;
}

int wifi_device_settxqueue(struct wifi_device *device,
			   struct capwap_80211_wtpqos_element *qos)
{
	int i, txop;

	for (i = 0; i < CAPWAP_UPDATE_STATION_QOS_SUBELEMENTS; i++) {
		switch (i) {
		case 0:			/* Best Effort */
			txop = 0;
			break;
		case 1:			/* Background */
			txop = 0;
			break;
		case 2:			/* Video */
			txop = 94;
			break;
		case 3:			/* Voice */
			txop = 47;
			break;
		default:
			return -1;
		}

		if (device_settxqueue(device, i, qos->qos[i].aifs, qos->qos[i].cwmin,
				      qos->qos[i].cwmax, txop) < 0)
			return -1;
	}
	return 0;
}

/* */
int wifi_device_updaterates(struct wifi_device* device,
			    uint8_t* rates, int ratescount)
{
	struct device_setrates_params buildrate;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);
	ASSERT(rates != NULL);
	ASSERT(ratescount > 0);

	/* */
	wifi_wlan_getrates(device, rates, ratescount, &buildrate);
	if (!buildrate.supportedratescount ||
	    (buildrate.supportedratescount > IEEE80211_SUPPORTEDRATE_MAX_COUNT)) {
		log_printf(LOG_DEBUG, "update rates: supported rates failed, (%d .. %d)",
			   buildrate.supportedratescount, IEEE80211_SUPPORTEDRATE_MAX_COUNT);
		return -1;
	} else if (!buildrate.basicratescount ||
		   (buildrate.basicratescount > IEEE80211_SUPPORTEDRATE_MAX_COUNT)) {
		log_printf(LOG_DEBUG, "update rates: basic rates failed: %d", buildrate.basicratescount);
		return -1;
	}

	/* Set new rates */
	device->flags |= WIFI_DEVICE_SET_RATES;
	memcpy(device->supportedrates, buildrate.supportedrates, buildrate.supportedratescount);
	device->supportedratescount = buildrate.supportedratescount;
	memcpy(device->basicrates, buildrate.basicrates, buildrate.basicratescount);
	device->basicratescount = buildrate.basicratescount;

	/* Update beacons */
	if (device->wlans->count)
		device_updatebeacons(device);

	return 0;
}

/* */
static int wifi_iface_hwaddr(int sock, const char* ifname, uint8_t* hwaddr)
{
	struct ifreq ifreq;

	ASSERT(sock > 0);
	ASSERT(ifname != NULL);
	ASSERT(*ifname != 0);
	ASSERT(hwaddr != NULL);

	/* Get mac address of interface */
	memset(&ifreq, 0, sizeof(ifreq));
	strcpy(ifreq.ifr_name, ifname);
	if (!ioctl(sock, SIOCGIFHWADDR, &ifreq)) {
		if (ifreq.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
			memcpy(hwaddr, ifreq.ifr_hwaddr.sa_data, MACADDRESS_EUI48_LENGTH);
			return 0;
		}
	}

	return -1;
}

/* */
struct wifi_wlan* wifi_wlan_create(struct wifi_device* device,
				   const char* ifname)
{
	int length;
	struct wifi_wlan* wlan;
	struct capwap_list_item* itemwlan;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);
	ASSERT(ifname != NULL);

	/* Check */
	length = strlen(ifname);
	if ((length <= 0) || (length >= IFNAMSIZ)) {
		log_printf(LOG_WARNING, "Wifi device name error: %s", ifname);
		return NULL;
	}

	/* Create new WLAN */
	itemwlan = capwap_itemlist_create(sizeof(struct wifi_wlan));
	wlan = (struct wifi_wlan*)itemwlan->item;
	memset(wlan, 0, sizeof(struct wifi_wlan));

	/* */
	wlan->device = device;
	strcpy(wlan->virtname, ifname);
	wlan->maxstationscount = IEEE80211_MAX_STATIONS;

	/* Appent to wlan list */
	capwap_itemlist_insert_after(device->wlans, NULL, itemwlan);

	/* Create interface */
	wlan->handle = wlan_create(device, wlan);
	if (!wlan->handle) {
		log_printf(LOG_WARNING, "Unable to create virtual interface: %s", ifname);
		wifi_wlan_destroy(wlan);
		return NULL;
	}

	/* Interface info */
	wlan->virtindex = wifi_iface_index(ifname);
	if (wifi_iface_hwaddr(g_wifiglobal.sock_util, wlan->virtname, wlan->address)) {
		log_printf(LOG_WARNING, "Unable to get macaddress: %s", ifname);
		wifi_wlan_destroy(wlan);
		return NULL;
	}

	return wlan;
}

/* Build 802.11 Information Elements from CAPWAP Message Elements */
static void build_80211_ie(uint8_t radioid, uint8_t wlanid, uint8_t type,
			   struct capwap_array *ie,
			   uint8_t **ptr, int *len)
{
	uint8_t buffer[IEEE80211_MTU];
	ssize_t space = sizeof(buffer);
	uint8_t *pos = buffer;
	int i;

	ASSERT(ptr);
	ASSERT(len);

	log_printf(LOG_DEBUG, "WIFI 802.11: IE: %d:%d %02x, %p",
		   radioid, wlanid, type, ie);

	*len = 0;
	*ptr = NULL;

	if (!ie)
		return;

	for (i = 0; i < ie->count; i++) {
		struct capwap_80211_ie_element *e =
			*(struct capwap_80211_ie_element **)capwap_array_get_item_pointer(ie, i);

		log_printf(LOG_DEBUG, "WIFI 802.11: IE: %d:%d %02x (%p)",
			   radioid, wlanid, e->flags, &e->flags);

		if (e->radioid != radioid ||
		    e->wlanid != wlanid ||
		    !(e->flags & type))
			continue;

		/* not enough space left */
		if (e->ielength > space)
			continue;

		memcpy(pos, e->ie, e->ielength);
		pos += e->ielength;
		space -= e->ielength;
	}

	*len = pos - buffer;
	if (*len > 0) {
		*ptr = malloc(*len);
		if (*ptr)
			memcpy(*ptr, buffer, *len);
	}
}

/* Scan AC provided IEs for HT Capabilities and HT Operation */
static int ht_opmode_from_ie(uint8_t radioid, uint8_t wlanid,
			     struct capwap_array *ie)
{
	int i;

	if (!ie)
		return -1;

	for (i = 0; i < ie->count; i++) {
		struct ieee80211_ht_operation *ht_oper;
		struct capwap_80211_ie_element *e =
			*(struct capwap_80211_ie_element **)capwap_array_get_item_pointer(ie, i);

		log_printf(LOG_DEBUG, "HT Mode WIFI 802.11: IE: %d:%d %02x (%p)",
			   radioid, wlanid, e->flags, &e->flags);

		if (e->radioid != radioid ||
		    e->wlanid != wlanid ||
		    !(e->flags & CAPWAP_IE_BEACONS_ASSOCIATED) ||
		    e->ielength < 2)
			continue;

		ht_oper = (struct ieee80211_ht_operation *)e->ie;
		log_printf(LOG_DEBUG, "HT Mode WIFI 802.11: IE: %02d (%p)",
			   ht_oper->id, ht_oper);
		if (ht_oper->id == IEEE80211_IE_HT_OPERATION)
			return __le16_to_cpu(ht_oper->operation_mode);
	}

	log_printf(LOG_DEBUG, "WIFI 802.11: No HT Operation IE present");
	return -1;
}

/* Scan AC provided IEs for RSNE settings */
static struct ieee80211_ie *rsn_from_ie(uint8_t radioid, uint8_t wlanid,
					       struct capwap_array *ie)
{
	int i;

	if (!ie)
		return NULL;

	for (i = 0; i < ie->count; i++) {
		struct ieee80211_ie *rsn;
		struct capwap_80211_ie_element *e =
			*(struct capwap_80211_ie_element **)capwap_array_get_item_pointer(ie, i);

		log_printf(LOG_DEBUG, "RSN WIFI 802.11: IE: %d:%d %02x (%p)",
			   radioid, wlanid, e->flags, &e->flags);

		if (e->radioid != radioid ||
		    e->wlanid != wlanid ||
		    e->ielength < 2)
			continue;

		rsn = (struct ieee80211_ie *)e->ie;
		log_printf(LOG_DEBUG, "RSN WIFI 802.11: IE: %02d (%p)",
			   rsn->id, rsn);
		if (rsn->id == IEEE80211_IE_RSN_INFORMATION)
			return rsn;
	}

	log_printf(LOG_DEBUG, "WIFI 802.11: No RSN IE present");
	return NULL;
}

/* */
int wifi_wlan_startap(struct wifi_wlan* wlan, struct wlan_startap_params* params)
{
	int result;

	ASSERT(wlan != NULL);
	ASSERT(wlan->device != NULL);
	ASSERT(params != NULL);

	/* Check device */
	if ((wlan->flags & WIFI_WLAN_RUNNING) ||
	    ((wlan->device->flags & WIFI_DEVICE_REQUIRED_FOR_BSS) != WIFI_DEVICE_REQUIRED_FOR_BSS))
		return -1;

	/* Save configuration */
	strcpy(wlan->ssid, params->ssid);
	wlan->ssid_hidden = params->ssid_hidden;
	wlan->capability = params->capability;
	wlan->authmode = params->authmode;
	wlan->macmode = params->macmode;
	wlan->tunnelmode = params->tunnelmode;
	wlan->radioid = params->radioid;
	wlan->wlanid = params->wlanid;
	wlan->ht_opmode = ht_opmode_from_ie(wlan->radioid, wlan->wlanid,
					    params->ie);
	log_printf(LOG_DEBUG, "WIFI 802.11: HT OpMode: %04x", wlan->ht_opmode);
	wlan->rsne = rsn_from_ie(wlan->radioid, wlan->wlanid,
				 params->ie);
	wlan->keyindex = params->keyindex;
	wlan->keylength = params->keylength;
	if (params->key && params->keylength)
		wlan->key = capwap_clone(params->key, params->keylength);

	build_80211_ie(wlan->radioid, wlan->wlanid,
		       CAPWAP_IE_BEACONS_ASSOCIATED,
		       params->ie,
		       &wlan->beacon_ies, &wlan->beacon_ies_len);
	build_80211_ie(wlan->radioid, wlan->wlanid,
		       CAPWAP_IE_PROBE_RESPONSE_ASSOCIATED,
		       params->ie,
		       &wlan->response_ies, &wlan->response_ies_len);

	/* Start AP */
	result = wlan_startap(wlan);
	if (!result) {
		wlan->device->wlanactive++;
		log_printf(LOG_INFO, "Configured interface: %s, SSID: '%s'", wlan->virtname, wlan->ssid);
	} else {
		wifi_wlan_stopap(wlan);
	}

	return result;
}

/* */
void wifi_wlan_stopap(struct wifi_wlan* wlan)
{
	ASSERT(wlan != NULL);
	ASSERT(wlan->device != NULL);

	/* Stop AP */
	wlan_stopap(wlan);

	free(wlan->beacon_ies);
	wlan->beacon_ies = NULL;
	free(wlan->response_ies);
	wlan->response_ies = NULL;

	/* */
	if (wlan->flags & WIFI_WLAN_RUNNING)
		wlan->device->wlanactive--;

	/* */
	wlan->flags = 0;

	/* TODO: Remove all stations from hash */
}

/* */
int wifi_wlan_getbssid(struct wifi_wlan* wlan, uint8_t* bssid)
{
	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);
	ASSERT(bssid != NULL);

	memcpy(bssid, wlan->address, MACADDRESS_EUI48_LENGTH);
	return 0;
}

/* */
uint16_t wifi_wlan_check_capability(struct wifi_wlan* wlan, uint16_t capability)
{
	uint16_t result = capability;

	/* Force ESS capability */
	result |= IEEE80211_CAPABILITY_ESS;

	/* Check short preamble capability */
	if (wlan->device->shortpreamble && !wlan->device->stationsnoshortpreamblecount)
		result |= IEEE80211_CAPABILITY_SHORTPREAMBLE;
	else
		result &= ~IEEE80211_CAPABILITY_SHORTPREAMBLE;

	/* Check privacy capability */
	/* TODO */

	/* Check short slot time capability */
	if ((wlan->device->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G) &&
	    !wlan->device->stationsnoshortslottimecount)
		result |= IEEE80211_CAPABILITY_SHORTSLOTTIME;
	else
		result &= ~IEEE80211_CAPABILITY_SHORTSLOTTIME;

	return result;
}

/* */
void wifi_wlan_destroy(struct wifi_wlan* wlan)
{
	struct capwap_list_item* itemwlan;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);

	/* Terminate service */
	wifi_wlan_stopap(wlan);

	/* */
	wlan_delete(wlan);

	/* Remove wlan from device's list */
	for (itemwlan = wlan->device->wlans->first; itemwlan; itemwlan = itemwlan->next)
		if (wlan == (struct wifi_wlan*)itemwlan->item) {
			capwap_itemlist_free(capwap_itemlist_remove(wlan->device->wlans, itemwlan));
			break;
		}
}

/* */
void wifi_wlan_receive_station_frame(struct wifi_wlan* wlan,
				     const struct ieee80211_header* frame,
				     int length, uint32_t frequency,
				     uint8_t rssi, uint8_t snr, uint16_t rate)
{
	uint16_t framecontrol;
	uint16_t framecontrol_type;
	uint16_t framecontrol_subtype;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);

	/* Check frame */
	if (!frame || (length < sizeof(struct ieee80211_header)))
		return;

	/* Get type frame */
	framecontrol = __le16_to_cpu(frame->framecontrol);
	framecontrol_type = IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol);
	framecontrol_subtype = IEEE80211_FRAME_CONTROL_GET_SUBTYPE(framecontrol);

	/* Parsing frame */
	if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_MGMT)
		wifi_wlan_receive_station_mgmt_frame(wlan,
						     (const struct ieee80211_header_mgmt*)frame,
						     length, framecontrol_subtype,
						     frequency, rssi, snr, rate);
}

/* */
void wifi_wlan_receive_station_ackframe(struct wifi_wlan* wlan,
					const struct ieee80211_header* frame,
					int length, int ack)
{
	uint16_t framecontrol;
	uint16_t framecontrol_type;
	uint16_t framecontrol_subtype;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);

	/* Check frame */
	if (!frame || (length < sizeof(struct ieee80211_header)))
		return;

	/* Get type frame */
	framecontrol = __le16_to_cpu(frame->framecontrol);
	framecontrol_type = IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol);
	framecontrol_subtype = IEEE80211_FRAME_CONTROL_GET_SUBTYPE(framecontrol);

	/* Parsing frame */
	if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_MGMT)
		wifi_wlan_receive_station_mgmt_ackframe(wlan,
							(const struct ieee80211_header_mgmt*)frame,
							length, framecontrol_subtype, ack);
}

/* */
void wifi_wlan_receive_ac_frame(struct wifi_wlan* wlan,
				struct ieee80211_header* frame,
				int length)
{
	int forwardframe = 1;
	uint16_t framecontrol;
	uint16_t framecontrol_type;
	uint16_t framecontrol_subtype;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);

	/* Check frame */
	if (!frame || (length < sizeof(struct ieee80211_header)))
		return;

	/* Get type frame */
	framecontrol = __le16_to_cpu(frame->framecontrol);
	framecontrol_type = IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol);
	framecontrol_subtype = IEEE80211_FRAME_CONTROL_GET_SUBTYPE(framecontrol);

	/* Parsing frame */
	if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_MGMT)
		forwardframe = wifi_wlan_receive_ac_mgmt_frame(wlan,
							       (struct ieee80211_header_mgmt*)frame,
							       length, framecontrol_subtype);

	/* Forward frame */
	if (forwardframe) {
		int nowaitack = (ieee80211_is_broadcast_addr(ieee80211_get_da_addr(frame)) ? 1 : 0);
		wlan_sendframe(wlan, (uint8_t*)frame, length,
			       wlan->device->currentfrequency.frequency,
			       0, 0, 0, nowaitack);
	}
}

/* */
int wifi_wlan_send_frame(struct wifi_wlan* wlan,
			 const uint8_t* data, int length,
			 uint8_t rssi, uint8_t snr, uint16_t rate)
{
	int result;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);

	if (!data || (length <= 0))
		return -1;

	/* Send packet to AC */
	result = wtp_kmod_send_data(wlan->radioid, data, length, rssi, snr, rate);
	if (result)
		log_printf(LOG_WARNING, "Unable to sent packet to AC: %d error code", result);

	return result;
}

/* */
int wifi_station_authorize(struct wifi_wlan* wlan,
			   struct station_add_params* params)
{
	int result;
	struct wifi_station* station;

	ASSERT(wlan != NULL);
	ASSERT(wlan->device != NULL);
	ASSERT(params != NULL);

	/* Get station */
	station = wifi_station_get(wlan, params->address);
	if (!station)
		return -1;

	if (params->key)
		station->key = (struct capwap_80211_stationkey_element *)
			capwap_element_80211_stationkey_ops.clone(params->key);
	station->pairwise_cipher = params->pairwise;

	if (station->flags & WIFI_STATION_FLAGS_AUTHORIZED) {
		result = wifi_station_set_key(wlan, station);
		if (result) {
			wifi_wlan_deauthentication_station(wlan, station,
							   IEEE80211_REASON_PREV_AUTH_NOT_VALID);
			return result;
		}
		return 0;
	}

	if (params->ht_cap) {
		memcpy(&station->ht_cap, params->ht_cap, sizeof(station->ht_cap));
		station->flags |= WIFI_STATION_FLAGS_HT_CAP;
	}

	station->max_inactivity = params->max_inactivity;

	/* Station is authorized only after Authentication and Association */
	station->flags |= WIFI_STATION_FLAGS_AUTHORIZED;
	if (!(station->flags & WIFI_STATION_FLAGS_AUTHENTICATED) ||
	    !(station->flags & WIFI_STATION_FLAGS_ASSOCIATE))
		return 0;

	/* Station authorized */
	result = station_authorize(wlan, station);
	if (!result)
		result = wifi_station_set_key(wlan, station);
	if (result) {
		wifi_wlan_deauthentication_station(wlan, station,
						   IEEE80211_REASON_PREV_AUTH_NOT_VALID);
		return result;
	}

	/* let the timer expire, but set the action to SEND NULLFUNC */
	station->timeout_action = WIFI_STATION_TIMEOUT_ACTION_SEND_NULLFUNC;

	return 0;
}

/* */
int wifi_station_set_key(struct wifi_wlan *wlan,
			 struct wifi_station* station)
{

	ASSERT(wlan != NULL);
	ASSERT(wlan->device != NULL);
	ASSERT(station != NULL);

	if (station->pairwise_cipher)
		return wlan_set_key(wlan, station->pairwise_cipher, station->address,
				    0, 1, NULL, 0, station->key->key, station->key->keylength);

	return wlan_set_key(wlan, station->pairwise_cipher, station->address,
			    0, 1, NULL, 0, NULL, 0);
}

/* */
void wifi_station_deauthorize(struct wifi_device* device, const uint8_t* address) {
	struct wifi_station* station;

	ASSERT(device != NULL);
	ASSERT(address != NULL);

	/* */
	station = wifi_station_get(NULL, address);
	if (station && station->wlan)
		wifi_wlan_deauthentication_station(station->wlan, station,
						   IEEE80211_REASON_PREV_AUTH_NOT_VALID);
}

/* */
uint32_t wifi_iface_index(const char* ifname)
{
	if (!ifname || !*ifname)
		return 0;

	return if_nametoindex(ifname);
}

/* */
int wifi_iface_getstatus(int sock, const char* ifname)
{
	struct ifreq ifreq;

	ASSERT(sock > 0);
	ASSERT(ifname != NULL);
	ASSERT(*ifname != 0);

	/* Change link state of interface */
	memset(&ifreq, 0, sizeof(ifreq));
	strcpy(ifreq.ifr_name, ifname);
	if (!ioctl(sock, SIOCGIFFLAGS, &ifreq))
		return ((ifreq.ifr_flags & IFF_UP) ? 1: 0);

	return -1;
}

/* */
int wifi_iface_updown(int sock, const char* ifname, int up)
{
	struct ifreq ifreq;

	ASSERT(sock > 0);
	ASSERT(ifname != NULL);
	ASSERT(*ifname != 0);

	/* Change link state of interface */
	memset(&ifreq, 0, sizeof(ifreq));
	strcpy(ifreq.ifr_name, ifname);
	if (!ioctl(sock, SIOCGIFFLAGS, &ifreq)) {
		/* Set flag */
		if (up) {
			if (ifreq.ifr_flags & IFF_UP) {
				return 0;	/* Flag is already set */
			}

			ifreq.ifr_flags |= IFF_UP;
		} else {
			if (!(ifreq.ifr_flags & IFF_UP)) {
				return 0;	/* Flag is already unset */
			}

			ifreq.ifr_flags &= ~IFF_UP;
		}

		if (!ioctl(sock, SIOCSIFFLAGS, &ifreq)) {
			return 0;
		}
	}

	return -1;
}
