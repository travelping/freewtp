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
static void wifi_station_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param);
static void wifi_wlan_deauthentication_station(struct wifi_wlan* wlan, struct wifi_station* station, uint16_t reasoncode, int reusestation);

/* */
static void wifi_wlan_getrates(struct wifi_device* device, uint8_t* rates, int ratescount, struct device_setrates_params* device_params) {
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
		capwap_logging_debug("getrates: getcapability failed");
		return;
	}

	/* Get radio type for basic rate */
	radiotype = wifi_frequency_to_radiotype(device->currentfrequency.frequency);
	if (radiotype < 0) {
		capwap_logging_debug("getrates: no radiotype for freq %d", device->currentfrequency.frequency);
		return;
	}
	capwap_logging_debug("getrates: radiotype %d, freq: %d", radiotype, device->currentfrequency.frequency);

	capwap_logging_debug("getrates: Band %d", device->currentfrequency.band);

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

	capwap_logging_debug("getrates: Mode %d", mode);

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

	capwap_logging_debug("getrates: Bands Count %d", capability->bands->count);

	/* Filter band */
	for (i = 0; i < capability->bands->count; i++) {
		struct wifi_band_capability* bandcap =
			(struct wifi_band_capability*)capwap_array_get_item_pointer(capability->bands, i);

		capwap_logging_debug("getrates: Bandcap Band %d", bandcap->band);

		if (bandcap->band != device->currentfrequency.band)
			continue;

		for (j = 0; j < bandcap->rate->count; j++) {
			struct wifi_rate_capability* ratecapability =
				(struct wifi_rate_capability*)capwap_array_get_item_pointer(bandcap->rate, j);

			/* Validate rate */
			for (w = 0; w < ratescount; w++) {
				log_printf(LOG_DEBUG, "getrates: cmp %d .. %d",
					   rates[w], ratecapability->bitrate);
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
	if (!(mode & CAPWAP_RADIO_TYPE_80211N) && (device->currentfrequency.mode & CAPWAP_RADIO_TYPE_80211N)) {
		device_params->supportedrates[device_params->supportedratescount++] = IEEE80211_RATE_80211N;
	}

	for (i = 0; i < device_params->basicratescount; i++) {
		capwap_logging_debug("getrates: Basic Rate %d: %d", i, device_params->basicrates[i]);
	}
	for (i = 0; i < device_params->supportedratescount; i++) {
		log_printf(LOG_DEBUG, "getrates: Supported Rate %d: %.1f Mbit (%d)",
			   i, (device_params->supportedrates[i] * 5) / 10.0,
			   device_params->supportedrates[i]);
	}
}

/* */
static unsigned long wifi_hash_station_gethash(const void* key, unsigned long hashsize) {
	uint8_t* macaddress = (uint8_t*)key;

	return ((unsigned long)macaddress[3] ^ (unsigned long)macaddress[4] ^ (unsigned long)macaddress[5]);
}

/* */
static const void* wifi_hash_station_getkey(const void* data) {
	return (const void*)((struct wifi_station*)data)->address;
}

/* */
static int wifi_hash_station_cmp(const void* key1, const void* key2) {
	return memcmp(key1, key2, MACADDRESS_EUI48_LENGTH);
}

/* */
static void wifi_hash_station_free(void* data) {
	struct wifi_station* station = (struct wifi_station*)data;

	ASSERT(data != NULL);

	/* */
	capwap_logging_info("Destroy station: %s", station->addrtext);
	capwap_free(station);
}

/* */
static struct wifi_station* wifi_station_get(struct wifi_wlan* wlan, const uint8_t* address) {
	struct wifi_station* station;

	ASSERT(address != NULL);

	/* Get station */
	station = (struct wifi_station*)capwap_hash_search(g_wifiglobal.stations, address);
	if (station && wlan && (station->wlan != wlan)) {
		return NULL;
	}

	return station;
}

/* */
static void wifi_station_clean(struct wifi_station* station) {
	int updatebeacons = 0;

	ASSERT(station != NULL);

	if (station->wlan) {
		struct wifi_wlan* wlan = station->wlan;

		/* Delete station into wireless driver */
		if (station->flags & WIFI_STATION_FLAGS_AUTHORIZED) {
			wlan->device->instance->ops->station_deauthorize(wlan, station->address);
		}

		if (station->aid && (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL)) {
			ieee80211_aid_free(wlan->aidbitfield, station->aid);
			station->aid = 0;
		}

		if (station->flags & WIFI_STATION_FLAGS_NON_ERP) {
			wlan->device->stationsnonerpcount--;
			if (!wlan->device->stationsnonerpcount) {
				updatebeacons = 1;
			}
		}

		if (station->flags & WIFI_STATION_FLAGS_NO_SHORT_SLOT_TIME) {
			wlan->device->stationsnoshortslottimecount--;
			if (!wlan->device->stationsnoshortslottimecount && (wlan->device->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G)) {
				updatebeacons = 1;
			}
		}

		if (station->flags & WIFI_STATION_FLAGS_NO_SHORT_PREAMBLE) {
			wlan->device->stationsnoshortpreamblecount--;
			if (!wlan->device->stationsnoshortpreamblecount && (wlan->device->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G)) {
				updatebeacons = 1;
			}
		}

		/* Update beacons */
		if (updatebeacons) {
			wlan->device->instance->ops->device_updatebeacons(wlan->device);
		}

		/* Disconnet from WLAN */
		wlan->stationscount--;
		station->wlan = NULL;
	}

	/* Remove timers */
	if (station->idtimeout != CAPWAP_TIMEOUT_INDEX_NO_SET) {
		capwap_timeout_deletetimer(g_wifiglobal.timeout, station->idtimeout);
		station->idtimeout = CAPWAP_TIMEOUT_INDEX_NO_SET;
	}

	/* */
	station->flags = 0;
	station->supportedratescount = 0;
}

/* */
static void wifi_station_delete(struct wifi_station* station) {
	ASSERT(station != NULL);

	/* */
	capwap_logging_info("Delete station: %s", station->addrtext);

	/* */
	wifi_station_clean(station);

	/* Delay delete station */
	station->timeoutaction = WIFI_STATION_TIMEOUT_ACTION_DELETE;
	station->idtimeout = capwap_timeout_set(g_wifiglobal.timeout, station->idtimeout, WIFI_STATION_TIMEOUT_AFTER_DEAUTHENTICATED, wifi_station_timeout, station, NULL);
}

/* */
static struct wifi_station* wifi_station_create(struct wifi_wlan* wlan, const uint8_t* address) {
	struct wifi_station* station;
	char buffer[CAPWAP_MACADDRESS_EUI48_BUFFER];

	ASSERT(wlan != NULL);
	ASSERT(address != NULL);

	/* */
	capwap_printf_macaddress(buffer, address, MACADDRESS_EUI48_LENGTH);

	/* */
	station = wifi_station_get(NULL, address);
	if (station) {
		if (station->wlan && (station->wlan != wlan)) {
			capwap_logging_info("Roaming station: %s", buffer);
			wifi_wlan_deauthentication_station(station->wlan, station, IEEE80211_REASON_PREV_AUTH_NOT_VALID, 1);
		} else {
			capwap_logging_info("Reuse station: %s", buffer);
			wifi_station_clean(station);
		}
	}

	/* Checks if it has reached the maximum number of stations */
	if (wlan->stationscount >= wlan->maxstationscount) {
		capwap_logging_warning("Unable create station: reached the maximum number of stations");
		return NULL;
	}

	/* Create new station */
	if (!station) {
		capwap_logging_info("Create new station: %s", buffer);

		/* */
		station = (struct wifi_station*)capwap_alloc(sizeof(struct wifi_station));
		memset(station, 0, sizeof(struct wifi_station));

		/* Initialize station */
		memcpy(station->address, address, MACADDRESS_EUI48_LENGTH);
		capwap_printf_macaddress(station->addrtext, address, MACADDRESS_EUI48_LENGTH);
		station->idtimeout = CAPWAP_TIMEOUT_INDEX_NO_SET;

		/* Add to pool */
		capwap_hash_add(g_wifiglobal.stations, station);
	}

	/* Set station to WLAN */
	station->wlan = wlan;
	wlan->stationscount++;

	return station;
}

/* */
static void wifi_wlan_send_mgmt_deauthentication(struct wifi_wlan* wlan, const uint8_t* station, uint16_t reasoncode) {
	int responselength;
	struct ieee80211_deauthentication_params ieee80211_params;
	char stationaddress[CAPWAP_MACADDRESS_EUI48_BUFFER];

	/* */
	capwap_printf_macaddress(stationaddress, station, MACADDRESS_EUI48_LENGTH);

	/* Create deauthentication packet */
	memset(&ieee80211_params, 0, sizeof(struct ieee80211_deauthentication_params));
	memcpy(ieee80211_params.bssid, wlan->address, ETH_ALEN);
	memcpy(ieee80211_params.station, station, ETH_ALEN);
	ieee80211_params.reasoncode = reasoncode;

	responselength = ieee80211_create_deauthentication(g_bufferIEEE80211, sizeof(g_bufferIEEE80211), &ieee80211_params);
	if (responselength > 0) {
		if (!wlan->device->instance->ops->wlan_sendframe(wlan, g_bufferIEEE80211, responselength, wlan->device->currentfrequency.frequency, 0, 0, 0, 0)) {
			capwap_logging_info("Sent IEEE802.11 Deuthentication to %s station", stationaddress);

			/* Forwards the station deauthentication also to AC */
			wifi_wlan_send_frame(wlan, (uint8_t*)g_bufferIEEE80211, responselength, 0, 0, 0);
		} else {
			capwap_logging_warning("Unable to send IEEE802.11 Deuthentication to %s station", stationaddress);
		}
	} else {
		capwap_logging_warning("Unable to create IEEE802.11 Deauthentication to %s station", stationaddress);
	}
}

/* */
static void wifi_wlan_deauthentication_station(struct wifi_wlan* wlan, struct wifi_station* station, uint16_t reasoncode, int reusestation) {
	ASSERT(wlan != NULL);
	ASSERT(station != NULL);

	/* Send deauthentication message */
	if (station->flags & WIFI_STATION_FLAGS_AUTHENTICATED) {
		wifi_wlan_send_mgmt_deauthentication(wlan, station->address, reasoncode);
	}

	/* Clean station */
	if (reusestation) {
		wifi_station_clean(station);
	} else {
		wifi_station_delete(station);
	}
}

/* */
static void wifi_station_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	struct wifi_station* station = (struct wifi_station*)context;

	ASSERT(station != NULL);

	if (station->idtimeout == index) {
		switch (station->timeoutaction) {
			case WIFI_STATION_TIMEOUT_ACTION_DELETE: {
				/* Free station into hash callback function */
				wifi_station_clean(station);
				capwap_hash_delete(g_wifiglobal.stations, station->address);
				break;
			}

			case WIFI_STATION_TIMEOUT_ACTION_DEAUTHENTICATE: {
				capwap_logging_warning("The %s station has not completed the association in time", station->addrtext);
				wifi_wlan_deauthentication_station((struct wifi_wlan*)param, station, IEEE80211_REASON_PREV_AUTH_NOT_VALID, 0);
				break;
			}
		}
	}
}

/* */
static void wifi_wlan_receive_station_mgmt_probe_request(struct wifi_wlan* wlan, const struct ieee80211_header_mgmt* frame, int length, uint8_t rssi, uint8_t snr, uint16_t rate) {
	int ielength;
	int ssidcheck;
	int nowaitack;
	int responselength;
	struct ieee80211_ie_items ieitems;
	struct ieee80211_probe_response_params params;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->proberequest));
	if (ielength < 0) {
		return;
	}

	/* Parsing Information Elements */
	if (ieee80211_retrieve_information_elements_position(&ieitems, &frame->proberequest.ie[0], ielength)) {
		return;
	}

	/* Validate Probe Request Packet */
	if (!ieitems.ssid || !ieitems.supported_rates) {
		return;
	}

	/* Verify the SSID */
	ssidcheck = ieee80211_is_valid_ssid(wlan->ssid, ieitems.ssid, ieitems.ssid_list);
	if (ssidcheck == IEEE80211_WRONG_SSID) {
		return;
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
	params.erpinfo = ieee80211_get_erpinfo(wlan->device->currentfrequency.mode, wlan->device->olbc, wlan->device->stationsnonerpcount, wlan->device->stationsnoshortpreamblecount, wlan->device->shortpreamble);
	params.channel = wlan->device->currentfrequency.channel;
	params.response_ies = wlan->response_ies;
	params.response_ies_len = wlan->response_ies_len;

	responselength = ieee80211_create_probe_response(g_bufferIEEE80211, sizeof(g_bufferIEEE80211), &params);
	if (responselength < 0) {
		return;
	}

	/* Send probe response */
	nowaitack = ((ssidcheck == IEEE80211_WILDCARD_SSID) && ieee80211_is_broadcast_addr(frame->da) ? 1 : 0);
	if (!wlan->device->instance->ops->wlan_sendframe(wlan, g_bufferIEEE80211, responselength, wlan->device->currentfrequency.frequency, 0, 0, 0, nowaitack)) {
		/* If enable Split Mac send the probe request message to AC */
		if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
			wifi_wlan_send_frame(wlan, (uint8_t*)frame, length, rssi, snr, rate);
		}
	} else {
		capwap_logging_warning("Unable to send IEEE802.11 Probe Response");
	}
}

/* */
static void wifi_wlan_management_legacy_station(struct wifi_wlan* wlan, struct wifi_station* station) {
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
			if (wlan->device->stationsnonerpcount == 1) {
				updatebeacons = 1;
			}
		}
	}

	/* Check short slot capability */
	if (!(station->capability & IEEE80211_CAPABILITY_SHORTSLOTTIME)) {
		station->flags |= WIFI_STATION_FLAGS_NO_SHORT_SLOT_TIME;
		wlan->device->stationsnoshortslottimecount++;
		if ((wlan->device->stationsnoshortslottimecount == 1) && (wlan->device->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G)) {
			updatebeacons = 1;
		}
	}

	/* Check short preamble capability */
	if (!(station->capability & IEEE80211_CAPABILITY_SHORTPREAMBLE)) {
		station->flags |= WIFI_STATION_FLAGS_NO_SHORT_PREAMBLE;
		wlan->device->stationsnoshortpreamblecount++;
		if ((wlan->device->stationsnoshortpreamblecount == 1) && (wlan->device->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G)) {
			updatebeacons = 1;
		}
	}

	/* Update beacon */
	if (updatebeacons) {
		wlan->device->instance->ops->device_updatebeacons(wlan->device);
	}
}

/* */
static int wifi_wlan_get_station_rates(struct wifi_station* station, struct ieee80211_ie_items* ieitems) {
	if (!ieitems->supported_rates) {
		return -1;
	} else if ((ieitems->supported_rates->len + (ieitems->extended_supported_rates ? ieitems->extended_supported_rates->len : 0)) > sizeof(station->supportedrates)) {
		return -1;
	}

	/* */
	station->supportedratescount = ieitems->supported_rates->len;
	memcpy(station->supportedrates, ieitems->supported_rates->rates, ieitems->supported_rates->len);
	if (ieitems->extended_supported_rates) {
		station->supportedratescount += ieitems->extended_supported_rates->len;
		memcpy(&station->supportedrates[ieitems->supported_rates->len], ieitems->extended_supported_rates->rates, ieitems->extended_supported_rates->len);
	}

	return 0;
}

/* */
static void wifi_wlan_receive_station_mgmt_authentication(struct wifi_wlan* wlan, const struct ieee80211_header_mgmt* frame, int length, uint8_t rssi, uint8_t snr, uint16_t rate) {
	int acl;
	int ielength;
	struct ieee80211_ie_items ieitems;
	int responselength;
	struct ieee80211_authentication_params ieee80211_params;
	struct wifi_station* station;
	char stationaddress[CAPWAP_MACADDRESS_EUI48_BUFFER];
	uint16_t responsestatuscode;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->authetication));
	if (ielength < 0) {
		capwap_logging_info("Receive invalid IEEE802.11 Authentication Request");
		return;
	}

	/* Ignore authentication packet from same AP */
	if (!memcmp(frame->sa, wlan->address, MACADDRESS_EUI48_LENGTH)) {
		capwap_logging_info("Ignore IEEE802.11 Authentication Request from same AP");
		return;
	}

	/* */
	capwap_printf_macaddress(stationaddress, frame->sa, MACADDRESS_EUI48_LENGTH);

	/* Get ACL Station */
	acl = wtp_radio_acl_station(frame->sa);
	if (acl == WTP_RADIO_ACL_STATION_DENY) {
		capwap_logging_info("Denied IEEE802.11 Authentication Request from %s station", stationaddress);
		return;
	}

	/* Parsing Information Elements */
	if (ieee80211_retrieve_information_elements_position(&ieitems, &frame->authetication.ie[0], ielength)) {
		capwap_logging_info("Invalid IEEE802.11 Authentication Request from %s station", stationaddress);
		return;
	}

	/* */
	capwap_logging_info("Receive IEEE802.11 Authentication Request from %s station", stationaddress);

	/* Create station reference */
	station = wifi_station_create(wlan, frame->sa);
	if (station) {
		/* A station is removed if the association does not complete within a given period of time */
		station->timeoutaction = WIFI_STATION_TIMEOUT_ACTION_DEAUTHENTICATE;
		station->idtimeout = capwap_timeout_set(g_wifiglobal.timeout, station->idtimeout, WIFI_STATION_TIMEOUT_ASSOCIATION_COMPLETE, wifi_station_timeout, station, wlan);
		responsestatuscode = IEEE80211_STATUS_SUCCESS;
	} else {
		responsestatuscode = IEEE80211_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
	}

	/* */
	if ((responsestatuscode != IEEE80211_STATUS_SUCCESS) || (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL)) {
		uint16_t algorithm = __le16_to_cpu(frame->authetication.algorithm);
		uint16_t transactionseqnumber = __le16_to_cpu(frame->authetication.transactionseqnumber);

		/* Check authentication algorithm */
		if (responsestatuscode == IEEE80211_STATUS_SUCCESS) {
			responsestatuscode = IEEE80211_STATUS_NOT_SUPPORTED_AUTHENTICATION_ALGORITHM;
			if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_OPEN) && (wlan->authmode == CAPWAP_ADD_WLAN_AUTHTYPE_OPEN)) {
				if (transactionseqnumber == 1) {
					responsestatuscode = IEEE80211_STATUS_SUCCESS;
					station->authalgorithm = IEEE80211_AUTHENTICATION_ALGORITHM_OPEN;
				} else {
					responsestatuscode = IEEE80211_STATUS_UNKNOWN_AUTHENTICATION_TRANSACTION;
				}
			} else if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_SHARED_KEY) && (wlan->authmode == CAPWAP_ADD_WLAN_AUTHTYPE_WEP)) {
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

		responselength = ieee80211_create_authentication_response(g_bufferIEEE80211, sizeof(g_bufferIEEE80211), &ieee80211_params);
		if (responselength > 0) {
			/* Send authentication response */
			if (!wlan->device->instance->ops->wlan_sendframe(wlan, g_bufferIEEE80211, responselength, wlan->device->currentfrequency.frequency, 0, 0, 0, 0)) {
				capwap_logging_info("Sent IEEE802.11 Authentication Response to %s station with %d status code", stationaddress, (int)responsestatuscode);

				/* Notify authentication request message also to AC */
				wifi_wlan_send_frame(wlan, (uint8_t*)frame, length, rssi, snr, rate);

				/* Forwards the authentication response message also to AC */
				wifi_wlan_send_frame(wlan, (uint8_t*)g_bufferIEEE80211, responselength, 0, 0, 0);
			} else if (station) {
				capwap_logging_warning("Unable to send IEEE802.11 Authentication Response to %s station", stationaddress);
				wifi_station_delete(station);
			}
		} else if (station) {
			capwap_logging_warning("Unable to create IEEE802.11 Authentication Response to %s station", stationaddress);
			wifi_station_delete(station);
		}
	} else if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
		wifi_wlan_send_frame(wlan, (uint8_t*)frame, length, rssi, snr, rate);
	}
}

/* */
static void wifi_wlan_receive_station_mgmt_association_request(struct wifi_wlan* wlan, const struct ieee80211_header_mgmt* frame, int length, uint8_t rssi, uint8_t snr, uint16_t rate) {
	int ielength;
	int responselength;
	struct ieee80211_ie_items ieitems;
	struct ieee80211_associationresponse_params params;
	struct wifi_station* station;
	uint16_t resultstatuscode;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->associationrequest));
	if (ielength < 0) {
		capwap_logging_info("Receive invalid IEEE802.11 Association Request");
		return;
	}

	/* Get station reference */
	station = wifi_station_get(wlan, frame->sa);
	if (!station) {
		char buffer[CAPWAP_MACADDRESS_EUI48_BUFFER];

		/* Invalid station, send deauthentication message */
		capwap_logging_info("Receive IEEE802.11 Association Request from %s unknown station", capwap_printf_macaddress(buffer, frame->sa, MACADDRESS_EUI48_LENGTH));
		wifi_wlan_send_mgmt_deauthentication(wlan, frame->sa, IEEE80211_REASON_CLASS2_FRAME_FROM_NONAUTH_STA);
		return;
	}

	/* */
	if (!(station->flags & WIFI_STATION_FLAGS_AUTHENTICATED)) {
		/* Invalid station, send deauthentication message */
		capwap_logging_info("Receive IEEE802.11 Association Request from %s unauthorized station", station->addrtext);
		wifi_wlan_deauthentication_station(wlan, station, IEEE80211_REASON_CLASS2_FRAME_FROM_NONAUTH_STA, 0);
		return;
	}

	/* Parsing Information Elements */
	if (ieee80211_retrieve_information_elements_position(&ieitems, &frame->associationrequest.ie[0], ielength)) {
		capwap_logging_info("Invalid IEEE802.11 Association Request from %s station", station->addrtext);
		wifi_wlan_deauthentication_station(wlan, station, IEEE80211_REASON_PREV_AUTH_NOT_VALID, 0);
		return;
	}

	/* */
	capwap_logging_info("Receive IEEE802.11 Association Request from %s station", station->addrtext);

	if (ieitems.wmm_ie != NULL && ieitems.wmm_ie->version == 1) {
		station->flags |= WIFI_STATION_FLAGS_WMM;
		station->qosinfo = ieitems.wmm_ie->qos_info;
	}

	/* */
	if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL) {
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
		memcpy(params.supportedrates, wlan->device->supportedrates, wlan->device->supportedratescount);
		params.supportedratescount = wlan->device->supportedratescount;
		params.response_ies = wlan->response_ies;
		params.response_ies_len = wlan->response_ies_len;

		responselength = ieee80211_create_associationresponse_response(g_bufferIEEE80211, sizeof(g_bufferIEEE80211), &params);
		if (responselength > 0) {
			if (!wlan->device->instance->ops->wlan_sendframe(wlan, g_bufferIEEE80211, responselength, wlan->device->currentfrequency.frequency, 0, 0, 0, 0)) {
				capwap_logging_info("Sent IEEE802.11 Association Response to %s station with %d status code", station->addrtext, (int)resultstatuscode);

				/* Notify association request message also to AC */
				wifi_wlan_send_frame(wlan, (uint8_t*)frame, length, rssi, snr, rate);

				/* Forwards the association response message also to AC */
				wifi_wlan_send_frame(wlan, (uint8_t*)g_bufferIEEE80211, responselength, 0, 0, 0);
			} else {
				capwap_logging_warning("Unable to send IEEE802.11 Association Response to %s station", station->addrtext);
				wifi_wlan_deauthentication_station(wlan, station, IEEE80211_REASON_PREV_AUTH_NOT_VALID, 0);
			}
		} else {
			capwap_logging_warning("Unable to create IEEE802.11 Association Response to %s station", station->addrtext);
			wifi_wlan_deauthentication_station(wlan, station, IEEE80211_REASON_PREV_AUTH_NOT_VALID, 0);
		}
	} else if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
		wifi_wlan_send_frame(wlan, (uint8_t*)frame, length, rssi, snr, rate);

		/* Station information */
		station->capability = __le16_to_cpu(frame->associationresponse.capability);
		station->listeninterval = __le16_to_cpu(frame->associationrequest.listeninterval);
	}
}

/* */
static void wifi_wlan_receive_station_mgmt_reassociation_request(struct wifi_wlan* wlan, const struct ieee80211_header_mgmt* frame, int length, uint8_t rssi, uint8_t snr, uint16_t rate) {
	int ielength;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->reassociationrequest));
	if (ielength < 0) {
		return;
	}

	/* TODO */
}

/* */
static void wifi_wlan_receive_station_mgmt_disassociation(struct wifi_wlan* wlan, const struct ieee80211_header_mgmt* frame, int length, uint8_t rssi, uint8_t snr, uint16_t rate) {
	int ielength;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->disassociation));
	if (ielength < 0) {
		return;
	}

	/* TODO */

	/* Notify disassociation message also to AC */
	wifi_wlan_send_frame(wlan, (uint8_t*)frame, length, rssi, snr, rate);
}

/* */
static void wifi_wlan_receive_station_mgmt_deauthentication(struct wifi_wlan* wlan, const struct ieee80211_header_mgmt* frame, int length, uint8_t rssi, uint8_t snr, uint16_t rate) {
	int ielength;
	struct wifi_station* station;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->deauthetication));
	if (ielength < 0) {
		return;
	}

	/* Delete station */
	station = wifi_station_get(wlan, frame->sa);
	if (station) {
		wifi_station_delete(station);
	}

	/* Notify deauthentication message also to AC */
	wifi_wlan_send_frame(wlan, (uint8_t*)frame, length, rssi, snr, rate);
}

/* */
static void wifi_wlan_receive_station_mgmt_frame(struct wifi_wlan* wlan, const struct ieee80211_header_mgmt* frame, int length, uint16_t framecontrol_subtype, uint32_t frequency, uint8_t rssi, uint8_t snr, uint16_t rate) {
	int broadcast;

	/* Check frequency */
	if (frequency && (wlan->device->currentfrequency.frequency != frequency)) {
		return;
	}

	/* Check if sent packet to correct AP */
	broadcast = ieee80211_is_broadcast_addr(frame->bssid);
	if (!broadcast && memcmp(frame->bssid, wlan->address, MACADDRESS_EUI48_LENGTH)) {
		return;
	}

	/* */
	if (framecontrol_subtype == IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_PROBE_REQUEST) {
		 wifi_wlan_receive_station_mgmt_probe_request(wlan, frame, length, rssi, snr, rate);
	} else if (!memcmp(frame->da, wlan->address, MACADDRESS_EUI48_LENGTH)) {
		switch (framecontrol_subtype) {
			case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTHENTICATION: {
				wifi_wlan_receive_station_mgmt_authentication(wlan, frame, length, rssi, snr, rate);
				break;
			}

			case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_REQUEST: {
				wifi_wlan_receive_station_mgmt_association_request(wlan, frame, length, rssi, snr, rate);
				break;
			}

			case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_REASSOCIATION_REQUEST: {
				wifi_wlan_receive_station_mgmt_reassociation_request(wlan, frame, length, rssi, snr, rate);
				break;
			}

			case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DISASSOCIATION: {
				wifi_wlan_receive_station_mgmt_disassociation(wlan, frame, length, rssi, snr, rate);
				break;
			}

			case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTHENTICATION: {
				wifi_wlan_receive_station_mgmt_deauthentication(wlan, frame, length, rssi, snr, rate);
				break;
			}

			case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ACTION: {
				/* TODO */
				break;
			}
		}
	}
}

/* */
static void wifi_wlan_receive_station_mgmt_authentication_ack(struct wifi_wlan* wlan, const struct ieee80211_header_mgmt* frame, int length, int ack) {
	uint16_t algorithm;
	uint16_t transactionseqnumber;
	uint16_t statuscode;
	struct wifi_station* station;

	/* Check packet */
	if (!ack || (length < (sizeof(struct ieee80211_header) + sizeof(frame->authetication)))) {
		return;
	}

	/* Get station information */
	station = wifi_station_get(wlan, frame->da);
	if (!station) {
		return;
	}

	/* */
	statuscode = __le16_to_cpu(frame->authetication.statuscode);
	if (statuscode == IEEE80211_STATUS_SUCCESS) {
		algorithm = __le16_to_cpu(frame->authetication.algorithm);
		transactionseqnumber = __le16_to_cpu(frame->authetication.transactionseqnumber);

		/* Check if authenticate */
		if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_OPEN) && (transactionseqnumber == 2)) {
			capwap_logging_info("IEEE802.11 Authentication complete to %s station", station->addrtext);
			station->flags |= WIFI_STATION_FLAGS_AUTHENTICATED;
		} else if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_SHARED_KEY) && (transactionseqnumber == 4)) {
			/* TODO */
		}
	}
}

/* */
static void wifi_wlan_receive_station_mgmt_association_response_ack(struct wifi_wlan* wlan, const struct ieee80211_header_mgmt* frame, int length, int ack) {
	uint16_t statuscode;
	struct wifi_station* station;

	/* Check packet */
	if (!ack || (length < (sizeof(struct ieee80211_header) + sizeof(frame->associationresponse)))) {
		return;
	}

	/* Get station information */
	station = wifi_station_get(wlan, frame->da);
	if (!station) {
		return;
	}

	/* */
	statuscode = __le16_to_cpu(frame->associationresponse.statuscode);
	if (statuscode == IEEE80211_STATUS_SUCCESS) {
		capwap_logging_info("IEEE802.11 Association complete to %s station", station->addrtext);

		/* */
		station->flags |= WIFI_STATION_FLAGS_ASSOCIATE;
		if (station->flags & WIFI_STATION_FLAGS_AUTHORIZED) {
			/* Apply authorization if Station already authorized */
			if (wlan->device->instance->ops->station_authorize(wlan, station)) {
				wifi_wlan_deauthentication_station(wlan, station, IEEE80211_REASON_PREV_AUTH_NOT_VALID, 0);
			}
		}
	}
}

/* */
static void wifi_wlan_receive_station_mgmt_ackframe(struct wifi_wlan* wlan, const struct ieee80211_header_mgmt* frame, int length, uint16_t framecontrol_subtype, int ack) {
	/* Ignore packet if not sent to AP */
	if (memcmp(frame->bssid, wlan->address, MACADDRESS_EUI48_LENGTH)) {
		return;
	}

	/* */
	switch (framecontrol_subtype) {
		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTHENTICATION: {
			wifi_wlan_receive_station_mgmt_authentication_ack(wlan, frame, length, ack);
			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_RESPONSE: {
			wifi_wlan_receive_station_mgmt_association_response_ack(wlan, frame, length, ack);
			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTHENTICATION: {
			/* TODO */
			break;
		}
	}
}

/* */
static int wifi_wlan_receive_ac_mgmt_authentication(struct wifi_wlan* wlan, struct ieee80211_header_mgmt* frame, int length) {
	int ielength;
	struct wifi_station* station;
	int forwardframe = 0;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->authetication));
	if (ielength >= 0) {
		if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
			station = wifi_station_get(wlan, frame->da);
			if (station) {
				uint16_t statuscode = __le16_to_cpu(frame->authetication.statuscode);

				if (statuscode == IEEE80211_STATUS_SUCCESS) {
					uint16_t algorithm = __le16_to_cpu(frame->authetication.algorithm);
					uint16_t transactionseqnumber = __le16_to_cpu(frame->authetication.transactionseqnumber);

					/* Get authentication algorithm */
					if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_OPEN) && (transactionseqnumber == 2)) {
						station->authalgorithm = IEEE80211_AUTHENTICATION_ALGORITHM_OPEN;
					} else if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_SHARED_KEY) && (transactionseqnumber == 4)) {
						station->authalgorithm = IEEE80211_AUTHENTICATION_ALGORITHM_SHARED_KEY;
					}
				}

				/* */
				forwardframe = 1;
			}
		}
	}

	return forwardframe;
}

/* */
static int wifi_wlan_receive_ac_mgmt_association_response(struct wifi_wlan* wlan, struct ieee80211_header_mgmt* frame, int length) {
	int ielength;
	struct ieee80211_ie_items ieitems;
	struct wifi_station* station;
	int forwardframe = 0;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->associationresponse));
	if (ielength >= 0) {
		station = wifi_station_get(wlan, frame->da);
		if (station) {
			if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL) {
				if (frame->associationresponse.statuscode != IEEE80211_STATUS_SUCCESS) {
					capwap_logging_info("AC request deauthentication of station: %s", station->addrtext);
					wifi_wlan_deauthentication_station(wlan, station, IEEE80211_REASON_PREV_AUTH_NOT_VALID, 0);
				}
			} else if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
				uint16_t statuscode = __le16_to_cpu(frame->associationresponse.statuscode);

				if ((statuscode == IEEE80211_STATUS_SUCCESS) && !ieee80211_retrieve_information_elements_position(&ieitems, &frame->associationresponse.ie[0], ielength)) {
					/* Station information */
					station->aid = (__le16_to_cpu(frame->associationresponse.aid) & ~IEEE80211_AID_FIELD);

					/* Get supported rates */
					wifi_wlan_get_station_rates(station, &ieitems);

					/* */
					wifi_wlan_management_legacy_station(wlan, station);

					/* Assign valid WLAN capability */
					frame->associationresponse.capability = __cpu_to_le16(wifi_wlan_check_capability(wlan, wlan->capability));
				}

				/* */
				forwardframe = 1;
			}
		}
	}

	return forwardframe;
}

/* */
static int wifi_wlan_receive_ac_mgmt_reassociation_response(struct wifi_wlan* wlan, struct ieee80211_header_mgmt* frame, int length) {
	int ielength;
	struct wifi_station* station;
	int forwardframe = 0;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->reassociationresponse));
	if (ielength >= 0) {
		if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
			station = wifi_station_get(wlan, frame->da);
			if (station) {
				/* TODO */
			}
		}
	}

	return forwardframe;
}

/* */
static int wifi_wlan_receive_ac_mgmt_disassociation(struct wifi_wlan* wlan, struct ieee80211_header_mgmt* frame, int length) {
	int ielength;
	struct wifi_station* station;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->disassociation));
	if (ielength < 0) {
		return 0;
	}

	/* */
	station = wifi_station_get(wlan, frame->da);
	if (station) {
		/* Deautherize station */
		if (station->flags & WIFI_STATION_FLAGS_AUTHORIZED) {
			station->flags &= ~WIFI_STATION_FLAGS_AUTHORIZED;
			wlan->device->instance->ops->station_deauthorize(wlan, station->address);
		}

		/* Deassociate station */
		station->flags &= ~WIFI_STATION_FLAGS_ASSOCIATE;
	}

	return 1;
}

/* */
static int wifi_wlan_receive_ac_mgmt_deauthentication(struct wifi_wlan* wlan, struct ieee80211_header_mgmt* frame, int length) {
	int ielength;
	struct wifi_station* station;

	/* Information Elements packet length */
	ielength = length - (sizeof(struct ieee80211_header) + sizeof(frame->deauthetication));
	if (ielength < 0) {
		return 0;
	}

	/* Delete station */
	station = wifi_station_get(wlan, frame->da);
	if (station) {
		wifi_station_delete(station);
	}

	return 1;
}

/* */
static int wifi_wlan_receive_ac_mgmt_frame(struct wifi_wlan* wlan, struct ieee80211_header_mgmt* frame, int length, uint16_t framecontrol_subtype) {
	int forwardframe = 0;

	switch (framecontrol_subtype) {
		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTHENTICATION: {
			forwardframe = wifi_wlan_receive_ac_mgmt_authentication(wlan, frame, length);
			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_RESPONSE: {
			forwardframe = wifi_wlan_receive_ac_mgmt_association_response(wlan, frame, length);
			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_REASSOCIATION_RESPONSE: {
			forwardframe = wifi_wlan_receive_ac_mgmt_reassociation_response(wlan, frame, length);
			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DISASSOCIATION: {
			forwardframe = wifi_wlan_receive_ac_mgmt_disassociation(wlan, frame, length);
			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTHENTICATION: {
			forwardframe = wifi_wlan_receive_ac_mgmt_deauthentication(wlan, frame, length);
			break;
		}
	}

	return forwardframe;
}

/* */
int wifi_driver_init(struct capwap_timeout* timeout) {
	int i;

	ASSERT(timeout != NULL);

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
	g_wifiglobal.timeout = timeout;
	g_wifiglobal.devices = capwap_list_create();
	g_wifiglobal.stations = capwap_hash_create(WIFI_STATIONS_HASH_SIZE);
	g_wifiglobal.stations->item_gethash = wifi_hash_station_gethash;
	g_wifiglobal.stations->item_getkey = wifi_hash_station_getkey;
	g_wifiglobal.stations->item_cmp = wifi_hash_station_cmp;
	g_wifiglobal.stations->item_free = wifi_hash_station_free;

	return 0;
}

/* */
void wifi_driver_free(void) {
	int i;
	struct capwap_list_item* itemdevice;

	/* Free devices */
	if (g_wifiglobal.devices) {
		for (itemdevice = g_wifiglobal.devices->first; itemdevice != NULL; itemdevice = itemdevice->next) {
			struct wifi_device* device = (struct wifi_device*)itemdevice->item;

			/* Free WLANS */
			if (device->wlans) {
				while (device->wlans->first) {
					wifi_wlan_destroy((struct wifi_wlan*)device->wlans->first->item);
				}

				capwap_list_free(device->wlans);
			}

			/* */
			if (device->handle) {
				device->instance->ops->device_deinit(device);
			}

			/* Free capability */
			if (device->capability) {
				if (device->capability->bands) {
					for (i = 0; i < device->capability->bands->count; i++) {
						struct wifi_band_capability* bandcap = (struct wifi_band_capability*)capwap_array_get_item_pointer(device->capability->bands, i);

						if (bandcap->freq) {
							capwap_array_free(bandcap->freq);
						}

						if (bandcap->rate) {
							capwap_array_free(bandcap->rate);
						}
					}

					capwap_array_free(device->capability->bands);
				}

				if (device->capability->ciphers) {
					capwap_array_free(device->capability->ciphers);
				}

				capwap_free(device->capability);
			}
		}

		capwap_list_free(g_wifiglobal.devices);
	}

	/* Free stations */
	if (g_wifiglobal.stations) {
		capwap_hash_free(g_wifiglobal.stations);
	}

	/* Free driver */
	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		wifi_driver[i].ops->global_deinit(wifi_driver[i].handle);
	}

	/* */
	close(g_wifiglobal.sock_util);
}

/* */
int wifi_event_getfd(struct pollfd* fds, struct wifi_event* events, int count) {
	int i;
	int result = 0;
	struct capwap_list_item* itemdevice;
	struct capwap_list_item* itemwlan;

	if ((count > 0) && (!fds || !events)) {
		return -1;
	}

	/* Get from driver */
	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		result += wifi_driver[i].ops->global_getfdevent(wifi_driver[i].handle, (count ? &fds[result] : NULL), (count ? &events[result] : NULL));
	}

	/* Get from device */
	for (itemdevice = g_wifiglobal.devices->first; itemdevice != NULL; itemdevice = itemdevice->next) {
		struct wifi_device* device = (struct wifi_device*)itemdevice->item;
		if (device->handle) {
			result += device->instance->ops->device_getfdevent(device, (count ? &fds[result] : NULL), (count ? &events[result] : NULL));

			/* Get from wlan */
			if (device->wlans) {
				for (itemwlan = device->wlans->first; itemwlan != NULL; itemwlan = itemwlan->next) {
					struct wifi_wlan* wlan = (struct wifi_wlan*)itemwlan->item;

					if (wlan->handle) {
						result += device->instance->ops->wlan_getfdevent(wlan, (count ? &fds[result] : NULL), (count ? &events[result] : NULL));
					}
				}
			}
		}
	}

	return result;
}

/* */
struct wifi_wlan* wifi_get_wlan(uint32_t ifindex) {
	struct capwap_list_item* itemdevice;
	struct capwap_list_item* itemwlan;

	ASSERT(g_wifiglobal.devices != NULL);
	ASSERT(ifindex > 0);

	/* Search device */
	for (itemdevice = g_wifiglobal.devices->first; itemdevice != NULL; itemdevice = itemdevice->next) {
		struct wifi_device* device = (struct wifi_device*)itemdevice->item;

		/* Search wlan */
		if (device->wlans) {
			for (itemwlan = device->wlans->first; itemwlan != NULL; itemwlan = itemwlan->next) {
				struct wifi_wlan* wlan = (struct wifi_wlan*)itemwlan->item;

				if (wlan->virtindex == ifindex) {
					return wlan;
				}
			}
		}
	}

	return NULL;
}

/* */
struct wifi_device* wifi_device_connect(const char* ifname, const char* driver) {
	int i;
	int length;
	struct capwap_list_item* itemdevice;
	struct wifi_device* device = NULL;

	ASSERT(ifname != NULL);
	ASSERT(driver != NULL);

	/* Check */
	length = strlen(ifname);
	if ((length <= 0) || (length >= IFNAMSIZ)) {
		capwap_logging_warning("Wifi device name error: %s", ifname);
		return NULL;
	}

	/* Search driver */
	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		if (!strcmp(driver, wifi_driver[i].ops->name)) {
			itemdevice = capwap_itemlist_create(sizeof(struct wifi_device));
			device = (struct wifi_device*)itemdevice->item;
			memset(device, 0, sizeof(struct wifi_device));

			/* */
			device->global = &g_wifiglobal;
			device->instance = &wifi_driver[i];
			strcpy(device->phyname, ifname);

			/* Device init */
			if (!wifi_driver[i].ops->device_init(wifi_driver[i].handle, device)) {
				/* Registered new device */
				device->wlans = capwap_list_create();

				/* Device capability */
				device->capability = (struct wifi_capability*)capwap_alloc(sizeof(struct wifi_capability));
				memset(device->capability, 0, sizeof(struct wifi_capability));
				device->capability->bands = capwap_array_create(sizeof(struct wifi_band_capability), 0, 1);
				device->capability->ciphers = capwap_array_create(sizeof(struct wifi_cipher_capability), 0, 1);

				/* Retrieve device capability */
				device->instance->ops->device_getcapability(device, device->capability);

				/* Appent to device list */
				capwap_itemlist_insert_after(g_wifiglobal.devices, NULL, itemdevice);
			} else {
				capwap_itemlist_free(itemdevice);
				device = NULL;
			}

			break;
		}
	}

	return device;
}

/* */
const struct wifi_capability* wifi_device_getcapability(struct wifi_device* device) {
	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);

	return device->capability;
}

/* */
int wifi_device_setconfiguration(struct wifi_device* device, struct device_setconfiguration_params* params) {
	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);
	ASSERT(params != NULL);

	/* */
	device->flags |= WIFI_DEVICE_SET_CONFIGURATION;
	device->beaconperiod = params->beaconperiod;
	device->dtimperiod = params->dtimperiod;
	device->shortpreamble = (params->shortpreamble ? 1 : 0);

	/* Update beacons */
	if (device->wlans->count) {
		device->instance->ops->device_updatebeacons(device);
	}

	return 0;
}

/* */
int wifi_device_setfrequency(struct wifi_device* device, uint32_t band, uint32_t mode, uint8_t channel) {
	int i, j;
	int result = -1;
	const struct wifi_capability* capability;
	uint32_t frequency = 0;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);

	/* Capability device */
	capability = wifi_device_getcapability(device);
	if (!capability || !(capability->flags & WIFI_CAPABILITY_RADIOTYPE) || !(capability->flags & WIFI_CAPABILITY_BANDS)) {
		return -1;
	}

	/* Search frequency */
	for (i = 0; (i < capability->bands->count) && !frequency; i++) {
		struct wifi_band_capability* bandcap = (struct wifi_band_capability*)capwap_array_get_item_pointer(capability->bands, i);

		if (bandcap->band == band) {
			for (j = 0; j < bandcap->freq->count; j++) {
				struct wifi_freq_capability* freqcap = (struct wifi_freq_capability*)capwap_array_get_item_pointer(bandcap->freq, j);
				if (freqcap->channel == channel) {
					frequency = freqcap->frequency;
					break;
				}
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
		if (device->currentfrequency.band == WIFI_BAND_2GHZ) {
			device->currentfrequency.mode &= ~CAPWAP_RADIO_TYPE_80211A;
		} else if (device->currentfrequency.band == WIFI_BAND_5GHZ) {
			device->currentfrequency.mode &= ~(CAPWAP_RADIO_TYPE_80211B | CAPWAP_RADIO_TYPE_80211G);
		}

		/* Set frequency */
		device->flags |= WIFI_DEVICE_SET_FREQUENCY;
		result = device->instance->ops->device_setfrequency(device);
	}

	/* */
	return result;
}

int wifi_device_settxqueue(struct wifi_device *device, struct capwap_80211_wtpqos_element *qos)
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

		if (device->instance->ops->device_settxqueue(device, i,
							     qos->qos[i].aifs,
							     qos->qos[i].cwmin,
							     qos->qos[i].cwmax, txop) < 0)
			return -1;
	}
	return 0;
}

/* */
int wifi_device_updaterates(struct wifi_device* device, uint8_t* rates, int ratescount) {
	struct device_setrates_params buildrate;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);
	ASSERT(rates != NULL);
	ASSERT(ratescount > 0);

	/* */
	wifi_wlan_getrates(device, rates, ratescount, &buildrate);
	if (!buildrate.supportedratescount || (buildrate.supportedratescount > IEEE80211_SUPPORTEDRATE_MAX_COUNT)) {
		capwap_logging_debug("update rates: supported rates failed, (%d .. %d)", buildrate.supportedratescount, IEEE80211_SUPPORTEDRATE_MAX_COUNT);
		return -1;
	} else if (!buildrate.basicratescount || (buildrate.basicratescount > IEEE80211_SUPPORTEDRATE_MAX_COUNT)) {
		capwap_logging_debug("update rates: basic rates failed: %d", buildrate.basicratescount);
		return -1;
	}

	/* Set new rates */
	device->flags |= WIFI_DEVICE_SET_RATES;
	memcpy(device->supportedrates, buildrate.supportedrates, buildrate.supportedratescount);
	device->supportedratescount = buildrate.supportedratescount;
	memcpy(device->basicrates, buildrate.basicrates, buildrate.basicratescount);
	device->basicratescount = buildrate.basicratescount;

	/* Update beacons */
	if (device->wlans->count) {
		device->instance->ops->device_updatebeacons(device);
	}

	return 0;
}

/* */
struct wifi_wlan* wifi_wlan_create(struct wifi_device* device, const char* ifname) {
	int length;
	struct wifi_wlan* wlan;
	struct capwap_list_item* itemwlan;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);
	ASSERT(ifname != NULL);

	/* Check */
	length = strlen(ifname);
	if ((length <= 0) || (length >= IFNAMSIZ)) {
		capwap_logging_warning("Wifi device name error: %s", ifname);
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
	wlan->handle = device->instance->ops->wlan_create(device, wlan);
	if (!wlan->handle) {
		capwap_logging_warning("Unable to create virtual interface: %s", ifname);
		wifi_wlan_destroy(wlan);
		return NULL;
	}

	/* Interface info */
	wlan->virtindex = wifi_iface_index(ifname);
	if (wifi_iface_hwaddr(g_wifiglobal.sock_util, wlan->virtname, wlan->address)) {
		capwap_logging_warning("Unable to get macaddress: %s", ifname);
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

/* */
int wifi_wlan_startap(struct wifi_wlan* wlan, struct wlan_startap_params* params) {
	int result;

	ASSERT(wlan != NULL);
	ASSERT(wlan->device != NULL);
	ASSERT(params != NULL);

	/* Check device */
	if ((wlan->flags & WIFI_WLAN_RUNNING) || ((wlan->device->flags & WIFI_DEVICE_REQUIRED_FOR_BSS) != WIFI_DEVICE_REQUIRED_FOR_BSS)) {
		return -1;
	}

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

	build_80211_ie(wlan->radioid, wlan->wlanid,
		       CAPWAP_IE_BEACONS_ASSOCIATED,
		       params->ie,
		       &wlan->beacon_ies, &wlan->beacon_ies_len);
	build_80211_ie(wlan->radioid, wlan->wlanid,
		       CAPWAP_IE_PROBE_RESPONSE_ASSOCIATED,
		       params->ie,
		       &wlan->response_ies, &wlan->response_ies_len);

	/* Start AP */
	result = wlan->device->instance->ops->wlan_startap(wlan);
	if (!result) {
		wlan->device->wlanactive++;
		capwap_logging_info("Configured interface: %s, SSID: '%s'", wlan->virtname, wlan->ssid);
	} else {
		wifi_wlan_stopap(wlan);
	}

	return result;
}

/* */
void wifi_wlan_stopap(struct wifi_wlan* wlan) {
	ASSERT(wlan != NULL);
	ASSERT(wlan->device != NULL);

	/* Stop AP */
	wlan->device->instance->ops->wlan_stopap(wlan);

	free(wlan->beacon_ies);
	wlan->beacon_ies = NULL;
	free(wlan->response_ies);
	wlan->response_ies = NULL;

	/* */
	if (wlan->flags & WIFI_WLAN_RUNNING) {
		wlan->device->wlanactive--;
	}

	/* */
	wlan->flags = 0;

	/* TODO: Remove all stations from hash */
}

/* */
int wifi_wlan_getbssid(struct wifi_wlan* wlan, uint8_t* bssid) {
	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);
	ASSERT(bssid != NULL);

	memcpy(bssid, wlan->address, MACADDRESS_EUI48_LENGTH);
	return 0;
}

/* */
uint16_t wifi_wlan_check_capability(struct wifi_wlan* wlan, uint16_t capability) {
	uint16_t result = capability;

	/* Force ESS capability */
	result |= IEEE80211_CAPABILITY_ESS;

	/* Check short preamble capability */
	if (wlan->device->shortpreamble && !wlan->device->stationsnoshortpreamblecount) {
		result |= IEEE80211_CAPABILITY_SHORTPREAMBLE;
	} else {
		result &= ~IEEE80211_CAPABILITY_SHORTPREAMBLE;
	}

	/* Check privacy capability */
	/* TODO */

	/* Check short slot time capability */
	if ((wlan->device->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G) && !wlan->device->stationsnoshortslottimecount) {
		result |= IEEE80211_CAPABILITY_SHORTSLOTTIME;
	} else {
		result &= ~IEEE80211_CAPABILITY_SHORTSLOTTIME;
	}

	return result;
}

/* */
void wifi_wlan_destroy(struct wifi_wlan* wlan) {
	struct capwap_list_item* itemwlan;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);

	/* Terminate service */
	wifi_wlan_stopap(wlan);

	/* */
	wlan->device->instance->ops->wlan_delete(wlan);

	/* Remove wlan from device's list */
	for (itemwlan = wlan->device->wlans->first; itemwlan; itemwlan = itemwlan->next) {
		if (wlan == (struct wifi_wlan*)itemwlan->item) {
			capwap_itemlist_free(capwap_itemlist_remove(wlan->device->wlans, itemwlan));
			break;
		}
	}
}

/* */
void wifi_wlan_receive_station_frame(struct wifi_wlan* wlan, const struct ieee80211_header* frame, int length, uint32_t frequency, uint8_t rssi, uint8_t snr, uint16_t rate) {
	uint16_t framecontrol;
	uint16_t framecontrol_type;
	uint16_t framecontrol_subtype;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);

	/* Check frame */
	if (!frame || (length < sizeof(struct ieee80211_header))) {
		return;
	}

	/* Get type frame */
	framecontrol = __le16_to_cpu(frame->framecontrol);
	framecontrol_type = IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol);
	framecontrol_subtype = IEEE80211_FRAME_CONTROL_GET_SUBTYPE(framecontrol);

	/* Parsing frame */
	if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_MGMT) {
		wifi_wlan_receive_station_mgmt_frame(wlan, (const struct ieee80211_header_mgmt*)frame, length, framecontrol_subtype, frequency, rssi, snr, rate);
	}
}

/* */
void wifi_wlan_receive_station_ackframe(struct wifi_wlan* wlan, const struct ieee80211_header* frame, int length, int ack) {
	uint16_t framecontrol;
	uint16_t framecontrol_type;
	uint16_t framecontrol_subtype;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);

	/* Check frame */
	if (!frame || (length < sizeof(struct ieee80211_header))) {
		return;
	}

	/* Get type frame */
	framecontrol = __le16_to_cpu(frame->framecontrol);
	framecontrol_type = IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol);
	framecontrol_subtype = IEEE80211_FRAME_CONTROL_GET_SUBTYPE(framecontrol);

	/* Parsing frame */
	if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_MGMT) {
		wifi_wlan_receive_station_mgmt_ackframe(wlan, (const struct ieee80211_header_mgmt*)frame, length, framecontrol_subtype, ack);
	}
}

/* */
void wifi_wlan_receive_ac_frame(struct wifi_wlan* wlan, struct ieee80211_header* frame, int length) {
	int forwardframe = 1;
	uint16_t framecontrol;
	uint16_t framecontrol_type;
	uint16_t framecontrol_subtype;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);

	/* Check frame */
	if (!frame || (length < sizeof(struct ieee80211_header))) {
		return;
	}

	/* Get type frame */
	framecontrol = __le16_to_cpu(frame->framecontrol);
	framecontrol_type = IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol);
	framecontrol_subtype = IEEE80211_FRAME_CONTROL_GET_SUBTYPE(framecontrol);

	/* Parsing frame */
	if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_MGMT) {
		forwardframe = wifi_wlan_receive_ac_mgmt_frame(wlan, (struct ieee80211_header_mgmt*)frame, length, framecontrol_subtype);
	}

	/* Forward frame */
	if (forwardframe) {
		int nowaitack = (ieee80211_is_broadcast_addr(ieee80211_get_da_addr(frame)) ? 1 : 0);
		wlan->device->instance->ops->wlan_sendframe(wlan, (uint8_t*)frame, length, wlan->device->currentfrequency.frequency, 0, 0, 0, nowaitack);
	}
}

/* */
int wifi_wlan_send_frame(struct wifi_wlan* wlan, const uint8_t* data, int length, uint8_t rssi, uint8_t snr, uint16_t rate) {
	int result;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);

	if (!data || (length <= 0)) {
		return -1;
	}

	/* Send packet to AC */
	result = wtp_kmod_send_data(wlan->radioid, data, length, rssi, snr, rate);
	if (result) {
		capwap_logging_warning("Unable to sent packet to AC: %d error code", result);
	}

	return result;
}

/* */
int wifi_station_authorize(struct wifi_wlan* wlan, struct station_add_params* params) {
	int result;
	struct wifi_station* station;

	ASSERT(wlan != NULL);
	ASSERT(wlan->device != NULL);
	ASSERT(params != NULL);

	/* Get station */
	station = wifi_station_get(wlan, params->address);
	if (!station) {
		return -1;
	} else if (station->flags & WIFI_STATION_FLAGS_AUTHORIZED) {
		return 0;
	}

	/* */
	capwap_timeout_deletetimer(g_wifiglobal.timeout, station->idtimeout);
	station->idtimeout = CAPWAP_TIMEOUT_INDEX_NO_SET;

	/* Station is authorized only after Authentication and Association */
	station->flags |= WIFI_STATION_FLAGS_AUTHORIZED;
	if (!(station->flags & WIFI_STATION_FLAGS_AUTHENTICATED) ||
	    !(station->flags & WIFI_STATION_FLAGS_ASSOCIATE))
		return 0;

	if (params->ht_cap) {
		memcpy(&station->ht_cap, params->ht_cap, sizeof(station->ht_cap));
		station->flags |= WIFI_STATION_FLAGS_HT_CAP;
	}

	/* Station authorized */
	result = wlan->device->instance->ops->station_authorize(wlan, station);
	if (result) {
		wifi_wlan_deauthentication_station(wlan, station, IEEE80211_REASON_PREV_AUTH_NOT_VALID, 0);
	}

	return result;
}

/* */
void wifi_station_deauthorize(struct wifi_device* device, const uint8_t* address) {
	struct wifi_station* station;

	ASSERT(device != NULL);
	ASSERT(address != NULL);

	/* */
	station = wifi_station_get(NULL, address);
	if (station && station->wlan) {
		wifi_wlan_deauthentication_station(station->wlan, station, IEEE80211_REASON_PREV_AUTH_NOT_VALID, 0);
	}
}

/* */
uint32_t wifi_iface_index(const char* ifname) {
	if (!ifname || !*ifname) {
		return 0;
	}

	return if_nametoindex(ifname);
}

/* */
int wifi_iface_getstatus(int sock, const char* ifname) {
	struct ifreq ifreq;

	ASSERT(sock > 0);
	ASSERT(ifname != NULL);
	ASSERT(*ifname != 0);

	/* Change link state of interface */
	memset(&ifreq, 0, sizeof(ifreq));
	strcpy(ifreq.ifr_name, ifname);
	if (!ioctl(sock, SIOCGIFFLAGS, &ifreq)) {
		return ((ifreq.ifr_flags & IFF_UP) ? 1: 0);
	}

	return -1;
}

/* */
int wifi_iface_updown(int sock, const char* ifname, int up) {
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

/* */
int wifi_iface_hwaddr(int sock, const char* ifname, uint8_t* hwaddr) {
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
int wifi_frequency_to_radiotype(uint32_t freq) {
	if ((freq >= 2412) && (freq <= 2472)) {
		return CAPWAP_RADIO_TYPE_80211G;
	} else if (freq == 2484) {
		return CAPWAP_RADIO_TYPE_80211B;
	} else if ((freq >= 4915) && (freq <= 4980)) {
		return CAPWAP_RADIO_TYPE_80211A;
	} else if ((freq >= 5035) && (freq <= 5825)) {
		return CAPWAP_RADIO_TYPE_80211A;
	}

	return -1;
}
