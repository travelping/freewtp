#include "capwap.h"
#include "capwap_array.h"
#include "capwap_element.h"
#include "wtp_radio.h"
#include "wifi_drivers.h"

/* Declare enable wifi driver */
#ifdef ENABLE_WIFI_DRIVERS_NL80211
extern struct wifi_driver_ops wifi_driver_nl80211_ops;
#endif

static struct wifi_driver_instance wifi_driver[] = {
#ifdef ENABLE_WIFI_DRIVERS_NL80211
	{ &wifi_driver_nl80211_ops },
#endif
	{ NULL }
};

/* Radio instance */
static struct capwap_array* g_wifidevice = NULL;

/* */
int wifi_driver_init(void) {
	int i;

	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		/* Initialize driver */
		ASSERT(wifi_driver[i].ops->global_init != NULL);
		wifi_driver[i].handle = wifi_driver[i].ops->global_init();
		if (!wifi_driver[i].handle) {
			return -1;
		}
	}

	/* Device handler */
	g_wifidevice = capwap_array_create(sizeof(struct wifi_device), 0, 1);

	return 0;
}

/* */
void wifi_driver_free(void) {
	unsigned long i;
	unsigned long j;

	/* Free device */
	if (g_wifidevice) {
		for (i = 0; i < g_wifidevice->count; i++) {
			struct wifi_device* device = (struct wifi_device*)capwap_array_get_item_pointer(g_wifidevice, i);

			if (device->wlan) {
				if (device->instance->ops->wlan_delete != NULL) {
					for (j = 0; j < device->wlan->count; j++) {
						struct wifi_wlan* wlan = (struct wifi_wlan*)capwap_array_get_item_pointer(device->wlan, j);

						if (wlan->handle) {
							device->instance->ops->wlan_delete(wlan->handle);
						}
					}
				}

				capwap_array_free(device->wlan);
			}

			if (device->handle && device->instance->ops->device_deinit) {
				device->instance->ops->device_deinit(device->handle);
			}
		}

		capwap_array_free(g_wifidevice);
	}

	/* Free driver */
	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		if (wifi_driver[i].ops->global_deinit) {
			wifi_driver[i].ops->global_deinit(wifi_driver[i].handle);
		}
	}
}

/* */
int wifi_event_getfd(struct pollfd* fds, struct wifi_event* events, int count) {
	int i, j;
	int result = 0;

	if ((count > 0) && (!fds || !events)) {
		return -1;
	}

	/* Get from driver */
	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		if (wifi_driver[i].ops->global_getfdevent) {
			result += wifi_driver[i].ops->global_getfdevent(wifi_driver[i].handle, (count ? &fds[result] : NULL), (count ? &events[result] : NULL));
		}
	}

	/* Get from device */
	for (i = 0; i < g_wifidevice->count; i++) {
		struct wifi_device* device = (struct wifi_device*)capwap_array_get_item_pointer(g_wifidevice, i);
		if (device->handle) {
			if (device->instance->ops->device_getfdevent) {
				result += device->instance->ops->device_getfdevent(device->handle, (count ? &fds[result] : NULL), (count ? &events[result] : NULL));
			}

			/* Get from wlan */
			if (device->instance->ops->wlan_getfdevent) {
				for (j = 0; j < device->wlan->count; j++) {
					struct wifi_wlan* wlan = (struct wifi_wlan*)capwap_array_get_item_pointer(device->wlan, j);

					if (wlan->handle) {
						result += device->instance->ops->wlan_getfdevent(wlan->handle, (count ? &fds[result] : NULL), (count ? &events[result] : NULL));
					}
				}
			}
		}
	}

	return result;
}

/* */
int wifi_device_connect(int radioid, const char* ifname, const char* driver) {
	int i;
	int length;
	int result = -1;

	ASSERT(radioid > 0);
	ASSERT(ifname != NULL);
	ASSERT(driver != NULL);

	/* Check */
	length = strlen(ifname);
	if ((length <= 0) || (length >= IFNAMSIZ)) {
		capwap_logging_warning("Wifi device name error: %s", ifname);
		return -1;
	} else if (g_wifidevice->count >= radioid) {
		struct wifi_device* device = (struct wifi_device*)capwap_array_get_item_pointer(g_wifidevice, radioid);

		if (device->handle) {
			capwap_logging_warning("Wifi device RadioID already used: %d", radioid);
			return -1;
		}
	}

	/* Search driver */
	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		if (!strcmp(driver, wifi_driver[i].ops->name)) {
			wifi_device_handle devicehandle;
			struct device_init_params params = {
				.ifname = ifname
			};

			/* Device init */
			ASSERT(wifi_driver[i].ops->device_init);
			devicehandle = wifi_driver[i].ops->device_init(wifi_driver[i].handle, &params);
			if (devicehandle) {
				/* Register new device */
				struct wifi_device* device = (struct wifi_device*)capwap_array_get_item_pointer(g_wifidevice, radioid);
				device->handle = devicehandle;
				device->instance = &wifi_driver[i];
				device->wlan = capwap_array_create(sizeof(struct wifi_wlan), 0, 1);

				result = 0;
			}

			break;
		}
	}

	return result;
}

/* */
static struct wifi_wlan* wifi_wlan_getdevice(int radioid, int wlanid) {
	struct wifi_device* device;

	ASSERT(radioid > 0);
	ASSERT(wlanid > 0);

	if (g_wifidevice->count < radioid) {
		return NULL;
	}

	/* Get radio connection */
	device = (struct wifi_device*)capwap_array_get_item_pointer(g_wifidevice, radioid);
	if (device->wlan->count < wlanid) {
		return NULL;
	}

	/* */
	if (device->wlan->count < wlanid) {
		return NULL;
	}

	/* Return wlan connection */
	return (struct wifi_wlan*)capwap_array_get_item_pointer(device->wlan, wlanid);
}

/* */
int wifi_wlan_create(int radioid, int wlanid, const char* ifname, uint8_t* bssid) {
	int length;
	struct wifi_device* device;
	struct wifi_wlan* wlan;
	wifi_wlan_handle wlanhandle;
	struct wlan_init_params params = {
		.ifname = ifname,
		.type = WLAN_INTERFACE_AP
	};

	ASSERT(radioid > 0);
	ASSERT(wlanid > 0);
	ASSERT(ifname != NULL);
	//ASSERT(bssid != NULL);

	/* Check */
	length = strlen(ifname);
	if ((length <= 0) || (length >= IFNAMSIZ)) {
		capwap_logging_warning("Wifi device name error: %s", ifname);
		return -1;
	} else if (g_wifidevice->count < radioid) {
		capwap_logging_warning("Wifi device RadioID %d is not connected", radioid);
		return -1;
	}

	/* Get radio connection */
	device = (struct wifi_device*)capwap_array_get_item_pointer(g_wifidevice, radioid);
	if (!device->handle) {
		capwap_logging_warning("Wifi device RadioID %d is not connected", radioid);
		return -1;
	} else if (device->wlan->count >= wlanid) {
		wlan = (struct wifi_wlan*)capwap_array_get_item_pointer(device->wlan, wlanid);
		if (wlan->handle) {
			capwap_logging_warning("WLAN interface already used: %d", wlanid);
			return -1;
		}
	} else if (!device->instance->ops->wlan_create) {
		capwap_logging_warning("%s library don't support wlan_create", device->instance->ops->name);
		return -1;
	}

	/* Create interface */
	wlanhandle = device->instance->ops->wlan_create(device->handle, &params);
	if (!wlanhandle) {
		capwap_logging_warning("Unable to create virtual interface: %s", ifname);
		return -1;
	}

	/* */
	wlan = (struct wifi_wlan*)capwap_array_get_item_pointer(device->wlan, wlanid);
	wlan->handle = wlanhandle;
	wlan->device = device;

	return 0;
}

/* */
static void wifi_wlan_getrates(struct wifi_device* device, struct wtp_radio* radio) {
	int i, j, w;
	int radiotype;
	uint32_t mode = 0;
	const struct wifi_capability* capability; 

	ASSERT(device != NULL);
	ASSERT(radio != NULL);

	/* Free old supported rates */
	device->supportedratescount = 0;

	/* Retrieve capability */
	capability = wifi_device_getcapability(radio->radioid);
	if (!capability) {
		return;
	}

	/* Get radio type for basic rate */
	radiotype = wifi_frequency_to_radiotype(device->currentfreq.frequency);
	if (radiotype < 0) {
		return;
	}

	/* Check type of rate mode */
	for (i = 0; i < radio->rateset.ratesetcount; i++) {
		if (device->currentfreq.band == WIFI_BAND_2GHZ) {
			if (IS_IEEE80211_RATE_B(radio->rateset.rateset[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211B;
			} else if (IS_IEEE80211_RATE_G(radio->rateset.rateset[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211G;
			} else if (IS_IEEE80211_RATE_N(radio->rateset.rateset[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211N;
			}
		} else if (device->currentfreq.band == WIFI_BAND_5GHZ) {
			if (IS_IEEE80211_RATE_A(radio->rateset.rateset[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211A;
			} else if (IS_IEEE80211_RATE_N(radio->rateset.rateset[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211N;
			}
		}
	}

	/* Add implicit 802.11b rate with only 802.11g rate */
	if ((device->currentfreq.band == WIFI_BAND_2GHZ) && !(mode & CAPWAP_RADIO_TYPE_80211B) && (device->currentfreq.mode & CAPWAP_RADIO_TYPE_80211B)) {
		device->supportedrates[device->supportedratescount++] = IEEE80211_RATE_1M;
		device->supportedrates[device->supportedratescount++] = IEEE80211_RATE_2M;
		device->supportedrates[device->supportedratescount++] = IEEE80211_RATE_5_5M;
		device->supportedrates[device->supportedratescount++] = IEEE80211_RATE_11M;
	}

	/* Filter band */
	for (i = 0; i < capability->bands->count; i++) {
		struct wifi_band_capability* bandcap = (struct wifi_band_capability*)capwap_array_get_item_pointer(capability->bands, i);

		if (bandcap->band == device->currentfreq.band) {
			for (j = 0; j < bandcap->rate->count; j++) {
				struct wifi_rate_capability* rate = (struct wifi_rate_capability*)capwap_array_get_item_pointer(bandcap->rate, j);

				/* Validate rate */
				for (w = 0; w < radio->rateset.ratesetcount; w++) {
					if (radio->rateset.rateset[w] == rate->bitrate) {
						device->supportedrates[device->supportedratescount++] = rate->bitrate;
						break;
					}
				}
			}

			break;
		}
	}

	/* Apply basic rate */
	for (i = 0; i < device->supportedratescount; i++) {
		if (radiotype == CAPWAP_RADIO_TYPE_80211A) {
			if (IS_IEEE80211_BASICRATE_A(device->supportedrates[i])) {
				device->supportedrates[i] |= IEEE80211_BASICRATE;
			}
		} else if (radiotype == CAPWAP_RADIO_TYPE_80211B) {
			if (IS_IEEE80211_BASICRATE_B(device->supportedrates[i])) {
				device->supportedrates[i] |= IEEE80211_BASICRATE;
			}
		} else if (radiotype == CAPWAP_RADIO_TYPE_80211G) {
			if (IS_IEEE80211_BASICRATE_G(device->supportedrates[i])) {
				device->supportedrates[i] |= IEEE80211_BASICRATE;
			}
		}
	}

	/* Add implicit 802.11n rate with only 802.11a/g rate */
	if (!(mode & CAPWAP_RADIO_TYPE_80211N) && (device->currentfreq.mode & CAPWAP_RADIO_TYPE_80211N)) {
		device->supportedrates[device->supportedratescount++] = IEEE80211_RATE_80211N;
	}
}

/* */
int wifi_wlan_setupap(int radioid, int wlanid) {
	struct wifi_wlan* wlan;

	ASSERT(radioid > 0);
	ASSERT(wlanid > 0);

	/* */
	wlan = wifi_wlan_getdevice(radioid, wlanid);
	if (!wlan || !wlan->device->instance->ops->wlan_setupap) {
		return -1;
	}

	return wlan->device->instance->ops->wlan_setupap(wlan->handle);
}

/* */
int wifi_wlan_startap(int radioid, int wlanid) {
	struct wifi_wlan* wlan;
	struct wtp_radio* radio;
	struct wtp_radio_wlan* radiowlan;
	struct wlan_startap_params wlan_params;

	ASSERT(radioid > 0);
	ASSERT(wlanid > 0);

	/* */
	wlan = wifi_wlan_getdevice(radioid, wlanid);
	radio = wtp_radio_get_phy(radioid);
	if (!wlan || !radio || !wlan->device->instance->ops->wlan_startap) {
		return -1;
	}

	/* */
	radiowlan = wtp_radio_get_wlan(radio, wlanid);
	if (!radiowlan) {
		return -1;
	}

	/* Retrieve supported rates */
	wifi_wlan_getrates(wlan->device, radiowlan->radio);

	/* Start AP */
	memset(&wlan_params, 0, sizeof(struct wlan_startap_params));
	wlan_params.ssid = radiowlan->ssid;
	wlan_params.ssid_hidden = radiowlan->ssid_hidden;
	wlan_params.beaconperiod = radio->radioconfig.beaconperiod;
	wlan_params.capability = radiowlan->capability;
	wlan_params.dtimperiod = radio->radioconfig.dtimperiod;
	memcpy(wlan_params.supportedrates, wlan->device->supportedrates, wlan->device->supportedratescount);
	wlan_params.supportedratescount = wlan->device->supportedratescount;
	wlan_params.authenticationtype = radiowlan->authmode;

	return wlan->device->instance->ops->wlan_startap(wlan->handle, &wlan_params);
}

/* */
int wifi_wlan_stopap(int radioid, int wlanid) {
	struct wifi_wlan* wlan;

	/* */
	wlan = wifi_wlan_getdevice(radioid, wlanid);
	if (!wlan->device->instance->ops->wlan_stopap) {
		return -1;
	}

	return wlan->device->instance->ops->wlan_stopap(wlan->handle);
}

/* */
int wifi_wlan_getbssid(int radioid, int wlanid, uint8_t* bssid) {
	struct wifi_wlan* wlan;

	/* */
	wlan = wifi_wlan_getdevice(radioid, wlanid);
	if (!wlan->device->instance->ops->wlan_getmacaddress) {
		return -1;
	}

	return wlan->device->instance->ops->wlan_getmacaddress(wlan->handle, bssid);
}

/* */
void wifi_wlan_destroy(int radioid, int wlanid) {
	struct wifi_wlan* wlan;

	ASSERT(radioid > 0);
	ASSERT(wlanid > 0);

	wlan = wifi_wlan_getdevice(radioid, wlanid);
	if (wlan && wlan->handle) {
		if (wlan->device->instance->ops->wlan_delete) {
			wlan->device->instance->ops->wlan_delete(wlan->handle);
		}

		memset(wlan, 0, sizeof(struct wifi_wlan));
	}
}

/* */
const struct wifi_capability* wifi_device_getcapability(int radioid) {
	struct wifi_device* device;

	ASSERT(radioid > 0);

	if (g_wifidevice->count <= radioid) {
		return NULL;
	}

	/* Retrieve cached capability */
	device = (struct wifi_device*)capwap_array_get_item_pointer(g_wifidevice, radioid);
	if (!device->handle || !device->instance->ops->device_getcapability) {
		return NULL;
	}

	return device->instance->ops->device_getcapability(device->handle);
}

/* */
int wifi_device_setfrequency(int radioid, uint32_t band, uint32_t mode, uint8_t channel) {
	int i, j;
	int result = -1;
	const struct wifi_capability* capability;
	uint32_t frequency = 0;

	ASSERT(radioid > 0);

	if (g_wifidevice->count <= radioid) {
		return -1;
	}

	/* Capability device */
	capability = wifi_device_getcapability(radioid);
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
		struct wifi_device* device = (struct wifi_device*)capwap_array_get_item_pointer(g_wifidevice, radioid);

		memset(&device->currentfreq, 0, sizeof(struct wifi_frequency));
		device->currentfreq.band = band;
		device->currentfreq.mode = mode;
		device->currentfreq.channel = channel;
		device->currentfreq.frequency = frequency;

		/* According to the selected band remove the invalid mode */
		if (device->currentfreq.band == WIFI_BAND_2GHZ) {
			device->currentfreq.mode &= ~CAPWAP_RADIO_TYPE_80211A;
		} else if (device->currentfreq.band == WIFI_BAND_5GHZ) {
			device->currentfreq.mode &= ~(CAPWAP_RADIO_TYPE_80211B | CAPWAP_RADIO_TYPE_80211G);
		}

		/* Set frequency */
		device = (struct wifi_device*)capwap_array_get_item_pointer(g_wifidevice, radioid);
		if (device->handle && device->instance->ops->device_setfrequency) {
			result = device->instance->ops->device_setfrequency(device->handle, &device->currentfreq);
		}
	}

	/* */
	return result;
}

/* */
uint32_t wifi_iface_index(const char* ifname) {
	if (!ifname || !*ifname) {
		return 0;
	}

	return if_nametoindex(ifname);
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
		if (up) {
			ifreq.ifr_flags |= IFF_UP;
		} else {
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
			memcpy(hwaddr, ifreq.ifr_hwaddr.sa_data, ETH_ALEN);
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

/* */
unsigned long wifi_frequency_to_channel(uint32_t freq) {
	if ((freq >= 2412) && (freq <= 2472)) {
		return (freq - 2407) / 5;
	} else if (freq == 2484) {
		return 14;
	} else if ((freq >= 4915) && (freq <= 4980)) {
		return (freq - 4000) / 5;
	} else if ((freq >= 5035) && (freq <= 5825)) {
		return (freq - 5000) / 5;
	}

	return 0;
}

/* */
int wifi_is_broadcast_addr(const uint8_t* addr) {
	return (((addr[0] == 0xff) && (addr[1] == 0xff) && (addr[2] == 0xff) && (addr[3] == 0xff) && (addr[4] == 0xff) && (addr[5] == 0xff)) ? 1 : 0);
}

/* */
int wifi_is_valid_ssid(const char* ssid, struct ieee80211_ie_ssid* iessid, struct ieee80211_ie_ssid_list* isssidlist) {
	int ssidlength;

	ASSERT(ssid != NULL);
	ASSERT(iessid != NULL);

	/* Check SSID */
	ssidlength = strlen((char*)ssid);
	if ((ssidlength == iessid->len) && !memcmp(ssid, iessid->ssid, ssidlength)) {
		return WIFI_VALID_SSID;
	}

	/* Check SSID list */
	if (isssidlist) {
		int length = isssidlist->len;
		uint8_t* pos = isssidlist->lists;

		while (length >= sizeof(struct ieee80211_ie)) {
			struct ieee80211_ie_ssid* ssiditem = (struct ieee80211_ie_ssid*)pos;

			/* Check buffer */
			length -= sizeof(struct ieee80211_ie);
			if ((ssiditem->id != IEEE80211_IE_SSID) || !ssiditem->len || (length < ssiditem->len)) {
				break;
			} else if ((ssidlength == ssiditem->len) && !memcmp(ssid, ssiditem->ssid, ssidlength)) {
				return WIFI_VALID_SSID;
			}

			/* Next */
			length -= ssiditem->len;
			pos += sizeof(struct ieee80211_ie) + ssiditem->len;
		}
	}

	return (!iessid->len ? WIFI_WILDCARD_SSID : WIFI_WRONG_SSID);
}

/* */
int wifi_retrieve_information_elements_position(struct ieee80211_ie_items* items, const uint8_t* data, int length) {
	ASSERT(items != NULL);
	ASSERT(data != NULL);

	/* */
	memset(items, 0, sizeof(struct ieee80211_ie_items));

	/* Parsing */
	while (length >= 2) {
		uint8_t ie_id = data[0];
		uint8_t ie_len = data[1];

		/* Parsing Information Element */
		switch (ie_id) {
			case IEEE80211_IE_SSID: {
				if (ie_len > IEEE80211_IE_SSID_MAX_LENGTH) {
					return -1;
				}

				items->ssid = (struct ieee80211_ie_ssid*)data;
				break;
			}

			case IEEE80211_IE_SUPPORTED_RATES: {
				if ((ie_len < IEEE80211_IE_SUPPORTED_RATES_MIN_LENGTH) || (ie_len > IEEE80211_IE_SUPPORTED_RATES_MAX_LENGTH)) {
					return -1;
				}

				items->supported_rates = (struct ieee80211_ie_supported_rates*)data;
				break;
			}

			case IEEE80211_IE_DSSS: {
				if (ie_len != IEEE80211_IE_DSSS_LENGTH) {
					return -1;
				}

				items->dsss = (struct ieee80211_ie_dsss*)data;
				break;
			}

			case IEEE80211_IE_COUNTRY: {
				if (ie_len < IEEE80211_IE_COUNTRY_MIN_LENGTH) {
					return -1;
				}

				items->country = (struct ieee80211_ie_country*)data;
				break;
			}

			case IEEE80211_IE_CHALLENGE_TEXT: {
				if (ie_len < IEEE80211_IE_CHALLENGE_TEXT_MIN_LENGTH) {
					return -1;
				}

				items->challenge_text = (struct ieee80211_ie_challenge_text*)data;
				break;
			}

			case IEEE80211_IE_ERP: {
				if (ie_len != IEEE80211_IE_ERP_LENGTH) {
					return -1;
				}

				items->erp = (struct ieee80211_ie_erp*)data;
				break;
			}

			case IEEE80211_IE_EXTENDED_SUPPORTED_RATES: {
				if (ie_len < IEEE80211_IE_EXTENDED_SUPPORTED_MIN_LENGTH) {
					return -1;
				}

				items->extended_supported_rates = (struct ieee80211_ie_extended_supported_rates*)data;
				break;
			}

			case IEEE80211_IE_EDCA_PARAMETER_SET: {
				if (ie_len != IEEE80211_IE_EDCA_PARAMETER_SET_LENGTH) {
					return -1;
				}

				items->edca_parameter_set = (struct ieee80211_ie_edca_parameter_set*)data;
				break;
			}

			case IEEE80211_IE_QOS_CAPABILITY: {
				if (ie_len != IEEE80211_IE_QOS_CAPABILITY_LENGTH) {
					return -1;
				}

				items->qos_capability = (struct ieee80211_ie_qos_capability*)data;
				break;
			}

			case IEEE80211_IE_POWER_CONSTRAINT: {
				if (ie_len != IEEE80211_IE_POWER_CONSTRAINT_LENGTH) {
					return -1;
				}

				items->power_constraint = (struct ieee80211_ie_power_constraint*)data;
				break;
			}

			case IEEE80211_IE_SSID_LIST: {
				items->ssid_list = (struct ieee80211_ie_ssid_list*)data;
				break;
			}
		}

		/* Next Information Element */
		data += sizeof(struct ieee80211_ie) + ie_len;
		length -= sizeof(struct ieee80211_ie) + ie_len;
	}

	return (!length ? 0 : -1);
}
