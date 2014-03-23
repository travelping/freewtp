#include "capwap.h"
#include "capwap_list.h"
#include "capwap_element.h"
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
static struct capwap_list* g_wifidevice = NULL;

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
		return;
	}

	/* Get radio type for basic rate */
	radiotype = wifi_frequency_to_radiotype(device->currentfreq.frequency);
	if (radiotype < 0) {
		return;
	}

	/* Check type of rate mode */
	for (i = 0; i < ratescount; i++) {
		if (device->currentfreq.band == WIFI_BAND_2GHZ) {
			if (IS_IEEE80211_RATE_B(rates[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211B;
			} else if (IS_IEEE80211_RATE_G(rates[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211G;
			} else if (IS_IEEE80211_RATE_N(rates[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211N;
			}
		} else if (device->currentfreq.band == WIFI_BAND_5GHZ) {
			if (IS_IEEE80211_RATE_A(rates[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211A;
			} else if (IS_IEEE80211_RATE_N(rates[i])) {
				mode |= CAPWAP_RADIO_TYPE_80211N;
			}
		}
	}

	/* Add implicit 802.11b rate with only 802.11g rate */
	if ((device->currentfreq.band == WIFI_BAND_2GHZ) && !(mode & CAPWAP_RADIO_TYPE_80211B) && (device->currentfreq.mode & CAPWAP_RADIO_TYPE_80211B)) {
		device_params->supportedrates[device_params->supportedratescount++] = IEEE80211_RATE_1M;
		device_params->supportedrates[device_params->supportedratescount++] = IEEE80211_RATE_2M;
		device_params->supportedrates[device_params->supportedratescount++] = IEEE80211_RATE_5_5M;
		device_params->supportedrates[device_params->supportedratescount++] = IEEE80211_RATE_11M;
	}

	/* Filter band */
	for (i = 0; i < capability->bands->count; i++) {
		struct wifi_band_capability* bandcap = (struct wifi_band_capability*)capwap_array_get_item_pointer(capability->bands, i);

		if (bandcap->band == device->currentfreq.band) {
			for (j = 0; j < bandcap->rate->count; j++) {
				struct wifi_rate_capability* ratecapability = (struct wifi_rate_capability*)capwap_array_get_item_pointer(bandcap->rate, j);

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
	}

	/* Apply basic rate */
	for (i = 0; i < device_params->supportedratescount; i++) {
		if (radiotype == CAPWAP_RADIO_TYPE_80211A) {
			if (IS_IEEE80211_BASICRATE_A(device_params->supportedrates[i])) {
				device_params->basicrates[device_params->basicratescount++] = device_params->supportedrates[i];
				device_params->supportedrates[i] |= IEEE80211_BASICRATE;
			}
		} else if (radiotype == CAPWAP_RADIO_TYPE_80211B) {
			if (IS_IEEE80211_BASICRATE_B(device_params->supportedrates[i])) {
				device_params->basicrates[device_params->basicratescount++] = device_params->supportedrates[i];
				device_params->supportedrates[i] |= IEEE80211_BASICRATE;
			}
		} else if (radiotype == CAPWAP_RADIO_TYPE_80211G) {
			if (IS_IEEE80211_BASICRATE_G(device_params->supportedrates[i])) {
				device_params->basicrates[device_params->basicratescount++] = device_params->supportedrates[i];
				device_params->supportedrates[i] |= IEEE80211_BASICRATE;
			}
		}
	}

	/* Add implicit 802.11n rate with only 802.11a/g rate */
	if (!(mode & CAPWAP_RADIO_TYPE_80211N) && (device->currentfreq.mode & CAPWAP_RADIO_TYPE_80211N)) {
		device_params->supportedrates[device_params->supportedratescount++] = IEEE80211_RATE_80211N;
	}
}

/* */
int wifi_driver_init(struct capwap_timeout* timeout) {
	int i;
	struct global_init_params params;

	ASSERT(timeout != NULL);

	/* */
	params.timeout = timeout;

	/* */
	for (i = 0; wifi_driver[i].ops != NULL; i++) {
		/* Initialize driver */
		ASSERT(wifi_driver[i].ops->global_init != NULL);
		wifi_driver[i].handle = wifi_driver[i].ops->global_init(&params);
		if (!wifi_driver[i].handle) {
			return -1;
		}
	}

	/* Device handler */
	g_wifidevice = capwap_list_create();

	return 0;
}

/* */
void wifi_driver_free(void) {
	unsigned long i;
	struct capwap_list_item* itemdevice;
	struct capwap_list_item* itemwlan;

	/* Free device */
	if (g_wifidevice) {
		for (itemdevice = g_wifidevice->first; itemdevice != NULL; itemdevice = itemdevice->next) {
			struct wifi_device* device = (struct wifi_device*)itemdevice->item;

			if (device->wlan) {
				if (device->instance->ops->wlan_delete != NULL) {
					for (itemwlan = device->wlan->first; itemwlan != NULL; itemwlan = itemwlan->next) {
						struct wifi_wlan* wlan = (struct wifi_wlan*)itemwlan->item;

						if (wlan->handle) {
							device->instance->ops->wlan_delete(wlan->handle);
						}
					}
				}

				capwap_list_free(device->wlan);
			}

			if (device->handle && device->instance->ops->device_deinit) {
				device->instance->ops->device_deinit(device->handle);
			}
		}

		capwap_list_free(g_wifidevice);
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
	int i;
	int result = 0;
	struct capwap_list_item* itemdevice;
	struct capwap_list_item* itemwlan;

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
	for (itemdevice = g_wifidevice->first; itemdevice != NULL; itemdevice = itemdevice->next) {
		struct wifi_device* device = (struct wifi_device*)itemdevice->item;
		if (device->handle) {
			if (device->instance->ops->device_getfdevent) {
				result += device->instance->ops->device_getfdevent(device->handle, (count ? &fds[result] : NULL), (count ? &events[result] : NULL));
			}

			/* Get from wlan */
			if (device->wlan && device->instance->ops->wlan_getfdevent) {
				for (itemwlan = device->wlan->first; itemwlan != NULL; itemwlan = itemwlan->next) {
					struct wifi_wlan* wlan = (struct wifi_wlan*)itemwlan->item;

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
struct wifi_device* wifi_device_connect(const char* ifname, const char* driver) {
	int i;
	int length;
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
			wifi_device_handle devicehandle;
			struct device_init_params params = {
				.ifname = ifname
			};

			/* Device init */
			ASSERT(wifi_driver[i].ops->device_init);
			devicehandle = wifi_driver[i].ops->device_init(wifi_driver[i].handle, &params);
			if (devicehandle) {
				struct capwap_list_item* itemdevice;

				/* Register new device */
				itemdevice = capwap_itemlist_create(sizeof(struct wifi_device));
				device = (struct wifi_device*)itemdevice->item;
				device->handle = devicehandle;
				device->instance = &wifi_driver[i];
				device->wlan = capwap_list_create();

				/* Appent to device list */
				capwap_itemlist_insert_after(g_wifidevice, NULL, itemdevice);
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

	/* Retrieve cached capability */
	if (!device->instance->ops->device_getcapability) {
		return NULL;
	}

	return device->instance->ops->device_getcapability(device->handle);
}

/* */
int wifi_device_setconfiguration(struct wifi_device* device, struct device_setconfiguration_params* params) {
	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);
	ASSERT(params != NULL);

	/* Get radio device */
	if (!device->instance->ops->device_setconfiguration) {
		return -1;
	}

	/* Set rates */
	return device->instance->ops->device_setconfiguration(device->handle, params);
}

/* */
int wifi_device_setfrequency(struct wifi_device* device, uint32_t band, uint32_t mode, uint8_t channel) {
	int i, j;
	int result = -1;
	const struct wifi_capability* capability;
	uint32_t frequency = 0;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);

	/* Check device */
	if (!device->instance->ops->device_setfrequency) {
		return -1;
	}

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
		result = device->instance->ops->device_setfrequency(device->handle, &device->currentfreq);
	}

	/* */
	return result;
}

/* */
int wifi_device_updaterates(struct wifi_device* device, uint8_t* rates, int ratescount) {
	struct device_setrates_params params;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);
	ASSERT(rates != NULL);
	ASSERT(ratescount > 0);

	/* Get radio device */
	if (!device->instance->ops->device_setrates) {
		return -1;
	}

	/* Set rates */
	wifi_wlan_getrates(device, rates, ratescount, &params);
	return device->instance->ops->device_setrates(device->handle, &params);
}

/* */
struct wifi_wlan* wifi_wlan_create(struct wifi_device* device, const char* ifname) {
	int length;
	struct wifi_wlan* wlan;
	wifi_wlan_handle wlanhandle;
	struct capwap_list_item* itemwlan;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);
	ASSERT(ifname != NULL);

	/* Check */
	length = strlen(ifname);
	if ((length <= 0) || (length >= IFNAMSIZ)) {
		capwap_logging_warning("Wifi device name error: %s", ifname);
		return NULL;
	} else if (!device->instance->ops->wlan_create) {
		capwap_logging_warning("%s library don't support wlan_create", device->instance->ops->name);
		return NULL;
	}

	/* Create interface */
	wlanhandle = device->instance->ops->wlan_create(device->handle, ifname);
	if (!wlanhandle) {
		capwap_logging_warning("Unable to create BSS: %s", ifname);
		return NULL;
	}

	/* Create new BSS */
	itemwlan = capwap_itemlist_create(sizeof(struct wifi_wlan));
	wlan = (struct wifi_wlan*)itemwlan->item;
	wlan->handle = wlanhandle;
	wlan->device = device;

	/* Appent to wlan list */
	capwap_itemlist_insert_after(device->wlan, NULL, itemwlan);
	return wlan;
}

/* */
int wifi_wlan_startap(struct wifi_wlan* wlan, struct wlan_startap_params* params) {
	ASSERT(wlan != NULL);
	ASSERT(wlan->device != NULL);
	ASSERT(params != NULL);

	/* Check */
	if (!wlan->device->instance->ops->wlan_startap) {
		return -1;
	}

	/* Start AP */
	return wlan->device->instance->ops->wlan_startap(wlan->handle, params);
}

/* */
void wifi_wlan_stopap(struct wifi_wlan* wlan) {
	ASSERT(wlan != NULL);
	ASSERT(wlan->device != NULL);

	/* Stop AP */
	if (wlan->device->instance->ops->wlan_stopap) {
		wlan->device->instance->ops->wlan_stopap(wlan->handle);
	}
}

/* */
int wifi_wlan_getbssid(struct wifi_wlan* wlan, uint8_t* bssid) {
	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);
	ASSERT(bssid != NULL);

	/* */
	if (!wlan->device->instance->ops->wlan_getmacaddress) {
		return -1;
	}

	return wlan->device->instance->ops->wlan_getmacaddress(wlan->handle, bssid);
}

/* */
void wifi_wlan_destroy(struct wifi_wlan* wlan) {
	struct capwap_list_item* itemwlan;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);

	/* */
	if (wlan->device->instance->ops->wlan_delete) {
		wlan->device->instance->ops->wlan_delete(wlan->handle);
	}

	/* Remove from wlan list of device */
	for (itemwlan = wlan->device->wlan->first; itemwlan != NULL; itemwlan = itemwlan->next) {
		if (wlan == (struct wifi_wlan*)itemwlan->item) {
			capwap_itemlist_free(capwap_itemlist_remove(wlan->device->wlan, itemwlan));
			break;
		}
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
