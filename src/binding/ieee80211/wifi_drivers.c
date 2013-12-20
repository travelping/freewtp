#include "capwap.h"
#include "capwap_array.h"
#include "capwap_element.h"
#include "wtp_radio.h"
#include "wifi_drivers.h"
#include "ieee80211.h"

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
static void wifi_device_freecapability(struct wifi_capability* capability) {
	int i;

	ASSERT(capability != NULL);

	/* Free memory */
	if (capability->bands) {
		for (i = 0; i < capability->bands->count; i++) {
			struct wifi_band_capability* bandcap = (struct wifi_band_capability*)capwap_array_get_item_pointer(capability->bands, i);

			if (bandcap->freq) {
				capwap_array_free(bandcap->freq);
			}

			if (bandcap->rate) {
				capwap_array_free(bandcap->rate);
			}
		}

		capwap_array_free(capability->bands);
	}

	if (capability->ciphers) {
		capwap_array_free(capability->ciphers);
	}

	capwap_free(capability);
}

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

			if (device->capability) {
				wifi_device_freecapability(device->capability);
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
	uint32_t mode = 0;

	ASSERT(device != NULL);
	ASSERT(radio != NULL);

	/* Free old supported rates */
	device->supportedratescount = 0;

	/* Retrieve cached capability */
	if (!device->capability) {
		if (!wifi_device_getcapability(radio->radioid)) {
			return;
		}
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
	for (i = 0; i < device->capability->bands->count; i++) {
		struct wifi_band_capability* bandcap = (struct wifi_band_capability*)capwap_array_get_item_pointer(device->capability->bands, i);

		if (bandcap->band == device->currentfreq.band) {
			if (bandcap->rate->count) {
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
			}

			break;
		}
	}

	/* Add implicit 802.11n rate with only 802.11a/g rate */
	if (!(mode & CAPWAP_RADIO_TYPE_80211N) && (device->currentfreq.mode & CAPWAP_RADIO_TYPE_80211N)) {
		device->supportedrates[device->supportedratescount++] = IEEE80211_RATE_80211N;
	}
}

/* */
static int wifi_ie_ssid(char* buffer, const char* ssid, int hidessid) {
	struct ieee80211_ie_ssid* iessid = (struct ieee80211_ie_ssid*)buffer;

	ASSERT(buffer != NULL);
	ASSERT(ssid != NULL);

	iessid->id = IEEE80211_IE_SSID;
	if (!hidessid) {
		iessid->len = strlen(ssid);
		if (iessid->len > IEEE80211_IE_SSID_MAX_LENGTH) {
			return -1;
		}

		strncpy((char*)iessid->ssid, ssid, iessid->len);
	}

	return sizeof(struct ieee80211_ie_ssid) + iessid->len;
}

/* */
static int wifi_ie_supportedrates(char* buffer, struct wifi_device* device) {
	int i;
	int count;
	struct ieee80211_ie_supported_rates* iesupportedrates = (struct ieee80211_ie_supported_rates*)buffer;

	ASSERT(buffer != NULL);

	/* IE accept max only 8 rate */
	count = device->supportedratescount;
	if (count > 8) {
		count = 8;
	}

	/* */
	iesupportedrates->id = IEEE80211_IE_SUPPORTED_RATES;
	iesupportedrates->len = count;

	for (i = 0; i < count; i++) {
		iesupportedrates->rates[i] = device->supportedrates[i];
	}

	return sizeof(struct ieee80211_ie_supported_rates) + iesupportedrates->len;
}

/* */
static int wifi_ie_extendedsupportedrates(char* buffer, struct wifi_device* device) {
	int i, j;
	struct ieee80211_ie_extended_supported_rates* ieextendedsupportedrates = (struct ieee80211_ie_extended_supported_rates*)buffer;

	ASSERT(buffer != NULL);

	/* IE accept only > 8 rate */
	if (device->supportedratescount <= IEEE80211_IE_SUPPORTED_RATES_MAX_LENGTH) {
		return 0;
	}

	/* */
	ieextendedsupportedrates->id = IEEE80211_IE_EXTENDED_SUPPORTED_RATES;
	ieextendedsupportedrates->len = device->supportedratescount - IEEE80211_IE_SUPPORTED_RATES_MAX_LENGTH;

	for (i = IEEE80211_IE_SUPPORTED_RATES_MAX_LENGTH, j = 0; i < device->supportedratescount; i++, j++) {
		ieextendedsupportedrates->rates[j] = device->supportedrates[i];
	}

	return sizeof(struct ieee80211_ie_extended_supported_rates) + ieextendedsupportedrates->len;
}

/* */
static int wifi_ie_dsss(char* buffer, struct wifi_device* device) {
	struct ieee80211_ie_dsss* iedsss;

	ASSERT(buffer != NULL);
	ASSERT(device != NULL);

	iedsss = (struct ieee80211_ie_dsss*)buffer;
	iedsss->id = IEEE80211_IE_SSID;
	iedsss->len = 1;
	iedsss->channel = device->currentfreq.channel;

	return sizeof(struct ieee80211_ie_dsss);
}

/* */
static int wifi_ie_erp(char* buffer, struct wifi_device* device) {
	ASSERT(buffer != NULL);
	ASSERT(device != NULL);

	return 0;

	/* TODO implements params ERP
	struct ieee80211_ie_erp* ieerp = (struct ieee80211_ie_erp*)buffer;

	if (device->currentfreq.mode != CAPWAP_RADIO_TYPE_80211G) {
		return 0;
	}

	ieerp->id = IEEE80211_IE_ERP;
	ieerp->len = 1;
	iedsss->params = 0;

	return sizeof(struct ieee80211_ie_erp);
	*/
}

/* */
int wifi_wlan_setupap(struct capwap_80211_addwlan_element* addwlan, struct capwap_array* ies) {
	int result;
	struct wifi_wlan* wlan;
	struct wtp_radio* radio;
	char buffer[IEEE80211_MTU];
	struct ieee80211_header_mgmt* header;
	struct wlan_setupap_params params;

	ASSERT(addwlan != NULL);

	/* Get WLAN and Radio information */
	wlan = wifi_wlan_getdevice(addwlan->radioid, addwlan->wlanid);
	radio = wtp_radio_get_phy(addwlan->radioid);
	if (!wlan || !radio || !wlan->handle || !wlan->device) {
		return -1;
	} else if (!wlan->device->instance->ops->wlan_setupap) {
		return -1;
	}

	/* */
	memset(buffer, 0, sizeof(buffer));
	header = (struct ieee80211_header_mgmt*)buffer;

	/* */
	memset(&params, 0, sizeof(struct wlan_setupap_params));
	params.headbeacon = buffer;

	/* Management header frame */
	header->framecontrol = IEEE80211_FRAME_CONTROL(IEEE80211_FRAMECONTROL_TYPE_MGMT, IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_BEACON);
	memset(header->da, 0xff, ETH_ALEN);
	wlan->device->instance->ops->wlan_getmacaddress(wlan->handle, header->sa);
	memcpy(header->bssid, header->sa, ETH_ALEN);
	header->beaconinterval = __cpu_to_le16(radio->radioconfig.beaconperiod);
	header->capability = __cpu_to_le16(addwlan->capability);
	params.headbeaconlength += sizeof(struct ieee80211_header_mgmt);

	/* Information Element: SSID */
	result = wifi_ie_ssid(&params.headbeacon[params.headbeaconlength], (const char*)addwlan->ssid, (addwlan->suppressssid ? 1 : 0));
	if (result < 0) {
		return -1;
	}

	params.headbeaconlength += result;

	/* Information Element: Supported Rates */
	wifi_wlan_getrates(wlan->device, radio);
	result = wifi_ie_supportedrates(&params.headbeacon[params.headbeaconlength], wlan->device);
	if (result < 0) {
		return -1;
	}

	params.headbeaconlength += result;

	/* Information Element: DSSS */
	result = wifi_ie_dsss(&params.headbeacon[params.headbeaconlength], wlan->device);
	if (result < 0) {
		return -1;
	}

	params.headbeaconlength += result;

	/* Separate Information Elements into two block between IE TIM */
	params.tailbeacon = &params.headbeacon[params.headbeaconlength];

	/* Information Element: Country */
	/* TODO */

	/* Information Element: ERP */
	result = wifi_ie_erp(&params.tailbeacon[params.tailbeaconlength], wlan->device);
	if (result < 0) {
		return -1;
	}

	params.tailbeaconlength += result;

	/* Information Element: Extended Supported Rates */
	result = wifi_ie_extendedsupportedrates(&params.tailbeacon[params.tailbeaconlength], wlan->device);
	if (result < 0) {
		return -1;
	}

	params.tailbeaconlength += result;

	/* Set configuration params */
	strcpy(params.ssid, (const char*)addwlan->ssid);
	params.suppressssid = addwlan->suppressssid;
	params.beaconinterval = radio->radioconfig.beaconperiod;
	params.dtimperiod = radio->radioconfig.dtimperiod;
	params.authenticationtype = addwlan->authmode;

	/* Configuration complete */
	return wlan->device->instance->ops->wlan_setupap(wlan->handle, &params);
}

/* */
int wifi_wlan_startap(int radioid, int wlanid) {
	struct wifi_wlan* wlan;

	/* */
	wlan = wifi_wlan_getdevice(radioid, wlanid);
	if (!wlan->device->instance->ops->wlan_startap) {
		return -1;
	}

	return wlan->device->instance->ops->wlan_startap(wlan->handle);
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
struct wifi_capability* wifi_device_getcapability(int radioid) {
	struct wifi_device* device;

	ASSERT(radioid > 0);

	if (g_wifidevice->count <= radioid) {
		return NULL;
	}

	/* Retrieve cached capability */
	device = (struct wifi_device*)capwap_array_get_item_pointer(g_wifidevice, radioid);
	if (!device->capability && device->handle && device->instance->ops->device_getcapability) {
		/* Get capability from device */
		device->capability = (struct wifi_capability*)capwap_alloc(sizeof(struct wifi_capability));
		memset(device->capability, 0, sizeof(struct wifi_capability));

		device->capability->bands = capwap_array_create(sizeof(struct wifi_band_capability), 0, 1);
		device->capability->ciphers = capwap_array_create(sizeof(struct wifi_cipher_capability), 0, 1);

		/* */
		if (device->instance->ops->device_getcapability(device->handle, device->capability)) {
			wifi_device_freecapability(device->capability);
			device->capability = NULL;
		}
	}

	return device->capability;
}

/* */
int wifi_device_setfrequency(int radioid, uint32_t band, uint32_t mode, uint8_t channel) {
	int i, j;
	int result = -1;
	struct wifi_capability* capability;
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
unsigned long wifi_frequency_to_channel(unsigned long freq) {
	if ((freq >= 2412) && (freq <= 2472)) {
		return (freq - 2407) / 5;
	} else if (freq == 2484) {
		return 14;
	} else if ((freq >= 5035) && (freq <= 5825)) {
		return freq / 5 - 1000;
	}

	return 0;
}
