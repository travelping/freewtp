#ifndef __WIFI_DRIVERS_HEADER__
#define __WIFI_DRIVERS_HEADER__

#include <net/if_arp.h>
#include <linux/if_ether.h>

/* */
#define WIFI_DRIVER_NAME_SIZE						16
#define WIFI_SSID_MAX_LENGTH						32

/* */
#define WIFI_BAND_UNKNOWN							0
#define WIFI_BAND_2GHZ								1
#define WIFI_BAND_5GHZ								2

/* */
#define WIFI_SUPPORTEDRATE_MAX_COUNT				16

/* */
#define WIFI_CAPABILITY_RADIOSUPPORTED				0x00000001
#define WIFI_CAPABILITY_RADIOTYPE					0x00000002
#define WIFI_CAPABILITY_BANDS						0x00000004
#define WIFI_CAPABILITY_CIPHERS						0x00000008
#define WIFI_CAPABILITY_ANTENNA_MASK				0x00000010

/* */
#define WIFI_CAPABILITY_AP_SUPPORTED				0x00000001
#define WIFI_CAPABILITY_AP_VLAN_SUPPORTED			0x00000002
#define WIFI_CAPABILITY_ADHOC_SUPPORTED				0x00000004
#define WIFI_CAPABILITY_MONITOR_SUPPORTED			0x00000008
#define WIFI_CAPABILITY_WDS_SUPPORTED				0x00000010

#define FREQ_CAPABILITY_DISABLED					0x00000001
#define FREQ_CAPABILITY_PASSIVE_SCAN				0x00000002
#define FREQ_CAPABILITY_NO_IBBS						0x00000004
#define FREQ_CAPABILITY_RADAR						0x00000008
#define FREQ_CAPABILITY_DFS_STATE					0x00000010
#define FREQ_CAPABILITY_DFS_TIME					0x00000020

#define RATE_CAPABILITY_SHORTPREAMBLE				0x00000001

#define CIPHER_CAPABILITY_UNKNOWN				0
#define CIPHER_CAPABILITY_WEP40					1
#define CIPHER_CAPABILITY_WEP104				2
#define CIPHER_CAPABILITY_TKIP					3
#define CIPHER_CAPABILITY_CCMP					4
#define CIPHER_CAPABILITY_CMAC					5
#define CIPHER_CAPABILITY_GCMP					6
#define CIPHER_CAPABILITY_WPI_SMS4				7

#define IEEE80211_DFS_USABLE						0
#define IEEE80211_DFS_UNAVAILABLE					1
#define IEEE80211_DFS_AVAILABLE						2

#define WLAN_INTERFACE_AP							1

/* */
typedef void* wifi_global_handle;
typedef void* wifi_device_handle;
typedef void* wifi_wlan_handle;

/* */
struct device_init_params {
	const char* ifname;
};

/* */
struct wlan_init_params {
	const char* ifname;
	int type;
};

/* */
struct wlan_setupap_params {
	char* headbeacon;
	int headbeaconlength;
	char* tailbeacon;
	int tailbeaconlength;

	char ssid[WIFI_SSID_MAX_LENGTH + 1];
	uint8_t suppressssid;

	uint16_t beaconinterval;
	uint8_t dtimperiod;

	uint8_t authenticationtype;
};

/* Interface capability */
struct wifi_freq_capability {
	unsigned long flags;

	unsigned long frequency;		/* MHz */
	unsigned long channel;

	unsigned long maxtxpower;		/* mBm = 100 * dBm */

	unsigned long dfsstate;
	unsigned long dfstime;			/* ms */
};

/* */
struct wifi_rate_capability {
	unsigned long flags;

	uint8_t bitrate;
};

/* */
struct wifi_band_capability {
	unsigned long band;

	unsigned long htcapability;

	struct capwap_array* freq;
	struct capwap_array* rate;
};

/* */
struct wifi_cipher_capability {
	unsigned long cipher;
};

/* */
struct wifi_capability {
	wifi_device_handle device;

	unsigned long flags;

	/* WIFI_CAPABILITY_RADIOSUPPORTED */
	unsigned long radiosupported;

	/* WIFI_CAPABILITY_RADIOTYPE */
	unsigned long radiotype;

	/* WIFI_CAPABILITY_ANTENNA_MASK */
	unsigned long txantennamask;
	unsigned long rxantennamask;

	/* WIFI_CAPABILITY_BANDS */
	struct capwap_array* bands;

	/* WIFI_CAPABILITY_CIPHERS */
	struct capwap_array* ciphers;
};

/* Frequency configuration */
struct wifi_frequency {
	uint32_t band;
	uint32_t mode;
	uint8_t channel;
	uint32_t frequency;
};

/* */
struct wifi_event {
	void (*event_handler)(int fd, void* param1, void* param2);
	void* param1;
	void* param2;
};

/* */
struct wifi_driver_ops {
	const char* name;				/* Name of wifi driver */
	const char* description;		/* Description of wifi driver */

	/* Global initialize driver */
	wifi_global_handle (*global_init)(void);
	int (*global_getfdevent)(wifi_global_handle handle, struct pollfd* fds, struct wifi_event* events);
	void (*global_deinit)(wifi_global_handle handle);

	/* Device functions */
	wifi_device_handle (*device_init)(wifi_global_handle handle, struct device_init_params* params);
	int (*device_getfdevent)(wifi_device_handle handle, struct pollfd* fds, struct wifi_event* events);
	int (*device_getcapability)(wifi_device_handle handle, struct wifi_capability* capability);
	int (*device_setfrequency)(wifi_device_handle handle, struct wifi_frequency* freq);
	void (*device_deinit)(wifi_device_handle handle);

	/* WLAN functions */
	wifi_wlan_handle (*wlan_create)(wifi_device_handle handle, struct wlan_init_params* params);
	int (*wlan_getfdevent)(wifi_wlan_handle handle, struct pollfd* fds, struct wifi_event* events);
	int (*wlan_setupap)(wifi_wlan_handle handle, struct wlan_setupap_params* params);
	int (*wlan_startap)(wifi_wlan_handle handle);
	int (*wlan_stopap)(wifi_wlan_handle handle);
	int (*wlan_getmacaddress)(wifi_wlan_handle handle, uint8_t* address); 
	void (*wlan_delete)(wifi_wlan_handle handle);
};

/* */
struct wifi_driver_instance {
	struct wifi_driver_ops* ops;						/* Driver functions */
	wifi_global_handle handle;							/* Global instance handle */
};

/* */
struct wifi_device {
	wifi_device_handle handle;							/* Device handle */
	struct wifi_driver_instance* instance;				/* Driver instance */

	struct capwap_array* wlan;							/* Virtual AP */

	/* Cache capability */
	struct wifi_capability* capability;

	/* Current frequency */
	struct wifi_frequency currentfreq;

	/* Supported Rates */
	int supportedratescount;
	uint8_t supportedrates[WIFI_SUPPORTEDRATE_MAX_COUNT];
};

/* */
struct wifi_wlan {
	wifi_wlan_handle handle;
	struct wifi_device* device;
};

/* Initialize wifi driver engine */
int wifi_driver_init(void);
void wifi_driver_free(void);

/* Get File Descriptor Event */
int wifi_event_getfd(struct pollfd* fds, struct wifi_event* events, int count);

/* */
int wifi_device_connect(int radioid, const char* ifname, const char* driver);
struct wifi_capability* wifi_device_getcapability(int radioid);
int wifi_device_setfrequency(int radioid, uint32_t band, uint32_t mode, uint8_t channel);

/* */
int wifi_wlan_create(int radioid, int wlanid, const char* ifname, uint8_t* bssid);
int wifi_wlan_setupap(struct capwap_80211_addwlan_element* addwlan, struct capwap_array* ies);
int wifi_wlan_startap(int radioid, int wlanid);
int wifi_wlan_stopap(int radioid, int wlanid);
int wifi_wlan_getbssid(int radioid, int wlanid, uint8_t* bssid);
void wifi_wlan_destroy(int radioid, int wlanid);

/* Util functions */
uint32_t wifi_iface_index(const char* ifname);
int wifi_iface_hwaddr(int sock, const char* ifname, uint8_t* hwaddr);
unsigned long wifi_frequency_to_channel(unsigned long freq);

int wifi_iface_updown(int sock, const char* ifname, int up);
#define wifi_iface_up(sock, ifname)										wifi_iface_updown(sock, ifname, 1)
#define wifi_iface_down(sock, ifname)									wifi_iface_updown(sock, ifname, 0)

#endif /* __WIFI_DRIVERS_HEADER__ */
