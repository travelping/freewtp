#ifndef __WIFI_DRIVERS_HEADER__
#define __WIFI_DRIVERS_HEADER__

#include <net/if_arp.h>
#include <linux/if_ether.h>
#include "ieee80211.h"

/* */
#define WIFI_DRIVER_NAME_SIZE								16

/* */
#define WIFI_BAND_UNKNOWN									0
#define WIFI_BAND_2GHZ										1
#define WIFI_BAND_5GHZ										2

/* */
#define WIFI_CAPABILITY_RADIOSUPPORTED						0x00000001
#define WIFI_CAPABILITY_RADIOTYPE							0x00000002
#define WIFI_CAPABILITY_BANDS								0x00000004
#define WIFI_CAPABILITY_CIPHERS								0x00000008
#define WIFI_CAPABILITY_ANTENNA_MASK						0x00000010
#define WIFI_CAPABILITY_MAX_SCAN_SSIDS						0x00000020
#define WIFI_CAPABILITY_MAX_SCHED_SCAN_SSIDS				0x00000040
#define WIFI_CAPABILITY_MAX_MATCH_SETS						0x00000080
#define WIFI_CAPABILITY_MAX_ACL_MACADDRESS					0x00000100

/* */
#define WIFI_CAPABILITY_FLAGS_OFFCHANNEL_TX_OK				0x00000001
#define WIFI_CAPABILITY_FLAGS_ROAM_SUPPORT					0x00000002
#define WIFI_CAPABILITY_FLAGS_SUPPORT_AP_UAPSD				0x00000004
#define WIFI_CAPABILITY_FLAGS_DEVICE_AP_SME					0x00000008
#define WIFI_CAPABILITY_FLAGS_PROBE_RESPONSE_OFFLOAD		0x00000010

/* */
#define WIFI_CAPABILITY_AP_SUPPORTED						0x00000001
#define WIFI_CAPABILITY_AP_VLAN_SUPPORTED					0x00000002
#define WIFI_CAPABILITY_ADHOC_SUPPORTED						0x00000004
#define WIFI_CAPABILITY_MONITOR_SUPPORTED					0x00000008
#define WIFI_CAPABILITY_WDS_SUPPORTED						0x00000010

#define FREQ_CAPABILITY_DISABLED							0x00000001
#define FREQ_CAPABILITY_PASSIVE_SCAN						0x00000002
#define FREQ_CAPABILITY_NO_IBBS								0x00000004
#define FREQ_CAPABILITY_RADAR								0x00000008
#define FREQ_CAPABILITY_DFS_STATE							0x00000010
#define FREQ_CAPABILITY_DFS_TIME							0x00000020

#define RATE_CAPABILITY_SHORTPREAMBLE						0x00000001

#define CIPHER_CAPABILITY_UNKNOWN							0
#define CIPHER_CAPABILITY_WEP40								1
#define CIPHER_CAPABILITY_WEP104							2
#define CIPHER_CAPABILITY_TKIP								3
#define CIPHER_CAPABILITY_CCMP								4
#define CIPHER_CAPABILITY_CMAC								5
#define CIPHER_CAPABILITY_GCMP								6
#define CIPHER_CAPABILITY_WPI_SMS4							7

#define IEEE80211_DFS_USABLE								0
#define IEEE80211_DFS_UNAVAILABLE							1
#define IEEE80211_DFS_AVAILABLE								2

#define WLAN_INTERFACE_AP									1

/* */
DECLARE_OPAQUE_TYPE(wifi_global_handle);
DECLARE_OPAQUE_TYPE(wifi_device_handle);
DECLARE_OPAQUE_TYPE(wifi_wlan_handle);

struct capwap_80211_wtpqos_element;

/* */
struct device_setrates_params {
	int supportedratescount;
	uint8_t supportedrates[IEEE80211_SUPPORTEDRATE_MAX_COUNT];
	int basicratescount;
	uint8_t basicrates[IEEE80211_SUPPORTEDRATE_MAX_COUNT];
};

/* */
#define WIFI_COUNTRY_LENGTH					4
struct device_setconfiguration_params {
	int shortpreamble;
	uint8_t maxbssid;
	uint8_t dtimperiod;
	uint8_t bssid[MACADDRESS_EUI48_LENGTH];
	uint16_t beaconperiod;
	uint8_t country[WIFI_COUNTRY_LENGTH];
};

/* */
typedef int (*send_frame_to_ac)(void* param, const uint8_t* frame, int length, uint8_t rssi, uint8_t snr, uint16_t rate);

struct wlan_startap_params {
	uint8_t radioid;
	uint8_t wlanid;

	const char* ssid;
	uint8_t ssid_hidden;
	uint16_t capability;
	uint8_t qos;
	uint8_t authmode;
	uint8_t macmode;
	uint8_t tunnelmode;

	struct capwap_array *ie;
};


/* */
struct wlan_send_frame_params {
	uint8_t* packet;
	int length;

	uint32_t frequency;
	uint32_t duration;
	int offchannel_tx_ok;
	int no_cck_rate;
	int no_wait_ack;

	uint64_t cookie;
};

/* */
struct station_add_params {
	uint8_t* address;
	struct ieee80211_ht_cap *ht_cap;
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
	uint8_t a_mpdu_params;
	uint8_t mcs_set[16];

	struct capwap_array* freq;
	struct capwap_array* rate;
};

/* */
struct wifi_cipher_capability {
	unsigned long cipher;
};

/* */
struct wifi_capability {
	struct wifi_device* device;

	unsigned long flags;
	unsigned long capability;

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

	/* WIFI_CAPABILITY_MAX_SCAN_SSIDS */
	uint8_t maxscanssids;

	/* WIFI_CAPABILITY_MAX_SCHED_SCAN_SSIDS */
	uint8_t maxschedscanssids;

	/* WIFI_CAPABILITY_MAX_MATCH_SETS */
	uint8_t maxmatchsets;

	/* WIFI_CAPABILITY_MAX_ACL_MACADDRESS */
	uint8_t maxaclmacaddress;
};

/* Frequency configuration */
struct wifi_frequency {
	uint32_t band;
	uint32_t mode;
	uint8_t channel;
	uint32_t frequency;
};

/* */
#define WIFI_EVENT_MAX_ITEMS					2
struct wifi_event {
	void (*event_handler)(int fd, void** params, int paramscount);
	int paramscount;
	void* params[WIFI_EVENT_MAX_ITEMS];
};

/* */
struct wifi_driver_instance {
	struct wifi_driver_ops* ops;						/* Driver functions */
	wifi_global_handle handle;							/* Global instance handle */
};

/* */
struct wifi_global {
	int sock_util;
	struct capwap_list* devices;

	/* Timeout */
	struct capwap_timeout* timeout;

	/* Stations */
	struct capwap_hash* stations;
};

/* Device handle */
#define WIFI_DEVICE_SET_FREQUENCY						0x00000001
#define WIFI_DEVICE_SET_RATES							0x00000002
#define WIFI_DEVICE_SET_CONFIGURATION					0x00000004
#define WIFI_DEVICE_REQUIRED_FOR_BSS					(WIFI_DEVICE_SET_FREQUENCY | WIFI_DEVICE_SET_RATES | WIFI_DEVICE_SET_CONFIGURATION)

struct wifi_device {
	struct wifi_global* global;

	wifi_device_handle handle;							/* Device handle */
	struct wifi_driver_instance* instance;				/* Driver instance */

	uint32_t phyindex;
	char phyname[IFNAMSIZ];

	unsigned long flags;

	/* */
	struct capwap_list* wlans;
	unsigned long wlanactive;

	/* Current frequency */
	struct wifi_frequency currentfrequency;

	/* */
	uint16_t beaconperiod;
	uint8_t dtimperiod;
	int shortpreamble;

	/* Cached capability */
	struct wifi_capability* capability;

	/* Rates */
	unsigned long supportedratescount;
	uint8_t supportedrates[IEEE80211_SUPPORTEDRATE_MAX_COUNT];
	unsigned long basicratescount;
	uint8_t basicrates[IEEE80211_SUPPORTEDRATE_MAX_COUNT];

	/* ERP Information */
	int olbc;
	unsigned long stationsnonerpcount;
	unsigned long stationsnoshortslottimecount;
	unsigned long stationsnoshortpreamblecount;
};

/* WLAN handle */
#define WIFI_WLAN_RUNNING							0x00000001
#define WIFI_WLAN_SET_BEACON						0x00000002
#define WIFI_WLAN_OPERSTATE_RUNNING					0x00000004

struct wifi_wlan {
	wifi_wlan_handle handle;
	struct wifi_device* device;

	unsigned long flags;

	uint32_t virtindex;
	char virtname[IFNAMSIZ];

	uint8_t address[MACADDRESS_EUI48_LENGTH];

	/* */
	uint8_t radioid;
	uint8_t wlanid;

	/* WLAN information */
	char ssid[IEEE80211_SSID_MAX_LENGTH + 1];
	uint8_t ssid_hidden;
	uint16_t capability;
	int ht_opmode;

	/* Tunnel */
	uint8_t macmode;
	uint8_t tunnelmode;

	/* Authentication */
	uint8_t authmode;

	/* Station information */
	unsigned long stationscount;
	unsigned long maxstationscount;

	uint32_t aidbitfield[IEEE80211_AID_BITFIELD_SIZE];

	int beacon_ies_len;
	uint8_t *beacon_ies;
	int response_ies_len;
	uint8_t *response_ies;
};

/* Station handle */
#define WIFI_STATION_FLAGS_AUTHENTICATED					0x00000001
#define WIFI_STATION_FLAGS_ASSOCIATE						0x00000002
#define WIFI_STATION_FLAGS_NON_ERP						0x00000004
#define WIFI_STATION_FLAGS_NO_SHORT_SLOT_TIME					0x00000008
#define WIFI_STATION_FLAGS_NO_SHORT_PREAMBLE					0x00000010
#define WIFI_STATION_FLAGS_WMM							0x00000020
#define WIFI_STATION_FLAGS_AUTHORIZED						0x00000040
#define WIFI_STATION_FLAGS_HT_CAP						0x00000080

/* */
#define WIFI_STATION_TIMEOUT_ASSOCIATION_COMPLETE				30000
#define WIFI_STATION_TIMEOUT_AFTER_DEAUTHENTICATED				5000

/* */
#define WIFI_STATION_TIMEOUT_ACTION_DELETE						0x00000001
#define WIFI_STATION_TIMEOUT_ACTION_DEAUTHENTICATE				0x00000002

struct wifi_station {
	uint8_t address[MACADDRESS_EUI48_LENGTH];
	char addrtext[CAPWAP_MACADDRESS_EUI48_BUFFER];

	/* */
	struct wifi_wlan* wlan;

	/* */
	unsigned long flags;

	/* Timers */
	int timeoutaction;
	unsigned long idtimeout;

	/* */
	uint16_t capability;
	uint16_t listeninterval;
	uint16_t aid;

	/* */
	int supportedratescount;
	uint8_t supportedrates[IEEE80211_SUPPORTEDRATE_MAX_COUNT];

	/* Authentication */
	uint16_t authalgorithm;

	uint8_t qosinfo;

	struct ieee80211_ht_cap ht_cap;
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
	int (*device_init)(wifi_global_handle handle, struct wifi_device* device);
	int (*device_getfdevent)(struct wifi_device* device, struct pollfd* fds, struct wifi_event* events);
	int (*device_getcapability)(struct wifi_device* device, struct wifi_capability* capability);
	void (*device_updatebeacons)(struct wifi_device* device);
	int (*device_setfrequency)(struct wifi_device* device);
	int (*device_settxqueue)(struct wifi_device* device, int queue, int aifs,
				 int cw_min, int cw_max, int txop);
	void (*device_deinit)(struct wifi_device* device);

	/* WLAN functions */
	wifi_wlan_handle (*wlan_create)(struct wifi_device* device, struct wifi_wlan* wlan);
	int (*wlan_getfdevent)(struct wifi_wlan* wlan, struct pollfd* fds, struct wifi_event* events);
	int (*wlan_startap)(struct wifi_wlan* wlan);
	void (*wlan_stopap)(struct wifi_wlan* wlan);
	int (*wlan_sendframe)(struct wifi_wlan* wlan, uint8_t* frame, int length, uint32_t frequency, uint32_t duration, int offchannel_tx_ok, int no_cck_rate, int no_wait_ack);
	void (*wlan_delete)(struct wifi_wlan* wlan);

	/* Stations functions */
	int (*station_authorize)(struct wifi_wlan* wlan, struct wifi_station* station);
	int (*station_deauthorize)(struct wifi_wlan* wlan, const uint8_t* address);
};

/* Initialize wifi driver engine */
int wifi_driver_init(struct capwap_timeout* timeout);
void wifi_driver_free(void);

/* Get File Descriptor Event */
int wifi_event_getfd(struct pollfd* fds, struct wifi_event* events, int count);

/* */
struct wifi_wlan* wifi_get_wlan(uint32_t ifindex);

/* Device management */
struct wifi_device* wifi_device_connect(const char* ifname, const char* driver);
const struct wifi_capability* wifi_device_getcapability(struct wifi_device* device);
int wifi_device_setconfiguration(struct wifi_device* device, struct device_setconfiguration_params* params);
int wifi_device_setfrequency(struct wifi_device* device, uint32_t band, uint32_t mode, uint8_t channel);
int wifi_device_settxqueue(struct wifi_device *device, struct capwap_80211_wtpqos_element *qos);
int wifi_device_updaterates(struct wifi_device* device, uint8_t* rates, int ratescount);

/* WLAN management */
struct wifi_wlan* wifi_wlan_create(struct wifi_device* device, const char* ifname);
int wifi_wlan_startap(struct wifi_wlan* wlan, struct wlan_startap_params* params);
void wifi_wlan_stopap(struct wifi_wlan* wlan);
int wifi_wlan_getbssid(struct wifi_wlan* wlan, uint8_t* bssid);
uint16_t wifi_wlan_check_capability(struct wifi_wlan* wlan, uint16_t capability);
int wifi_wlan_send_frame(struct wifi_wlan* wlan, const uint8_t* data, int length, uint8_t rssi, uint8_t snr, uint16_t rate);
void wifi_wlan_destroy(struct wifi_wlan* wlan);

/* WLAN packet management */
void wifi_wlan_receive_station_frame(struct wifi_wlan* wlan, const struct ieee80211_header* frame, int length, uint32_t frequency, uint8_t rssi, uint8_t snr, uint16_t rate);
void wifi_wlan_receive_station_ackframe(struct wifi_wlan* wlan, const struct ieee80211_header* frame, int length, int ack);
void wifi_wlan_receive_ac_frame(struct wifi_wlan* wlan, struct ieee80211_header* frame, int length);

/* Station management */
int wifi_station_authorize(struct wifi_wlan* wlan, struct station_add_params* params);
void wifi_station_deauthorize(struct wifi_device* device, const uint8_t* address);

/* Util functions */
uint32_t wifi_iface_index(const char* ifname);
int wifi_iface_hwaddr(int sock, const char* ifname, uint8_t* hwaddr);

int wifi_frequency_to_radiotype(uint32_t freq);

/* */
int wifi_iface_getstatus(int sock, const char* ifname);
int wifi_iface_updown(int sock, const char* ifname, int up);
#define wifi_iface_up(sock, ifname)										wifi_iface_updown(sock, ifname, 1)
#define wifi_iface_down(sock, ifname)									wifi_iface_updown(sock, ifname, 0)

#endif /* __WIFI_DRIVERS_HEADER__ */
