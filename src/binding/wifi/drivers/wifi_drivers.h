#ifndef __WIFI_DRIVERS_HEADER__
#define __WIFI_DRIVERS_HEADER__

/* */
#define WIFI_DRIVER_NAME_SIZE			16

/* */
#define IS_IEEE80211_FREQ_BG(x)					((x >= 2412) && (x <= 2484) ? 1 : 0)
#define IS_IEEE80211_FREQ_A(x)					((x >= 5035) && (x <= 5825) ? 1 : 0)

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

/* */
typedef void* wifi_global_handle;
typedef void* wifi_device_handle;

/* */
struct device_init_params {
	char* ifname;
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

struct wifi_rate_capability {
	unsigned long flags;

	unsigned long bitrate;			/* Kbps */
};

struct wifi_band_capability {
	unsigned long htcapability;
	struct capwap_array* freq;
	struct capwap_array* rate;
};

struct wifi_cipher_capability {
	unsigned long cipher;
};

struct wifi_capability {
	unsigned long radiosupported;

	unsigned long radiotype;

	struct capwap_array* bands;
	struct capwap_array* ciphers;
};

/* */
struct wifi_driver_ops {
	const char* name;				/* Name of wifi driver */
	const char* description;		/* Description of wifi driver */

	/* Global initialize driver */
	wifi_global_handle (*global_init)(void);
	void (*global_deinit)(wifi_global_handle handle);

	/* Initialize device */
	wifi_device_handle (*device_init)(wifi_global_handle handle, struct device_init_params* params);
	void (*device_deinit)(wifi_device_handle handle);

	/* Capability */
	struct wifi_capability* (*get_capability)(wifi_device_handle handle);
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
};

/* Initialize wifi driver engine */
int wifi_init_driver(void);
void wifi_free_driver(void);

/* */
int wifi_create_device(int radioid, char* ifname, char* driver);
struct wifi_capability* wifi_get_capability_device(int radioid);

/* Util functions */
void wifi_iface_updown(int sock, const char* ifname, int up);
unsigned long wifi_frequency_to_channel(unsigned long freq);

#endif /* __WIFI_DRIVERS_HEADER__ */
