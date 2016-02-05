#ifndef __KMOD_CAPWAP_PRIVATE_HEADER__
#define __KMOD_CAPWAP_PRIVATE_HEADER__

/* */
struct sc_capwap_wlan {
	int used;

	uint8_t bssid[MACADDRESS_EUI48_LENGTH];
	uint8_t macmode;
	uint8_t tunnelmode;
};

/* */
struct sc_capwap_session_priv {
	struct sc_capwap_session session;

	struct list_head list;
	struct sc_capwap_session_priv* __rcu next_ipaddr;
	struct sc_capwap_session_priv* __rcu next_sessionid;

	struct list_head list_stations;
	struct list_head list_connections;

	/* */
	int isolation;
	uint8_t binding;
	struct sc_capwap_wlan wlans[CAPWAP_RADIOID_MAX_COUNT][CAPWAP_WLANID_MAX_COUNT];
};

/* */
struct sc_capwap_workthread {
	struct task_struct* thread;

	struct sk_buff_head queue;
	wait_queue_head_t waitevent;
};

/* */
int sc_capwap_init(void);
void sc_capwap_close(void);

/* */
void sc_capwap_update_lock(void);
void sc_capwap_update_unlock(void);

#ifdef CONFIG_PROVE_LOCKING
int sc_capwap_update_lock_is_locked(void);
#else
static inline int sc_capwap_update_lock_is_locked(void) { return 1; }
#endif

/* */
int sc_capwap_sendkeepalive(const struct sc_capwap_sessionid_element* sessionid);

/* */
int sc_capwap_newsession(const struct sc_capwap_sessionid_element* sessionid, uint8_t binding, uint16_t mtu);
int sc_capwap_deletesession(const struct sc_capwap_sessionid_element* sessionid);

/* */
int sc_capwap_addwlan(const struct sc_capwap_sessionid_element* sessionid, uint8_t radioid, uint8_t wlanid, const uint8_t* bssid, uint8_t macmode, uint8_t tunnelmode);
int sc_capwap_removewlan(const struct sc_capwap_sessionid_element* sessionid, uint8_t radioid, uint8_t wlanid);

/* */
int sc_capwap_authstation(const struct sc_capwap_sessionid_element* sessionid, const uint8_t* address, uint32_t ifindex, uint8_t radioid, uint8_t wlanid, uint16_t vlan);
int sc_capwap_deauthstation(const struct sc_capwap_sessionid_element* sessionid, const uint8_t* address);

#endif /* __KMOD_CAPWAP_PRIVATE_HEADER__ */
