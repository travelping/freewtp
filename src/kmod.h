#ifndef __WTP_KMOD_HEADER__
#define __WTP_KMOD_HEADER__

#include "wifi_drivers.h"

/* */
#ifdef HAVE_LIBNL_10 
#define nl_sock nl_handle
#endif

/* */
#define WTP_KMOD_FLAGS_TUNNEL_NATIVE				0x00000000
#define WTP_KMOD_FLAGS_TUNNEL_8023					0x00000001

/* */
struct wtp_kmod_iface_handle {
	uint32_t flags;
	struct wifi_wlan* wlan;
};

/* */
struct wtp_kmod_handle {
	struct nl_sock* nl;
	struct nl_cb* nl_cb;
	int nlsmartcapwap_id;
	ev_io nl_ev;

	/* */
	struct nl_sock* nlmsg;
	struct nl_cb* nlmsg_cb;

	/* */
	struct capwap_list* interfaces;
};

/* */
#define WTP_KMOD_EVENT_MAX_ITEMS				2
struct wtp_kmod_event {
	void (*event_handler)(int fd, void** params, int paramscount);
	int paramscount;
	void* params[WTP_KMOD_EVENT_MAX_ITEMS];
};

/* */
int wtp_kmod_init(void);
void wtp_kmod_free(void);

/* */
int wtp_kmod_isconnected(void);
int wtp_kmod_getfd(struct pollfd* fds, struct wtp_kmod_event* events, int count);

/* */
int wtp_kmod_create(uint16_t family, struct sockaddr_storage* peeraddr,
		    struct capwap_sessionid_element* sessionid, uint16_t mtu);
int wtp_kmod_resetsession(void);

/* */
int wtp_kmod_send_keepalive(void);
int wtp_kmod_send_data(uint8_t radioid, const uint8_t* frame, int length, uint8_t rssi, uint8_t snr, uint16_t rate);

/* */
int wtp_kmod_join_mac80211_device(struct wifi_wlan* wlan, uint32_t flags);
int wtp_kmod_leave_mac80211_device(struct wifi_wlan* wlan);

/* */
#define STA_FLAG_AKM_ONLY	0x0001

/* */
int wtp_kmod_add_station(uint8_t radioid, const uint8_t *mac, uint8_t wlanid, uint32_t flags);
int wtp_kmod_del_station(uint8_t radioid, const uint8_t *mac);

#endif /* __WTP_KMOD_HEADER__ */
