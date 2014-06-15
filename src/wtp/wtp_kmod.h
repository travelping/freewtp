#ifndef __WTP_KMOD_HEADER__
#define __WTP_KMOD_HEADER__

#include "wifi_drivers.h"

/* */
#ifdef HAVE_LIBNL_10 
#define nl_sock nl_handle
#endif

/* */
#define WTP_KMOD_MODE_LOCAL							0x00000001
#define WTP_KMOD_MODE_TUNNEL_USERMODE				0x00000002
#define WTP_KMOD_MODE_TUNNEL_KERNELMODE				0x00000003

/* */
#define WTP_KMOD_FLAGS_TUNNEL_NATIVE				0x00000000
#define WTP_KMOD_FLAGS_TUNNEL_8023					0x00000001

/* */
struct wtp_kmod_iface_handle {
	struct nl_sock* nl;
	int nl_fd;
	struct nl_cb* nl_cb;

	uint32_t mode;
	uint32_t flags;
	struct wifi_wlan* wlan;
};

/* */
struct wtp_kmod_handle {
	struct nl_sock* nl;
	int nl_fd;
	struct nl_cb* nl_cb;
	int nlsmartcapwap_id;

	/* */
	struct capwap_list* interfaces;
	int interfaceconnectioncount;
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
int wtp_kmod_join_mac80211_device(struct wifi_wlan* wlan, uint32_t mode, uint32_t flags);
int wtp_kmod_leave_mac80211_device(struct wifi_wlan* wlan);

#endif /* __WTP_KMOD_HEADER__ */
