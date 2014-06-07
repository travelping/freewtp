#ifndef __WTP_KMOD_HEADER__
#define __WTP_KMOD_HEADER__

/* */
#ifdef HAVE_LIBNL_10 
#define nl_sock nl_handle
#endif

/* */
struct wtp_kmod_handle {
	struct nl_sock* nl;
	int nl_fd;
	struct nl_cb* nl_cb;
	int nlsmartcapwap_id;
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
int wtp_kmod_join_mac80211_device(uint32_t ifindex);

#endif /* __WTP_KMOD_HEADER__ */
