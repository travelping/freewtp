#ifndef __AC_KMOD_HEADER__
#define __AC_KMOD_HEADER__

/* */
#ifdef HAVE_LIBNL_10 
#define nl_sock nl_handle
#endif

/* */
#define AC_KMOD_MODE_LOCAL							0x00000001
#define AC_KMOD_MODE_TUNNEL_USERMODE				0x00000002
#define AC_KMOD_MODE_TUNNEL_KERNELMODE				0x00000003

/* */
#define AC_KMOD_FLAGS_TUNNEL_NATIVE					0x00000000
#define AC_KMOD_FLAGS_TUNNEL_8023					0x00000001

/* */
struct ac_kmod_handle {
	/* Callback */
	struct nl_sock* nl;
	int nl_fd;
	struct nl_cb* nl_cb;
	int nlsmartcapwap_id;

	/* Send message */
	struct nl_sock* nlmsg;
	struct nl_cb* nlmsg_cb;
};

/* */
#define AC_KMOD_EVENT_MAX_ITEMS				2
struct ac_kmod_event {
	void (*event_handler)(int fd, void** params, int paramscount);
	int paramscount;
	void* params[AC_KMOD_EVENT_MAX_ITEMS];
};

/* */
int ac_kmod_init(void);
void ac_kmod_free(void);

/* */
int ac_kmod_isconnected(void);
int ac_kmod_getfd(struct pollfd* fds, struct ac_kmod_event* events, int count);

/* */
int ac_kmod_createdatachannel(int family, unsigned short port);

/* */
int ac_kmod_send_keepalive(struct capwap_sessionid_element* sessionid);
int ac_kmod_send_data(struct capwap_sessionid_element* sessionid, uint8_t radioid, uint8_t binding, const uint8_t* data, int length);

/* */
int ac_kmod_create_iface(const char* ifname, uint16_t mtu);
int ac_kmod_delete_iface(int ifindex);

/* */
int ac_kmod_new_datasession(struct capwap_sessionid_element* sessionid, uint8_t binding, uint16_t mtu);
int ac_kmod_delete_datasession(struct capwap_sessionid_element* sessionid);

/* */
int ac_kmod_addwlan(struct capwap_sessionid_element* sessionid, uint8_t radioid, uint8_t wlanid, const uint8_t* bssid, uint8_t macmode, uint8_t tunnelmode);
int ac_kmod_removewlan(struct capwap_sessionid_element* sessionid);

/* */
int ac_kmod_authorize_station(struct capwap_sessionid_element* sessionid, const uint8_t* macaddress, int ifindex, uint8_t radioid, uint8_t wlanid, uint16_t vlan);
int ac_kmod_deauthorize_station(struct capwap_sessionid_element* sessionid, const uint8_t* macaddress);

#endif /* __AC_KMOD_HEADER__ */
