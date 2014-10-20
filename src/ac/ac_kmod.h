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
	struct nl_sock* nl;
	int nl_fd;
	struct nl_cb* nl_cb;
	int nlsmartcapwap_id;
};

/* */
#define AC_KMOD_EVENT_MAX_ITEMS				2
struct ac_kmod_event {
	void (*event_handler)(int fd, void** params, int paramscount);
	int paramscount;
	void* params[AC_KMOD_EVENT_MAX_ITEMS];
};

/* */
int ac_kmod_init(uint32_t hash, uint32_t threads);
void ac_kmod_free(void);

/* */
int ac_kmod_isconnected(void);
int ac_kmod_getfd(struct pollfd* fds, struct ac_kmod_event* events, int count);

/* */
int ac_kmod_createdatachannel(int family, unsigned short port);

/* */
int ac_kmod_send_keepalive(struct sockaddr_storage* sockaddr);
int ac_kmod_send_data(struct sockaddr_storage* sockaddr, uint8_t radioid, uint8_t binding, const uint8_t* data, int length);

/* */
int ac_kmod_create_iface(const char* ifname, uint16_t mtu);
int ac_kmod_delete_iface(int ifindex);

/* */
int ac_kmod_new_datasession(struct capwap_sessionid_element* sessionid, uint16_t mtu);
int ac_kmod_delete_datasession(struct capwap_sessionid_element* sessionid);

#endif /* __AC_KMOD_HEADER__ */
