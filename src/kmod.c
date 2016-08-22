#include "wtp.h"
#include "dfa.h"
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include "nlsmartcapwap.h"

/* libev handler */
static void wtp_kmod_event_receive(EV_P_ ev_io *w, int revents);

/* Compatibility functions */
#ifdef HAVE_LIBNL_10 
static uint32_t g_portbitmap[32] = { 0 };

static struct nl_sock* nl_socket_alloc_cb(void* cb) {
	int i;
	struct nl_sock* handle;
	uint32_t pid = getpid() & 0x3FFFFF;

	handle = nl_handle_alloc_cb(cb);
	for (i = 0; i < 1024; i++) {
		if (g_portbitmap[i / 32] & (1 << (i % 32))) {
			continue;
		}

		g_portbitmap[i / 32] |= 1 << (i % 32);
		pid += i << 22;
		break;
	}

	nl_socket_set_local_port(handle, pid);
	return handle;
}

static void nl_socket_free(struct nl_sock* handle) {
	uint32_t port = nl_socket_get_local_port(handle);

	port >>= 22;
	g_portbitmap[port / 32] &= ~(1 << (port % 32));

	nl_handle_destroy(handle);
}
#endif

/* */
typedef int (*wtp_kmod_valid_cb)(struct nl_msg* msg, void* data);

/* */
static struct nl_sock* nl_create_handle(struct nl_cb* cb) {
	struct nl_sock* handle;

	handle = nl_socket_alloc_cb(cb);
	if (!handle) {
		return NULL;
	}

	if (genl_connect(handle)) {
		nl_socket_free(handle);
		return NULL;
	}

	return handle;
}

/* */
static int wtp_kmod_no_seq_check(struct nl_msg* msg, void* arg) {
	return NL_OK;
}

/* */
static int wtp_kmod_error_handler(struct sockaddr_nl* nla, struct nlmsgerr* err, void* arg) {
	*((int*)arg) = err->error;
	return NL_STOP;
}

/* */
static int wtp_kmod_finish_handler(struct nl_msg* msg, void* arg) {
	*((int*)arg) = 0;
	return NL_SKIP;
}

/* */
static int wtp_kmod_ack_handler(struct nl_msg* msg, void* arg) {
	*((int*)arg) = 0;
	return NL_STOP;
}

/* */
static int wtp_kmod_event_handler(struct genlmsghdr* gnlh, struct nlattr** tb_msg, void* data) {
	switch (gnlh->cmd) {
		case NLSMARTCAPWAP_CMD_RECV_KEEPALIVE: {
			wtp_recv_data_keepalive();
			break;
		}

		case NLSMARTCAPWAP_CMD_RECV_DATA: {
			if (tb_msg[NLSMARTCAPWAP_ATTR_DATA_FRAME]) {
				wtp_recv_data(nla_data(tb_msg[NLSMARTCAPWAP_ATTR_DATA_FRAME]), nla_len(tb_msg[NLSMARTCAPWAP_ATTR_DATA_FRAME]));
			}

			break;
		}
	}

	return NL_SKIP;
}

/* */
static int wtp_kmod_valid_handler(struct nl_msg* msg, void* data) {
	struct nlattr* tb_msg[NLSMARTCAPWAP_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb_msg, NLSMARTCAPWAP_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	return wtp_kmod_event_handler(gnlh, tb_msg, data);
}

/* */
static int wtp_kmod_send_and_recv(struct nl_sock* nl, struct nl_cb* nl_cb, struct nl_msg* msg, wtp_kmod_valid_cb valid_cb, void* data) {
	int result;
	struct nl_cb* cb;

	/* Clone netlink callback */
	cb = nl_cb_clone(nl_cb);
	if (!cb) {
		return -1;
	}

	/* Complete send message */
	result = nl_send_auto_complete(nl, msg);
	if (result < 0) {
		nl_cb_put(cb);
		return -1;
	}

	/* Customize message callback */
	nl_cb_err(cb, NL_CB_CUSTOM, wtp_kmod_error_handler, &result);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, wtp_kmod_finish_handler, &result);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, wtp_kmod_ack_handler, &result);

	if (valid_cb) {
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_cb, data);
	}

	result = 1;
	while (result > 0) {
		nl_recvmsgs(nl, cb);
	}

	nl_cb_put(cb);
	return result;
}

/* */
static int wtp_kmod_send_and_recv_msg(struct nl_msg* msg, wtp_kmod_valid_cb valid_cb, void* data) {
	return wtp_kmod_send_and_recv(g_wtp.kmodhandle.nlmsg, g_wtp.kmodhandle.nlmsg_cb, msg, valid_cb, data);
}

/* */
static int wtp_kmod_link(void) {
	int result;
	struct nl_msg* msg;

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_wtp.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_LINK, 0);

	/* */
	result = wtp_kmod_send_and_recv(g_wtp.kmodhandle.nl, g_wtp.kmodhandle.nl_cb, msg, NULL, NULL);
	if (result) {
		if (result == -EALREADY) {
			result = 0;
		} else {
			log_printf(LOG_WARNING, "Unable to connect kernel module, error code: %d", result);
		}
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static void wtp_kmod_event_receive(EV_P_ ev_io *w, int revents)
{
	struct wtp_kmod_handle *kmodhandle = (struct wtp_kmod_handle *)
		(((char *)w) - offsetof(struct wtp_kmod_handle, nl_ev));
	int res;


	/* */
	res = nl_recvmsgs(kmodhandle->nl, kmodhandle->nl_cb);
	if (res) {
		log_printf(LOG_WARNING, "Receive kernel module message failed: %d", res);
	}
}

/* */
int wtp_kmod_create(uint16_t family, struct sockaddr_storage* peeraddr,
		    struct capwap_sessionid_element* sessionid, uint16_t mtu) {
	int result;
	struct nl_msg* msg;
	struct sockaddr_storage sockaddr;

	ASSERT((family == AF_INET) || (family == AF_INET6));
	ASSERT(peeraddr != NULL);
	ASSERT((peeraddr->ss_family == AF_INET) || (peeraddr->ss_family == AF_INET6));
	ASSERT(sessionid != NULL);

	/* */
	if (!wtp_kmod_isconnected())
		return -1;

	/* */
	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	memset(&sockaddr, 0, sizeof(struct sockaddr_storage));
	sockaddr.ss_family = family;

	/* */
	genlmsg_put(msg, 0, 0, g_wtp.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_CREATE, 0);
	nla_put(msg, NLSMARTCAPWAP_ATTR_LOCAL_ADDRESS, sizeof(struct sockaddr_storage), &sockaddr);
	nla_put(msg, NLSMARTCAPWAP_ATTR_PEER_ADDRESS, sizeof(struct sockaddr_storage), peeraddr);
	nla_put(msg, NLSMARTCAPWAP_ATTR_SESSION_ID, sizeof(struct capwap_sessionid_element), sessionid);
	nla_put_u16(msg, NLSMARTCAPWAP_ATTR_MTU, mtu);

	/* */
	result = wtp_kmod_send_and_recv_msg(msg, NULL, NULL);

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int wtp_kmod_send_keepalive(void) {
	int result;
	struct nl_msg* msg;

	/* */
	if (!wtp_kmod_isconnected()) {
		return -1;
	}

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_wtp.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_SEND_KEEPALIVE, 0);

	/* */
	result = wtp_kmod_send_and_recv_msg(msg, NULL, NULL);

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int wtp_kmod_resetsession(void) {
	int result;
	struct nl_msg* msg;

	/* */
	if (!wtp_kmod_isconnected()) {
		return -1;
	}

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_wtp.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_RESET, 0);

	/* */
	result = wtp_kmod_send_and_recv_msg(msg, NULL, NULL);

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int wtp_kmod_send_data(uint8_t radioid, const uint8_t* frame, int length, uint8_t rssi, uint8_t snr, uint16_t rate) {
	int result;
	struct nl_msg* msg;

	/* */
	if (!wtp_kmod_isconnected()) {
		return -1;
	}

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_wtp.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_SEND_DATA, 0);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_RADIOID, radioid);
	nla_put(msg, NLSMARTCAPWAP_ATTR_DATA_FRAME, length, frame);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_BINDING, g_wtp.binding);

	if (rssi) {
		nla_put_u8(msg, NLSMARTCAPWAP_ATTR_RSSI, rssi);
	}

	if (snr) {
		nla_put_u8(msg, NLSMARTCAPWAP_ATTR_SNR, snr);
	}

	if (rate) {
		nla_put_u16(msg, NLSMARTCAPWAP_ATTR_RATE, rate);
	}

	/* */
	result = wtp_kmod_send_and_recv_msg(msg, NULL, NULL);

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int wtp_kmod_join_mac80211_device(struct wifi_wlan* wlan, uint32_t flags) {
	int result;
	struct nl_msg* msg;
	struct capwap_list_item* itemlist;
	struct wtp_kmod_iface_handle* interface;
	uint32_t kmodflags = 0;

	ASSERT(wlan != NULL);

	/* */
	if (!wtp_kmod_isconnected()) {
		return -1;
	}

	/* */
	itemlist = capwap_itemlist_create(sizeof(struct wtp_kmod_iface_handle));
	interface = (struct wtp_kmod_iface_handle*)itemlist->item;
	memset(interface, 0, sizeof(struct wtp_kmod_iface_handle));

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		capwap_itemlist_free(itemlist);
		return -1;
	}

	/* Set flags */
	if (flags & WTP_KMOD_FLAGS_TUNNEL_8023) {
		kmodflags |= NLSMARTCAPWAP_FLAGS_TUNNEL_8023;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_wtp.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_JOIN_MAC80211_DEVICE, 0);
	nla_put_u32(msg, NLSMARTCAPWAP_ATTR_IFINDEX, wlan->virtindex);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_RADIOID, wlan->radioid);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_WLANID, wlan->wlanid);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_BINDING, g_wtp.binding);
	nla_put_u32(msg, NLSMARTCAPWAP_ATTR_FLAGS, kmodflags);
	nla_put_u16(msg, NLSMARTCAPWAP_ATTR_MGMT_SUBTYPE_MASK, 0x0000);
	nla_put_u16(msg, NLSMARTCAPWAP_ATTR_CTRL_SUBTYPE_MASK, 0x0000);
	nla_put_u16(msg, NLSMARTCAPWAP_ATTR_DATA_SUBTYPE_MASK, 0xffff);

	/* */
	result = wtp_kmod_send_and_recv_msg(msg, NULL, NULL);
	if (!result) {
		interface->flags = flags;
		interface->wlan = wlan;

		/* */
		capwap_itemlist_insert_after(g_wtp.kmodhandle.interfaces, NULL, itemlist);
	} else {
		capwap_itemlist_free(itemlist);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int wtp_kmod_leave_mac80211_device(struct wifi_wlan* wlan) {
	int result;
	struct nl_msg* msg;

	ASSERT(wlan != NULL);

	/* */
	if (!wtp_kmod_isconnected()) {
		return -1;
	}

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_wtp.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_LEAVE_MAC80211_DEVICE, 0);
	nla_put_u32(msg, NLSMARTCAPWAP_ATTR_IFINDEX, wlan->virtindex);

	/* */
	result = wtp_kmod_send_and_recv_msg(msg, NULL, NULL);
	if (!result) {
		struct capwap_list_item* itemlist;

		for (itemlist = g_wtp.kmodhandle.interfaces->first; itemlist != NULL; itemlist = itemlist->next) {
			struct wtp_kmod_iface_handle* interface = (struct wtp_kmod_iface_handle*)itemlist->item;

			if (interface->wlan == wlan) {
				capwap_itemlist_free(capwap_itemlist_remove(g_wtp.kmodhandle.interfaces, itemlist));
				break;
			}
		}
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int wtp_kmod_add_station(uint8_t radioid, const uint8_t *mac, uint8_t wlanid, uint32_t flags)
{
	int result;
	struct nl_msg* msg;

	/* */
	if (!wtp_kmod_isconnected())
		return -1;

	/* */
	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	/* */
	genlmsg_put(msg, 0, 0, g_wtp.kmodhandle.nlsmartcapwap_id, 0,
		    NLM_F_CREATE | NLM_F_REPLACE, NLSMARTCAPWAP_CMD_ADD_STATION, 0);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_RADIOID, radioid);
	nla_put(msg, NLSMARTCAPWAP_ATTR_MAC, ETH_ALEN, mac);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_WLANID, wlanid);
	nla_put_u32(msg, NLSMARTCAPWAP_ATTR_FLAGS, wlanid);

	/* */
	result = wtp_kmod_send_and_recv_msg(msg, NULL, NULL);

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int wtp_kmod_del_station(uint8_t radioid, const uint8_t *mac)
{
	int result;
	struct nl_msg* msg;

	/* */
	if (!wtp_kmod_isconnected())
		return -1;

	/* */
	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	/* */
	genlmsg_put(msg, 0, 0, g_wtp.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_DEL_STATION, 0);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_RADIOID, radioid);
	nla_put(msg, NLSMARTCAPWAP_ATTR_MAC, ETH_ALEN, mac);

	/* */
	result = wtp_kmod_send_and_recv_msg(msg, NULL, NULL);

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int wtp_kmod_isconnected(void) {
	return (g_wtp.kmodhandle.nlsmartcapwap_id ? 1 : 0);
}

/* */
int wtp_kmod_init(void) {
	int result;

	/* Configure netlink callback */
	g_wtp.kmodhandle.nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!g_wtp.kmodhandle.nl_cb) {
		wtp_kmod_free();
		return -1;
	}

	/* Create netlink socket */
	g_wtp.kmodhandle.nl = nl_create_handle(g_wtp.kmodhandle.nl_cb);
	if (!g_wtp.kmodhandle.nl) {
		wtp_kmod_free();
		return -1;
	}

	/* Get nlsmartcapwap netlink family */
	g_wtp.kmodhandle.nlsmartcapwap_id = genl_ctrl_resolve(g_wtp.kmodhandle.nl, NLSMARTCAPWAP_GENL_NAME);
	if (g_wtp.kmodhandle.nlsmartcapwap_id < 0) {
		log_printf(LOG_WARNING, "Unable to found kernel module");
		wtp_kmod_free();
		return -1;
	}

	/* Configure callback function */
	nl_cb_set(g_wtp.kmodhandle.nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, wtp_kmod_no_seq_check, NULL);
	nl_cb_set(g_wtp.kmodhandle.nl_cb, NL_CB_VALID, NL_CB_CUSTOM, wtp_kmod_valid_handler, NULL);

	/* Link to kernel module */
	result = wtp_kmod_link();
	if (result) {
		wtp_kmod_free();
		return result;
	}

	/* Configure netlink message socket */
	g_wtp.kmodhandle.nlmsg_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!g_wtp.kmodhandle.nlmsg_cb) {
		wtp_kmod_free();
		return -1;
	}

	/* */
	g_wtp.kmodhandle.nlmsg = nl_create_handle(g_wtp.kmodhandle.nlmsg_cb);
	if (!g_wtp.kmodhandle.nlmsg) {
		wtp_kmod_free();
		return -1;
	}

	/* */
	g_wtp.kmodhandle.interfaces = capwap_list_create();

	/* Configure libev struct */
	ev_io_init(&g_wtp.kmodhandle.nl_ev, wtp_kmod_event_receive,
		    nl_socket_get_fd(g_wtp.kmodhandle.nl), EV_READ);
	ev_io_start(EV_DEFAULT_UC_ &g_wtp.kmodhandle.nl_ev);

	return 0;
}

/* */
void wtp_kmod_free(void) {
	if (g_wtp.kmodhandle.interfaces) {
		while (g_wtp.kmodhandle.interfaces->first) {
			struct wtp_kmod_iface_handle* interface = (struct wtp_kmod_iface_handle*)g_wtp.kmodhandle.interfaces->first->item;

			if (wtp_kmod_leave_mac80211_device(interface->wlan)) {
				break;
			}
		}

		/* */
		capwap_list_free(g_wtp.kmodhandle.interfaces);
	}

	if (g_wtp.kmodhandle.nlmsg) {
		nl_socket_free(g_wtp.kmodhandle.nlmsg);
	}

	if (g_wtp.kmodhandle.nlmsg_cb) {
		nl_cb_put(g_wtp.kmodhandle.nlmsg_cb);
	}

	if (g_wtp.kmodhandle.nl) {
		nl_socket_free(g_wtp.kmodhandle.nl);
	}

	if (g_wtp.kmodhandle.nl_cb) {
		nl_cb_put(g_wtp.kmodhandle.nl_cb);
	}

	/* */
	memset(&g_wtp.kmodhandle, 0, sizeof(struct wtp_kmod_handle));
}
