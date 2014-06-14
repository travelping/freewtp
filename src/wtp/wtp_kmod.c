#include "wtp.h"
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include "nlsmartcapwap.h"

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
		case NLSMARTCAPWAP_CMD_FRAME: {
			struct wtp_kmod_iface_handle* interface = (struct wtp_kmod_iface_handle*)data;

			if (tb_msg[NLSMARTCAPWAP_ATTR_FRAME]) {
				uint32_t sig_dbm = (tb_msg[NLSMARTCAPWAP_ATTR_RX_SIGNAL_DBM] ? nla_get_u32(tb_msg[NLSMARTCAPWAP_ATTR_RX_SIGNAL_DBM]) : 0);
				uint16_t rate = (tb_msg[NLSMARTCAPWAP_ATTR_RX_RATE] ? ((uint16_t)nla_get_u8(tb_msg[NLSMARTCAPWAP_ATTR_RX_RATE])) * 5 : 0);		/* Convert rate 500Kbps to 100Kbps */
				int nativeframe = (tb_msg[SMARTCAPWAP_FLAGS_TUNNEL_8023] ? 0 : 1);

				/* Forwards the frame to AC */
				wifi_wlan_send_frame(interface->wlan, (uint8_t*)nla_data(tb_msg[NLSMARTCAPWAP_ATTR_FRAME]), nla_len(tb_msg[NLSMARTCAPWAP_ATTR_FRAME]), nativeframe, (uint8_t)sig_dbm, 0, rate);
			}

			break;
		}

		default: {
			capwap_logging_debug("*** wtp_kmod_event_handler: %d", (int)gnlh->cmd);
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
	return wtp_kmod_send_and_recv(g_wtp.kmodhandle.nl, g_wtp.kmodhandle.nl_cb, msg, valid_cb, data);
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
	result = wtp_kmod_send_and_recv_msg(msg, NULL, NULL);
	if (result) {
		if (result == -EALREADY) {
			result = 0;
		} else {
			capwap_logging_warning("Unable to connect kernel module, error code: %d", result);
		}
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static void wtp_kmod_event_receive(int fd, void** params, int paramscount) {
	int res;

	ASSERT(fd >= 0);
	ASSERT(params != NULL);
	ASSERT(paramscount == 2); 

	/* */
	res = nl_recvmsgs((struct nl_sock*)params[0], (struct nl_cb*)params[1]);
	if (res) {
		capwap_logging_warning("Receive kernel module message failed: %d", res);
	}
}

/* */
int wtp_kmod_join_mac80211_device(struct wifi_wlan* wlan, uint32_t mode, uint32_t flags) {
	int result;
	struct nl_msg* msg;
	struct capwap_list_item* itemlist;
	struct wtp_kmod_iface_handle* interface;
	uint32_t kmodflags = 0;
	uint16_t subtype_mgmt = 0;
	uint16_t subtype_ctrl = 0;
	uint16_t subtype_data = 0;

	ASSERT(wlan != NULL);

	/* */
	if (!wtp_kmod_isconnected()) {
		return -1;
	}

	/* */
	itemlist = capwap_itemlist_create(sizeof(struct wtp_kmod_iface_handle));
	interface = (struct wtp_kmod_iface_handle*)itemlist->item;
	memset(interface, 0, sizeof(struct wtp_kmod_iface_handle));

	/* Socket management */
	if (mode == WTP_KMOD_MODE_TUNNEL_USERMODE) {
		interface->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
		if (!interface->nl_cb) {
			capwap_itemlist_free(itemlist);
			return -1;
		}

		nl_cb_set(interface->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, wtp_kmod_no_seq_check, NULL);
		nl_cb_set(interface->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, wtp_kmod_valid_handler, (void*)interface);

		interface->nl = nl_create_handle(interface->nl_cb);
		if (interface->nl) {
			interface->nl_fd = nl_socket_get_fd(interface->nl);
		} else {
			nl_cb_put(interface->nl_cb);
			capwap_itemlist_free(itemlist);
			return -1;
		}
	}

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		if (mode == WTP_KMOD_MODE_TUNNEL_USERMODE) {
			nl_socket_free(interface->nl);
			nl_cb_put(interface->nl_cb);
		}

		capwap_itemlist_free(itemlist);
		return -1;
	}

	/* Set flags */
	switch (mode) {
		case WTP_KMOD_MODE_LOCAL: {
			break;
		}

		case WTP_KMOD_MODE_TUNNEL_USERMODE: {
			kmodflags |= SMARTCAPWAP_FLAGS_SEND_USERSPACE | SMARTCAPWAP_FLAGS_BLOCK_DATA_FRAME;
			subtype_data = 0xffff;

			if (flags & WTP_KMOD_FLAGS_TUNNEL_8023) {
				kmodflags |= SMARTCAPWAP_FLAGS_TUNNEL_8023;
			}

			break;
		}

		case WTP_KMOD_MODE_TUNNEL_KERNELMODE: {
			kmodflags |= SMARTCAPWAP_FLAGS_BLOCK_DATA_FRAME;
			subtype_data = 0xffff;

			if (flags & WTP_KMOD_FLAGS_TUNNEL_8023) {
				kmodflags |= SMARTCAPWAP_FLAGS_TUNNEL_8023;
			}

			break;
		}
	}

	/* */
	genlmsg_put(msg, 0, 0, g_wtp.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_JOIN_MAC80211_DEVICE, 0);
	nla_put_u32(msg, NLSMARTCAPWAP_ATTR_IFINDEX, wlan->virtindex);
	nla_put_u32(msg, NLSMARTCAPWAP_ATTR_FLAGS, kmodflags);
	nla_put_u16(msg, NLSMARTCAPWAP_ATTR_MGMT_SUBTYPE_MASK, subtype_mgmt);
	nla_put_u16(msg, NLSMARTCAPWAP_ATTR_CTRL_SUBTYPE_MASK, subtype_ctrl);
	nla_put_u16(msg, NLSMARTCAPWAP_ATTR_DATA_SUBTYPE_MASK, subtype_data);

	/* */
	result = wtp_kmod_send_and_recv(interface->nl, interface->nl_cb, msg, NULL, NULL);
	if (!result) {
		interface->wlan = wlan;

		/* */
		capwap_itemlist_insert_after(g_wtp.kmodhandle.interfaces, NULL, itemlist);
	} else {
		nl_socket_free(interface->nl);
		nl_cb_put(interface->nl_cb);
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
				nl_socket_free(interface->nl);
				nl_cb_put(interface->nl_cb);

				/* Free item */
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
int wtp_kmod_isconnected(void) {
	return (g_wtp.kmodhandle.nlsmartcapwap_id ? 1 : 0);
}

/* */
int wtp_kmod_getfd(struct pollfd* fds, struct wtp_kmod_event* events, int count) {
	int i;
	struct capwap_list_item* itemlist;
	int kmodcount = 0;

	/* */
	if (wtp_kmod_isconnected()) {
		kmodcount = 1;
		for (itemlist = g_wtp.kmodhandle.interfaces->first; itemlist; itemlist = itemlist->next) {
			struct wtp_kmod_iface_handle* interface = (struct wtp_kmod_iface_handle*)itemlist->item;

			if (interface->nl_fd) {
				kmodcount++;
			}
		}
	}

	/* */
	if (!kmodcount) {
		return 0;
	} else if (!fds && !events && !count) {
		return kmodcount;
	} else if ((count > 0) && (!fds || !events)) {
		return -1;
	} else if (count < kmodcount) {
		return -1;
	}

	/* */
	fds[0].fd = g_wtp.kmodhandle.nl_fd;
	fds[0].events = POLLIN | POLLERR | POLLHUP;

	/* */
	events[0].event_handler = wtp_kmod_event_receive;
	events[0].params[0] = (void*)g_wtp.kmodhandle.nl;
	events[0].params[1] = (void*)g_wtp.kmodhandle.nl_cb;
	events[0].paramscount = 2;

	/* */
	for (i = 1, itemlist = g_wtp.kmodhandle.interfaces->first; itemlist; itemlist = itemlist->next) {
		struct wtp_kmod_iface_handle* interface = (struct wtp_kmod_iface_handle*)itemlist->item;

		/* */
		if (interface->nl_fd) {
			fds[i].fd = interface->nl_fd;
			fds[i].events = POLLIN | POLLERR | POLLHUP;

			/* */
			events[i].event_handler = wtp_kmod_event_receive;
			events[i].params[0] = (void*)interface->nl;
			events[i].params[1] = (void*)interface->nl_cb;
			events[i].paramscount = 2;

			/* */
			i++;
		}
	}

	ASSERT(kmodcount == i);
	return kmodcount;
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

	g_wtp.kmodhandle.nl_fd = nl_socket_get_fd(g_wtp.kmodhandle.nl);

	/* Get nlsmartcapwap netlink family */
	g_wtp.kmodhandle.nlsmartcapwap_id = genl_ctrl_resolve(g_wtp.kmodhandle.nl, SMARTCAPWAP_GENL_NAME);
	if (g_wtp.kmodhandle.nlsmartcapwap_id < 0) {
		capwap_logging_warning("Unable to found kernel module");
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

	/* */
	g_wtp.kmodhandle.interfaces = capwap_list_create();
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

	if (g_wtp.kmodhandle.nl) {
		nl_socket_free(g_wtp.kmodhandle.nl);
	}

	if (g_wtp.kmodhandle.nl_cb) {
		nl_cb_put(g_wtp.kmodhandle.nl_cb);
	}

	/* */
	memset(&g_wtp.kmodhandle, 0, sizeof(struct wtp_kmod_handle));
}
