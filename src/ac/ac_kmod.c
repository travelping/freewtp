#include "ac.h"
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include "ac_session.h"
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
typedef int (*ac_kmod_valid_cb)(struct nl_msg* msg, void* data);

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
static int ac_kmod_no_seq_check(struct nl_msg* msg, void* arg) {
	return NL_OK;
}

/* */
static int ac_kmod_error_handler(struct sockaddr_nl* nla, struct nlmsgerr* err, void* arg) {
	*((int*)arg) = err->error;
	return NL_STOP;
}

/* */
static int ac_kmod_finish_handler(struct nl_msg* msg, void* arg) {
	*((int*)arg) = 0;
	return NL_SKIP;
}

/* */
static int ac_kmod_ack_handler(struct nl_msg* msg, void* arg) {
	*((int*)arg) = 0;
	return NL_STOP;
}

/* */
static int ac_kmod_event_handler(struct genlmsghdr* gnlh, struct nlattr** tb_msg, void* data) {
	switch (gnlh->cmd) {
		case NLSMARTCAPWAP_CMD_RECV_KEEPALIVE: {
			if (tb_msg[NLSMARTCAPWAP_ATTR_SESSION_ID]) {
				struct capwap_sessionid_element* sessionid = (struct capwap_sessionid_element*)nla_data(tb_msg[NLSMARTCAPWAP_ATTR_SESSION_ID]);
				struct ac_session_t* session = ac_search_session_from_sessionid(sessionid);

				if (session) {
					ac_kmod_send_keepalive(sessionid);
					ac_session_send_action(session, AC_SESSION_ACTION_RECV_KEEPALIVE, 0, NULL, 0);
					ac_session_release_reference(session);
				}
			}

			break;
		}

		case NLSMARTCAPWAP_CMD_RECV_DATA: {
			if (tb_msg[NLSMARTCAPWAP_ATTR_SESSION_ID] && tb_msg[NLSMARTCAPWAP_ATTR_DATA_FRAME]) {
				struct ac_session_t* session = ac_search_session_from_sessionid((struct capwap_sessionid_element*)nla_data(tb_msg[NLSMARTCAPWAP_ATTR_SESSION_ID]));

				if (session) {
					ac_session_send_action(session, AC_SESSION_ACTION_RECV_IEEE80211_MGMT_PACKET, 0, nla_data(tb_msg[NLSMARTCAPWAP_ATTR_DATA_FRAME]), nla_len(tb_msg[NLSMARTCAPWAP_ATTR_DATA_FRAME]));
					ac_session_release_reference(session);
				}
			}

			break;
		}
	}

	return NL_SKIP;
}

/* */
static int ac_kmod_valid_handler(struct nl_msg* msg, void* data) {
	struct nlattr* tb_msg[NLSMARTCAPWAP_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb_msg, NLSMARTCAPWAP_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	return ac_kmod_event_handler(gnlh, tb_msg, data);
}

/* */
static int ac_kmod_send_and_recv(struct nl_sock* nl, struct nl_cb* nl_cb, struct nl_msg* msg, ac_kmod_valid_cb valid_cb, void* data) {
	int result;
	struct nl_cb* cb;

	/* Clone netlink callback */
	cb = nl_cb_clone(nl_cb);
	if (!cb) {
		return -1;
	}

	/* */
	capwap_lock_enter(&g_ac.kmodhandle.msglock);

	/* Complete send message */
	result = nl_send_auto_complete(nl, msg);
	if (result >= 0) {
		/* Customize message callback */
		nl_cb_err(cb, NL_CB_CUSTOM, ac_kmod_error_handler, &result);
		nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, ac_kmod_finish_handler, &result);
		nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ac_kmod_ack_handler, &result);

		if (valid_cb) {
			nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_cb, data);
		}

		result = 1;
		while (result > 0) {
			nl_recvmsgs(nl, cb);
		}
	}

	/* */
	capwap_lock_exit(&g_ac.kmodhandle.msglock);
	nl_cb_put(cb);

	return result;
}

/* */
static int ac_kmod_send_and_recv_msg(struct nl_msg* msg, ac_kmod_valid_cb valid_cb, void* data) {
	return ac_kmod_send_and_recv(g_ac.kmodhandle.nlmsg, g_ac.kmodhandle.nlmsg_cb, msg, valid_cb, data);
}

/* */
static int ac_kmod_link(void) {
	int result;
	struct nl_msg* msg;

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_ac.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_LINK, 0);

	/* */
	result = ac_kmod_send_and_recv(g_ac.kmodhandle.nl, g_ac.kmodhandle.nl_cb, msg, NULL, NULL);
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
static void ac_kmod_event_receive(int fd, void** params, int paramscount) {
	int res;

	ASSERT(fd >= 0);
	ASSERT(params != NULL);
	ASSERT(paramscount == 2); 

	/* */
	res = nl_recvmsgs((struct nl_sock*)params[0], (struct nl_cb*)params[1]);
	if (res) {
		log_printf(LOG_WARNING, "Receive kernel module message failed: %d", res);
	}
}

/* */
int ac_kmod_send_keepalive(struct capwap_sessionid_element* sessionid) {
	int result;
	struct nl_msg* msg;

	ASSERT(sessionid != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_ac.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_SEND_KEEPALIVE, 0);
	nla_put(msg, NLSMARTCAPWAP_ATTR_SESSION_ID, sizeof(struct capwap_sessionid_element), sessionid);

	/* */
	log_printf(LOG_DEBUG, "Prepare to send keep-alive");
	result = ac_kmod_send_and_recv_msg(msg, NULL, NULL);
	if (result) {
		log_printf(LOG_ERR, "Unable to send keep-alive: %d", result);
	}
	log_printf(LOG_DEBUG, "Sent keep-alive");

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int ac_kmod_send_data(struct capwap_sessionid_element* sessionid, uint8_t radioid, uint8_t binding, const uint8_t* data, int length) {
	int result;
	struct nl_msg* msg;

	ASSERT(sessionid != NULL);
	ASSERT(data != NULL);
	ASSERT(length > 0);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_ac.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_SEND_DATA, 0);
	nla_put(msg, NLSMARTCAPWAP_ATTR_SESSION_ID, sizeof(struct capwap_sessionid_element), sessionid);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_RADIOID, radioid);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_BINDING, binding);
	nla_put(msg, NLSMARTCAPWAP_ATTR_DATA_FRAME, length, data);

	/* */
	result = ac_kmod_send_and_recv_msg(msg, NULL, NULL);
	if (result) {
		log_printf(LOG_ERR, "Unable to send data: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int ac_kmod_isconnected(void) {
	return (g_ac.kmodhandle.nlsmartcapwap_id ? 1 : 0);
}

/* */
int ac_kmod_getfd(struct pollfd* fds, struct ac_kmod_event* events, int count) {
	int kmodcount = (ac_kmod_isconnected() ? 1 : 0);

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
	fds[0].fd = g_ac.kmodhandle.nl_fd;
	fds[0].events = POLLIN | POLLERR | POLLHUP;

	/* */
	events[0].event_handler = ac_kmod_event_receive;
	events[0].params[0] = (void*)g_ac.kmodhandle.nl;
	events[0].params[1] = (void*)g_ac.kmodhandle.nl_cb;
	events[0].paramscount = 2;

	return kmodcount;
}

/* */
int ac_kmod_createdatachannel(int family, unsigned short port) {
	int result;
	struct nl_msg* msg;
	struct sockaddr_storage sockaddr;

	ASSERT((family == AF_INET) || (family == AF_INET6));
	ASSERT(port != 0);

	/* */
	memset(&sockaddr, 0, sizeof(struct sockaddr_storage));
	sockaddr.ss_family = family;
	if (sockaddr.ss_family == AF_INET) {
		((struct sockaddr_in*)&sockaddr)->sin_port = htons(port);
	} else if (sockaddr.ss_family == AF_INET6) {
		((struct sockaddr_in6*)&sockaddr)->sin6_port = htons(port);
	}

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_ac.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_BIND, 0);
	nla_put(msg, NLSMARTCAPWAP_ATTR_ADDRESS, sizeof(struct sockaddr_storage), &sockaddr);

	/* */
	result = ac_kmod_send_and_recv_msg(msg, NULL, NULL);
	if (result) {
		log_printf(LOG_ERR, "Unable to bind kernel socket: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int ac_kmod_new_datasession(struct capwap_sessionid_element* sessionid, uint8_t binding, uint16_t mtu) {
	int result;
	struct nl_msg* msg;

	ASSERT(sessionid != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_ac.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_NEW_SESSION, 0);
	nla_put(msg, NLSMARTCAPWAP_ATTR_SESSION_ID, sizeof(struct capwap_sessionid_element), sessionid);
	nla_put_u16(msg, NLSMARTCAPWAP_ATTR_BINDING, binding);
	nla_put_u16(msg, NLSMARTCAPWAP_ATTR_MTU, mtu);

	/* */
	result = ac_kmod_send_and_recv_msg(msg, NULL, NULL);
	if (result) {
		log_printf(LOG_ERR, "Unable to create data session: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int ac_kmod_delete_datasession(struct capwap_sessionid_element* sessionid) {
	int result;
	struct nl_msg* msg;

	ASSERT(sessionid != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_ac.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_DELETE_SESSION, 0);
	nla_put(msg, NLSMARTCAPWAP_ATTR_SESSION_ID, sizeof(struct capwap_sessionid_element), sessionid);

	/* */
	result = ac_kmod_send_and_recv_msg(msg, NULL, NULL);
	if (result && (result != ENOENT)) {
		log_printf(LOG_ERR, "Unable to delete data session: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int ac_kmod_addwlan(struct capwap_sessionid_element* sessionid, uint8_t radioid, uint8_t wlanid, const uint8_t* bssid, uint8_t macmode, uint8_t tunnelmode) {
	int result;
	struct nl_msg* msg;

	ASSERT(sessionid != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(IS_VALID_WLANID(wlanid));
	ASSERT(bssid != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_ac.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_ADD_WLAN, 0);
	nla_put(msg, NLSMARTCAPWAP_ATTR_SESSION_ID, sizeof(struct capwap_sessionid_element), sessionid);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_RADIOID, radioid);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_WLANID, wlanid);
	nla_put(msg, NLSMARTCAPWAP_ATTR_MACADDRESS, MACADDRESS_EUI48_LENGTH, bssid);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_MACMODE, macmode);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_TUNNELMODE, tunnelmode);

	/* */
	result = ac_kmod_send_and_recv_msg(msg, NULL, NULL);
	if (result) {
		log_printf(LOG_ERR, "Unable to add wlan: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int ac_kmod_removewlan(struct capwap_sessionid_element* sessionid) {
	int result;
	struct nl_msg* msg;

	ASSERT(sessionid != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_ac.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_REMOVE_WLAN, 0);
	nla_put(msg, NLSMARTCAPWAP_ATTR_SESSION_ID, sizeof(struct capwap_sessionid_element), sessionid);

	/* */
	result = ac_kmod_send_and_recv_msg(msg, NULL, NULL);
	if (result && (result != ENOENT)) {
		log_printf(LOG_ERR, "Unable to remove wlan: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static int cb_kmod_create_iface(struct nl_msg* msg, void* data) {
	struct nlattr* tb_msg[NLSMARTCAPWAP_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));
	uint32_t* ifindex = (uint32_t*)data;

	nla_parse(tb_msg, NLSMARTCAPWAP_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NLSMARTCAPWAP_ATTR_IFPHY_INDEX]) {
		*ifindex = nla_get_u32(tb_msg[NLSMARTCAPWAP_ATTR_IFPHY_INDEX]);
	}

	return NL_SKIP;
}

/* */
int ac_kmod_create_iface(const char* ifname, uint16_t mtu) {
	int result;
	struct nl_msg* msg;
	uint32_t ifindex = 0;

	ASSERT(ifname != NULL);
	ASSERT(mtu > 0);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_ac.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_ADD_IFACE, 0);
	nla_put_string(msg, NLSMARTCAPWAP_ATTR_IFPHY_NAME, ifname);
	nla_put_u16(msg, NLSMARTCAPWAP_ATTR_MTU, mtu);

	/* */
	result = ac_kmod_send_and_recv_msg(msg, cb_kmod_create_iface, &ifindex);
	if (!result) {
		result = (ifindex ? (int)ifindex : -1);
	} else {
		log_printf(LOG_ERR, "Unable to create data session: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int ac_kmod_delete_iface(int ifindex) {
	int result;
	struct nl_msg* msg;

	ASSERT(ifindex > 0);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_ac.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_DELETE_IFACE, 0);
	nla_put_u32(msg, NLSMARTCAPWAP_ATTR_IFPHY_INDEX, (uint32_t)ifindex);

	/* */
	result = ac_kmod_send_and_recv_msg(msg, NULL, NULL);
	if (result && (result != ENOENT)) {
		log_printf(LOG_ERR, "Unable to delete interface: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int ac_kmod_authorize_station(struct capwap_sessionid_element* sessionid, const uint8_t* macaddress, int ifindex, uint8_t radioid, uint8_t wlanid, uint16_t vlan) {
	int result;
	struct nl_msg* msg;

	ASSERT(sessionid != NULL);
	ASSERT(macaddress != NULL);
	ASSERT(ifindex >= 0);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(vlan < VLAN_MAX);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_ac.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_AUTH_STATION, 0);
	nla_put(msg, NLSMARTCAPWAP_ATTR_SESSION_ID, sizeof(struct capwap_sessionid_element), sessionid);
	nla_put(msg, NLSMARTCAPWAP_ATTR_MACADDRESS, MACADDRESS_EUI48_LENGTH, macaddress);
	nla_put_u32(msg, NLSMARTCAPWAP_ATTR_IFPHY_INDEX, (unsigned long)ifindex);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_RADIOID, radioid);
	nla_put_u8(msg, NLSMARTCAPWAP_ATTR_WLANID, wlanid);

	if (vlan > 0) {
		nla_put_u16(msg, NLSMARTCAPWAP_ATTR_VLAN, ifindex);
	}

	/* */
	result = ac_kmod_send_and_recv_msg(msg, NULL, NULL);
	if (result) {
		log_printf(LOG_ERR, "Unable to authorize station: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int ac_kmod_deauthorize_station(struct capwap_sessionid_element* sessionid, const uint8_t* macaddress) {
	int result;
	struct nl_msg* msg;

	ASSERT(sessionid != NULL);
	ASSERT(macaddress != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_ac.kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_DEAUTH_STATION, 0);
	nla_put(msg, NLSMARTCAPWAP_ATTR_SESSION_ID, sizeof(struct capwap_sessionid_element), sessionid);
	nla_put(msg, NLSMARTCAPWAP_ATTR_MACADDRESS, MACADDRESS_EUI48_LENGTH, macaddress);

	/* */
	result = ac_kmod_send_and_recv_msg(msg, NULL, NULL);
	if (result) {
		log_printf(LOG_ERR, "Unable to deauthorize station: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int ac_kmod_init(void) {
	int result;

	/* */
	capwap_lock_init(&g_ac.kmodhandle.msglock);

	/* Configure netlink callback */
	g_ac.kmodhandle.nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!g_ac.kmodhandle.nl_cb) {
		ac_kmod_free();
		return -1;
	}

	/* Create netlink socket */
	g_ac.kmodhandle.nl = nl_create_handle(g_ac.kmodhandle.nl_cb);
	if (!g_ac.kmodhandle.nl) {
		ac_kmod_free();
		return -1;
	}

	g_ac.kmodhandle.nl_fd = nl_socket_get_fd(g_ac.kmodhandle.nl);

	/* Get nlsmartcapwap netlink family */
	g_ac.kmodhandle.nlsmartcapwap_id = genl_ctrl_resolve(g_ac.kmodhandle.nl, NLSMARTCAPWAP_GENL_NAME);
	if (g_ac.kmodhandle.nlsmartcapwap_id < 0) {
		log_printf(LOG_WARNING, "Unable to found kernel module");
		ac_kmod_free();
		return -1;
	}

	/* Configure callback function */
	nl_cb_set(g_ac.kmodhandle.nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, ac_kmod_no_seq_check, NULL);
	nl_cb_set(g_ac.kmodhandle.nl_cb, NL_CB_VALID, NL_CB_CUSTOM, ac_kmod_valid_handler, NULL);

	/* Link to kernel module */
	result = ac_kmod_link();
	if (result) {
		ac_kmod_free();
		return result;
	}

	/* Configure netlink message socket */
	g_ac.kmodhandle.nlmsg_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!g_ac.kmodhandle.nlmsg_cb) {
		ac_kmod_free();
		return -1;
	}

	/* */
	g_ac.kmodhandle.nlmsg = nl_create_handle(g_ac.kmodhandle.nlmsg_cb);
	if (!g_ac.kmodhandle.nlmsg) {
		ac_kmod_free();
		return -1;
	}

	return 0;
}

/* */
void ac_kmod_free(void) {
	if (g_ac.kmodhandle.nl) {
		nl_socket_free(g_ac.kmodhandle.nl);
	}

	if (g_ac.kmodhandle.nl_cb) {
		nl_cb_put(g_ac.kmodhandle.nl_cb);
	}

	if (g_ac.kmodhandle.nlmsg) {
		nl_socket_free(g_ac.kmodhandle.nlmsg);
	}

	if (g_ac.kmodhandle.nlmsg_cb) {
		nl_cb_put(g_ac.kmodhandle.nlmsg_cb);
	}

	/* */
	capwap_lock_destroy(&g_ac.kmodhandle.msglock);

	/* */
	memset(&g_ac.kmodhandle, 0, sizeof(struct ac_kmod_handle));
}
