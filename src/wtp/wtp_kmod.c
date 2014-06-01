#include "wtp.h"
#include "wtp_kmod.h"
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include "nlsmartcapwap.h"

/* Compatibility functions */
#ifdef HAVE_LIBNL_10 
#define nl_sock nl_handle
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
struct wtp_kmod_handle {
	struct nl_sock* nl;
	struct nl_cb* nl_cb;
	int nlsmartcapwap_id;
};

/* */
typedef int (*wtp_kmod_valid_cb)(struct nl_msg* msg, void* data);

/* */
static struct wtp_kmod_handle g_kmodhandle;

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
static int wtp_kmod_valid_handler(struct nl_msg* msg, void* data) {
	struct nlattr* tb_msg[NLSMARTCAPWAP_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb_msg, NLSMARTCAPWAP_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	return NL_SKIP;
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
	return wtp_kmod_send_and_recv(g_kmodhandle.nl, g_kmodhandle.nl_cb, msg, valid_cb, data);
}

/* */
static int wtp_kmod_connect(void) {
	int result;
	struct nl_msg* msg;

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, g_kmodhandle.nlsmartcapwap_id, 0, 0, NLSMARTCAPWAP_CMD_CONNECT, 0);

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
int wtp_kmod_init(void) {
	int result;

	/* */
	memset(&g_kmodhandle, 0, sizeof(struct wtp_kmod_handle));

	/* Configure netlink callback */
	g_kmodhandle.nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!g_kmodhandle.nl_cb) {
		wtp_kmod_free();
		return -1;
	}

	/* Create netlink socket */
	g_kmodhandle.nl = nl_create_handle(g_kmodhandle.nl_cb);
	if (!g_kmodhandle.nl) {
		wtp_kmod_free();
		return -1;
	}

	/* Get nlsmartcapwap netlink family */
	g_kmodhandle.nlsmartcapwap_id = genl_ctrl_resolve(g_kmodhandle.nl, SMARTCAPWAP_GENL_NAME);
	if (g_kmodhandle.nlsmartcapwap_id < 0) {
		wtp_kmod_free();
		return -1;
	}

	/* Configure callback function */
	nl_cb_set(g_kmodhandle.nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, wtp_kmod_no_seq_check, NULL);
	nl_cb_set(g_kmodhandle.nl_cb, NL_CB_VALID, NL_CB_CUSTOM, wtp_kmod_valid_handler, NULL);

	/* Connect to kernel module */
	result = wtp_kmod_connect();
	if (result) {
		wtp_kmod_free();
		return result;
	}

	return 0;
}

/* */
void wtp_kmod_free(void) {
	if (g_kmodhandle.nl) {
		nl_socket_free(g_kmodhandle.nl);
	}

	if (g_kmodhandle.nl_cb) {
		nl_cb_put(g_kmodhandle.nl_cb);
	}
}
