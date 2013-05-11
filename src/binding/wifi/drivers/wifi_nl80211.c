#include "wifi_drivers.h"
#include <sys/types.h>
#include <unistd.h>
#include <net/if.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>

#include "capwap_list.h"
#include "wifi_nl80211.h"

/* Compatibility functions */
#if !defined(HAVE_LIBNL20) && !defined(HAVE_LIBNL30)
static uint32_t port_bitmap[32] = { 0 };

static struct nl_sock* nl_socket_alloc_cb(void* cb) {
	int i;
	struct nl_sock* handle;
	uint32_t pid = getpid() & 0x3FFFFF;

	handle = nl_handle_alloc_cb(cb);
	for (i = 0; i < 1024; i++) {
		if (port_bitmap[i / 32] & (1 << (i % 32))) {
			continue;
		}

		port_bitmap[i / 32] |= 1 << (i % 32);
		pid += i << 22;
		break;
	}

	nl_socket_set_local_port(handle, pid);
	return handle;
}

static void nl_socket_free(struct nl_sock* handle) {
	uint32_t port = nl_socket_get_local_port(handle);

	port >>= 22;
	port_bitmap[port / 32] &= ~(1 << (port % 32));

	nl_handle_destroy(handle);
}
#endif

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
static int nl80211_no_seq_check(struct nl_msg* msg, void* arg) {
	return NL_OK;
}

/* */
static int nl80211_error_handler(struct sockaddr_nl* nla, struct nlmsgerr* err, void* arg) {
	*((int*)arg) = err->error;
	return NL_STOP;
}

/* */
static int nl80211_finish_handler(struct nl_msg* msg, void* arg) {
	*((int*)arg) = 0;
	return NL_SKIP;
}

/* */
static int nl80211_ack_handler(struct nl_msg* msg, void* arg) {
	*((int*)arg) = 0;
	return NL_STOP;
}

/* */
static int nl80211_send_and_recv(struct nl_sock* nl, struct nl_cb* nl_cb, struct nl_msg* msg, nl_valid_cb valid_cb, void* data) {
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
	nl_cb_err(cb, NL_CB_CUSTOM, nl80211_error_handler, &result);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, nl80211_finish_handler, &result);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, nl80211_ack_handler, &result);

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
static int nl80211_send_and_recv_msg(struct nl80211_global_handle* globalhandle, struct nl_msg* msg, nl_valid_cb valid_cb, void* data) {
	return nl80211_send_and_recv(globalhandle->nl, globalhandle->nl_cb, msg, valid_cb, data);
}

/* */
static int cb_get_virtdevice_list(struct nl_msg* msg, void* data) {
	struct nlattr* tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct capwap_list* list = (struct capwap_list*)data;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_WIPHY] && tb_msg[NL80211_ATTR_IFNAME] && tb_msg[NL80211_ATTR_IFINDEX]) {
		struct capwap_list_item* item = capwap_itemlist_create(sizeof(struct nl80211_virtdevice_item));
		struct nl80211_virtdevice_item* virtitem = (struct nl80211_virtdevice_item*)item->item;

		/* Add virtual device info */
		virtitem->phyindex = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
		virtitem->virtindex = nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]);
		strcpy(virtitem->virtname, nla_get_string(tb_msg[NL80211_ATTR_IFNAME]));
		capwap_itemlist_insert_after(list, NULL, item);
	}

	return NL_SKIP;
}

/* */
static int nl80211_get_virtdevice_list(struct nl80211_global_handle* globalhandle, struct capwap_list* list) {
	int result;
	struct nl_msg* msg;

	ASSERT(globalhandle != NULL);
	ASSERT(list != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	genlmsg_put(msg, 0, 0, globalhandle->nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, 0);

	/* Retrieve all virtual interface */
	result = nl80211_send_and_recv_msg(globalhandle, msg, cb_get_virtdevice_list, list);

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static int cb_get_phydevice_list(struct nl_msg* msg, void* data) {
	struct nlattr* tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct capwap_list* list = (struct capwap_list*)data;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_WIPHY_NAME] && tb_msg[NL80211_ATTR_WIPHY]) {
		struct capwap_list_item* item = capwap_itemlist_create(sizeof(struct nl80211_phydevice_item));
		struct nl80211_phydevice_item* phyitem = (struct nl80211_phydevice_item*)item->item;

		/* Add physical device info */
		phyitem->index = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
		strcpy(phyitem->name, nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]));
		capwap_itemlist_insert_after(list, NULL, item);
	}

	return NL_SKIP;
}

/* */
static int nl80211_get_phydevice_list(struct nl80211_global_handle* globalhandle, struct capwap_list* list) {
	int result;
	struct nl_msg* msg;

	ASSERT(globalhandle != NULL);
	ASSERT(list != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	genlmsg_put(msg, 0, 0, globalhandle->nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_WIPHY, 0);

	/* Retrieve all physical interface */
	result = nl80211_send_and_recv_msg(globalhandle, msg, cb_get_phydevice_list, list);

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static int cb_get_phydevice_capability(struct nl_msg* msg, void* data) {
	struct nlattr* tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nl80211_device_handle* devicehandle = (struct nl80211_device_handle*)data;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_WIPHY] && (nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]) == devicehandle->phyindex)) {
		/* Interface supported */
		if (tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES]) {
			int i;
			struct nlattr* nl_mode;

			devicehandle->physupported = 0;
			nla_for_each_nested(nl_mode, tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES], i) {
				switch (nla_type(nl_mode)) {
					case NL80211_IFTYPE_AP: {
						devicehandle->physupported |= WIFI_CAPABILITY_AP_SUPPORTED;
						break;
					}

					case NL80211_IFTYPE_AP_VLAN: {
						devicehandle->physupported |= WIFI_CAPABILITY_AP_VLAN_SUPPORTED;
						break;
					}

					case NL80211_IFTYPE_ADHOC: {
						devicehandle->physupported |= WIFI_CAPABILITY_ADHOC_SUPPORTED;
						break;
					}

					case NL80211_IFTYPE_WDS: {
						devicehandle->physupported |= WIFI_CAPABILITY_WDS_SUPPORTED;
						break;
					}

					case NL80211_IFTYPE_MONITOR: {
						devicehandle->physupported |= WIFI_CAPABILITY_MONITOR_SUPPORTED;
						break;
					}
				}
			}
		}
	}

	return NL_SKIP;
}

/* */
static int nl80211_get_phydevice_capability(struct nl80211_device_handle* devicehandle) {
	int result;
	struct nl_msg* msg;

	ASSERT(devicehandle != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	genlmsg_put(msg, 0, 0, devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_GET_WIPHY, 0);
	nla_put_u32(msg, NL80211_ATTR_WIPHY, devicehandle->phyindex);

	/* Retrieve physical device capability */
	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg, cb_get_phydevice_capability, devicehandle);

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static int nl80211_destroy_virtdevice(struct nl80211_global_handle* globalhandle, uint32_t virtindex) {
	int result;
	struct nl_msg* msg;

	ASSERT(globalhandle != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	genlmsg_put(msg, 0, 0, globalhandle->nl80211_id, 0, 0, NL80211_CMD_DEL_INTERFACE, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, virtindex);

	/* Destroy virtual device */
	result = nl80211_send_and_recv_msg(globalhandle, msg, NULL, NULL);

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static void nl80211_destroy_all_virtdevice(struct nl80211_global_handle* globalhandle, uint32_t phyindex) {
	int result;
	struct capwap_list* list;

	/* Retrieve all virtual device */
	list = capwap_list_create();
	result = nl80211_get_virtdevice_list(globalhandle, list);
	if (!result) {
		struct capwap_list_item* item = list->first;

		/* Search virtual device by physical device */
		while (item) {
			struct nl80211_virtdevice_item* virtitem = (struct nl80211_virtdevice_item*)item->item;

			/* Destroy virtual device */
			if (virtitem->phyindex == phyindex) {
				wifi_iface_updown(globalhandle->sock_util, virtitem->virtname, 0);
				result = nl80211_destroy_virtdevice(globalhandle, virtitem->virtindex);
				if (result) {
					capwap_logging_error("Unable to destroy virtual device, error code: %d", result);
				}
			}

			/* Next */
			item = item->next;
		}
	} else {
		/* Error get virtual devices */
		capwap_logging_error("Unable retrieve virtual device info, error code: %d", result);
	}

	/* */
	capwap_list_free(list);
}

/* */
static wifi_device_handle nl80211_device_init(wifi_global_handle handle, struct device_init_params* params) {
	int result;
	struct capwap_list* list;
	struct capwap_list_item* item;
	struct nl80211_device_handle* devicehandle = NULL;
	struct nl80211_global_handle* globalhandle = (struct nl80211_global_handle*)handle;

	ASSERT(params != NULL);

	if (!handle) {
		return NULL;
	}

	/* Retrieve physical device info */
	list = capwap_list_create();
	result = nl80211_get_phydevice_list(globalhandle, list);
	if (!result) {
		item = list->first;
		while (item) {
			struct nl80211_phydevice_item* phyitem = (struct nl80211_phydevice_item*)item->item;
			
			if (!strcmp(phyitem->name, params->ifname)) {
				/* Create device */
				devicehandle = (struct nl80211_device_handle*)capwap_alloc(sizeof(struct nl80211_device_handle));
				memset(devicehandle, 0, sizeof(struct nl80211_device_handle));

				/* */
				strcpy(devicehandle->phyname, phyitem->name);
				devicehandle->phyindex = phyitem->index;

				break;
			}

			/* Next */
			item = item->next;
		}
	} else {
		/* Error get physical devices */
		capwap_logging_error("Unable retrieve physical device info, error code: %d", result);
	}

	/* */
	capwap_list_free(list);
	if (!devicehandle) {
		return NULL;
	}

	/* */
	devicehandle->globalhandle = globalhandle;

	/* Remove all virtual adapter from wifi device */
	nl80211_destroy_all_virtdevice(globalhandle, devicehandle->phyindex);

	/* Retrieve wifi device capability */
	result = nl80211_get_phydevice_capability(devicehandle);
	if (result) {
		capwap_logging_error("Unable retrieve physical device capability, error code: %d", result);
	}

	/* Save device handle into global handle */
	item = capwap_itemlist_create_with_item(devicehandle, sizeof(struct nl80211_device_handle));
	item->autodelete = 0;
	capwap_itemlist_insert_after(globalhandle->devicelist, NULL, item);

	return devicehandle;
}

/* */
static void nl80211_device_deinit(wifi_device_handle handle) {
	struct nl80211_device_handle* devicehandle = (struct nl80211_device_handle*)handle;

	if (devicehandle) {
		struct capwap_list_item* search;

		/* Remove device handle from global handle*/
		search = devicehandle->globalhandle->devicelist->first;
		while (search) {
			if ((struct nl80211_device_handle*)search->item == devicehandle) {
				/* Remove all virtual adapter from wifi device */
				nl80211_destroy_all_virtdevice(devicehandle->globalhandle, devicehandle->phyindex);

				/* Remove item from list */
				capwap_itemlist_free(capwap_itemlist_remove(devicehandle->globalhandle->devicelist, search));
				break;
			}

			search = search->next;
		}

		/* */
		capwap_free(devicehandle);
	}
}

/* */
static void nl80211_global_deinit(wifi_global_handle handle) {
	struct nl80211_global_handle* globalhandle = (struct nl80211_global_handle*)handle;

	if (globalhandle) {
		if (globalhandle->nl) {
			nl_socket_free(globalhandle->nl);
		}

		if (globalhandle->nl_cb) {
			nl_cb_put(globalhandle->nl_cb);
		}

		if (globalhandle->devicelist) {
			ASSERT(globalhandle->devicelist->count == 0);
			capwap_list_free(globalhandle->devicelist);
		}

		if (globalhandle->sock_util >= 0) {
			close(globalhandle->sock_util);
		}

		capwap_free(globalhandle);
	}
}

/* */
static wifi_global_handle nl80211_global_init(void) {
	struct nl80211_global_handle* globalhandle;

	/* */
	globalhandle = (struct nl80211_global_handle*)capwap_alloc(sizeof(struct nl80211_global_handle));
	memset(globalhandle, 0, sizeof(struct nl80211_global_handle));
	globalhandle->sock_util = -1;

	/* Configure global netlink callback */
	globalhandle->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!globalhandle->nl_cb) {
		nl80211_global_deinit((wifi_global_handle)globalhandle);
		return NULL;
	}

	/* Create netlink socket */
	globalhandle->nl = nl_create_handle(globalhandle->nl_cb);
	if (!globalhandle->nl) {
		nl80211_global_deinit((wifi_global_handle)globalhandle);
		return NULL;
	}

	/* Get nl80211 netlink family */
	globalhandle->nl80211_id = genl_ctrl_resolve(globalhandle->nl, "nl80211");
	if (globalhandle->nl80211_id < 0) {
		capwap_logging_warning("Unable to found mac80211 kernel module");
		nl80211_global_deinit((wifi_global_handle)globalhandle);
		return NULL;
	}

	/* Configure global callback function */
	nl_cb_set(globalhandle->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, nl80211_no_seq_check, NULL);
	/* TODO */

	/* Device list */
	globalhandle->devicelist = capwap_list_create();

	/* Socket utils */
	globalhandle->sock_util = socket(AF_PACKET, SOCK_RAW, 0);
	if (globalhandle->sock_util < 0) {
		nl80211_global_deinit((wifi_global_handle)globalhandle);
		return NULL;
	}

	return (wifi_global_handle)globalhandle;
}

/* Driver function */
const struct wifi_driver_ops wifi_driver_nl80211_ops = {
	.name = "nl80211",
	.description = "Linux nl80211/cfg80211",
	.global_init = nl80211_global_init,
	.global_deinit = nl80211_global_deinit,
	.device_init = nl80211_device_init,
	.device_deinit = nl80211_device_deinit
};
