#include "wtp.h"
#include "capwap_array.h"
#include "capwap_list.h"
#include "capwap_element.h"
#include "capwap_element_80211_ie.h"

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include "wtp_kmod.h"

/* Local version of nl80211 with all feature to remove the problem of frag version of nl80211 */
#include "nl80211_v3_10.h"

#include "wifi_drivers.h"
#include "wifi_nl80211.h"

/* Physical device info */
struct nl80211_phydevice_item {
	uint32_t index;
	char name[IFNAMSIZ];
};

/* Virtual device info */
struct nl80211_virtdevice_item {
	uint32_t phyindex;
	uint32_t virtindex;
	char virtname[IFNAMSIZ];
};

/* */
static const int g_stypes[] = {
	IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTHENTICATION,
	IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_REQUEST,
	IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_REASSOCIATION_REQUEST,
	IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DISASSOCIATION,
	IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTHENTICATION,
	IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ACTION,
	IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_PROBE_REQUEST
};

/* */
struct family_data {
	int id;
	const char* group;
};

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
static int cb_family_handler(struct nl_msg* msg, void* data) {
	int i;
	struct nlattr* mcast_group;
	struct nlattr* tb_msg[CTRL_ATTR_MAX + 1];
	struct nlattr* tb_msg_mcast_group[CTRL_ATTR_MCAST_GRP_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct family_data* resource = (struct family_data*)data;

	nla_parse(tb_msg, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[CTRL_ATTR_MCAST_GROUPS]) {
		nla_for_each_nested(mcast_group, tb_msg[CTRL_ATTR_MCAST_GROUPS], i) {
			nla_parse(tb_msg_mcast_group, CTRL_ATTR_MCAST_GRP_MAX, nla_data(mcast_group), nla_len(mcast_group), NULL);

			if (tb_msg_mcast_group[CTRL_ATTR_MCAST_GRP_NAME] && tb_msg_mcast_group[CTRL_ATTR_MCAST_GRP_ID]) {
				if (!strncmp(nla_data(tb_msg_mcast_group[CTRL_ATTR_MCAST_GRP_NAME]), resource->group, nla_len(tb_msg_mcast_group[CTRL_ATTR_MCAST_GRP_NAME]))) {
					resource->id = nla_get_u32(tb_msg_mcast_group[CTRL_ATTR_MCAST_GRP_ID]);
					break;
				}
			}
		}
	}

	return NL_SKIP;
}

/* */
static int nl80211_get_multicast_id(struct nl80211_global_handle* globalhandle, const char* family, const char* group) {
	int result;
	struct nl_msg* msg;
	struct family_data resource = { -1, group };

	ASSERT(globalhandle != NULL);
	ASSERT(family != NULL);
	ASSERT(group != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, genl_ctrl_resolve(globalhandle->nl, "nlctrl"), 0, 0, CTRL_CMD_GETFAMILY, 0);
	nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, family);

	/* */
	result = nl80211_send_and_recv_msg(globalhandle, msg, cb_family_handler, &resource);
	if (!result) {
		result = resource.id;
	} else {
		capwap_logging_error("Unable get multicast id, error code: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static int nl80211_wlan_set_type(struct wifi_wlan* wlan, uint32_t type) {
	int result;
	struct nl_msg* msg;
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_SET_INTERFACE, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlan->virtindex);
	nla_put_u32(msg, NL80211_ATTR_IFTYPE, type);

	/* */
	result = nl80211_send_and_recv_msg(wlanhandle->devicehandle->globalhandle, msg, NULL, NULL);
	if (result) {
		capwap_logging_error("Unable set type, error code: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static int cb_get_type(struct nl_msg* msg, void* data) {
	struct nlattr* tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));
	uint32_t* type = (uint32_t*)data;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_IFTYPE]) {
		*type = nla_get_u32(tb_msg[NL80211_ATTR_IFTYPE]);
	}

	return NL_SKIP;
}

/* */
static uint32_t nl80211_wlan_get_type(struct wifi_wlan* wlan) {
	int result;
	struct nl_msg* msg;
	uint32_t type = NL80211_IFTYPE_UNSPECIFIED;
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return NL80211_IFTYPE_UNSPECIFIED;
	}

	/* */
	genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_GET_INTERFACE, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlan->virtindex);

	/* */
	result = nl80211_send_and_recv_msg(wlanhandle->devicehandle->globalhandle, msg, cb_get_type, &type);
	if (result) {
		capwap_logging_error("Unable get type, error code: %d", result);
		type = NL80211_IFTYPE_UNSPECIFIED;
	}

	/* */
	nlmsg_free(msg);
	return type;
}

/* */
static int nl80211_wlan_set_profile(struct wifi_wlan* wlan, uint32_t type) {
	int result;

	/* Change interface type */
	result = nl80211_wlan_set_type(wlan, type);
	if (result && (type == nl80211_wlan_get_type(wlan))) {
		result = 0;		/* No error */
	}

	/* */
	if (result) {
		if (result == -ENODEV) {
			return -1;
		}

		/* TODO */
	}

	return result;
}

/* */
static int nl80211_device_changefrequency(struct wifi_device* device, struct wifi_frequency* freq) {
	int result;
	struct nl_msg* msg;
	struct capwap_list_item* wlansearch;
	struct nl80211_device_handle* devicehandle;
	struct wifi_wlan* wlan = NULL;

	ASSERT(device != NULL);
	ASSERT(freq != NULL);

	/* Search a valid interface */
	for (wlansearch = device->wlans->first; wlansearch; wlansearch = wlansearch->next) {
		struct wifi_wlan* element = (struct wifi_wlan*)wlansearch->item;

		if (element->flags & WIFI_WLAN_RUNNING) {
			wlan = element;
			break;
		}
	}

	/* */
	if (!wlan) {
		return -1;
	}

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* Set frequecy using device index of first BSS */
	devicehandle = (struct nl80211_device_handle*)device->handle;
	genlmsg_put(msg, 0, 0, devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_SET_WIPHY, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlan->virtindex);
	nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq->frequency);

	/* Set wifi frequency */
	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg, NULL, NULL);
	if (!result) {
		capwap_logging_info("Change %s frequency %d", wlan->virtname, (int)freq->frequency);
	} else {
		capwap_logging_error("Unable set frequency %d, error code: %d", (int)freq->frequency, result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static int nl80211_wlan_event(struct wifi_wlan* wlan, struct genlmsghdr* gnlh, struct nlattr** tb_msg) {
	switch (gnlh->cmd) {
		case NL80211_CMD_FRAME: {
			if (tb_msg[NL80211_ATTR_FRAME]) {
				uint32_t frequency = (tb_msg[NL80211_ATTR_WIPHY_FREQ] ? nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]) : 0);
				uint8_t rssi = (tb_msg[NL80211_ATTR_RX_SIGNAL_DBM] ? (uint8_t)nla_get_u32(tb_msg[NL80211_ATTR_RX_SIGNAL_DBM]) : 0);

				/* */
				wifi_wlan_receive_station_frame(wlan, (struct ieee80211_header*)nla_data(tb_msg[NL80211_ATTR_FRAME]), nla_len(tb_msg[NL80211_ATTR_FRAME]), frequency, rssi, 0, 0);
			}

			break;
		}

		case NL80211_CMD_FRAME_TX_STATUS: {
			if (tb_msg[NL80211_ATTR_FRAME] && tb_msg[NL80211_ATTR_COOKIE]) {
				struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;
				uint64_t cookie = nla_get_u64(tb_msg[NL80211_ATTR_COOKIE]);

				if (wlanhandle->last_cookie == cookie) {
					wlanhandle->last_cookie = 0;
					wifi_wlan_receive_station_ackframe(wlan, (struct ieee80211_header*)nla_data(tb_msg[NL80211_ATTR_FRAME]), nla_len(tb_msg[NL80211_ATTR_FRAME]), (tb_msg[NL80211_ATTR_ACK] ? 1 : 0));
				}
			}

			break;
		}

		case NL80211_CMD_TRIGGER_SCAN: {
			break;
		}

		case NL80211_CMD_NEW_SCAN_RESULTS: {
			break;
		}

		case NL80211_CMD_NEW_STATION: {
			break;
		}

		case NL80211_CMD_DEL_STATION: {
			break;
		}

		default: {
			capwap_logging_debug("*** nl80211_wlan_event: %d", (int)gnlh->cmd);
			break;
		}
	}

	return NL_SKIP;
}

/* */
static int nl80211_wlan_valid_handler(struct nl_msg* msg, void* arg) {
	struct nlattr* tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	return nl80211_wlan_event((struct wifi_wlan*)arg, gnlh, tb_msg);
}

/* */
static int nl80211_wlan_registerframe(struct wifi_wlan* wlan, uint16_t type, const uint8_t* match, int lengthmatch) {
	int result;
	struct nl_msg* msg;
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_REGISTER_FRAME, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlan->virtindex);
	nla_put_u16(msg, NL80211_ATTR_FRAME_TYPE, type);
	nla_put(msg, NL80211_ATTR_FRAME_MATCH, lengthmatch, match);

	/* Destroy virtual device */
	result = nl80211_send_and_recv(wlanhandle->nl, wlanhandle->nl_cb, msg, NULL, NULL);

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static int nl80211_global_destroy_virtdevice(struct nl80211_global_handle* globalhandle, uint32_t virtindex) {
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
	if (result) {
		capwap_logging_error("Unable destroy interface, error code: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static int cb_global_destroy_all_virtdevice(struct nl_msg* msg, void* data) {
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
static void nl80211_global_destroy_all_virtdevice(struct nl80211_global_handle* globalhandle, uint32_t phyindex) {
	int result;
	struct nl_msg* msg;
	struct capwap_list* list;
	struct capwap_list_item* itemsearch;

	ASSERT(globalhandle != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return;
	}

	genlmsg_put(msg, 0, 0, globalhandle->nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, 0);
	nla_put_u32(msg, NL80211_ATTR_WIPHY, phyindex);

	/* Retrieve all virtual interface */
	list = capwap_list_create();
	result = nl80211_send_and_recv_msg(globalhandle, msg, cb_global_destroy_all_virtdevice, list);
	if (!result) {
		for (itemsearch = list->first; itemsearch; itemsearch = itemsearch->next) {
			struct nl80211_virtdevice_item* virtitem = (struct nl80211_virtdevice_item*)itemsearch->item;

			/* Destroy virtual device */
			if (virtitem->phyindex == phyindex) {
				wifi_iface_down(globalhandle->sock_util, virtitem->virtname);
				result = nl80211_global_destroy_virtdevice(globalhandle, virtitem->virtindex);
				if (result) {
					capwap_logging_error("Unable to destroy virtual device, error code: %d", result);
				}
			}
		}
	} else {
		/* Error get virtual devices */
		capwap_logging_error("Unable retrieve virtual device info, error code: %d", result);
	}

	/* */
	nlmsg_free(msg);
	capwap_list_free(list);
}

/* */
static wifi_wlan_handle nl80211_wlan_create(struct wifi_device* device, struct wifi_wlan* wlan) {
	int result;
	struct nl_msg* msg;
	struct nl80211_wlan_handle* wlanhandle;
	struct nl80211_device_handle* devicehandle;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);
	ASSERT(wlan != NULL);

	/* */
	devicehandle = (struct nl80211_device_handle*)device->handle;

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return NULL;
	}

	/* Create wlan interface */
	genlmsg_put(msg, 0, 0, devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_NEW_INTERFACE, 0);
	nla_put_u32(msg, NL80211_ATTR_WIPHY, device->phyindex);
	nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
	nla_put_string(msg, NL80211_ATTR_IFNAME, wlan->virtname);
#if defined(NL80211_ATTR_IFACE_SOCKET_OWNER)
	nla_put_flag(msg, NL80211_ATTR_IFACE_SOCKET_OWNER);
#endif

	/* */
	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg, NULL, NULL);
	nlmsg_free(msg);

	/* Check interface */
	if (result || !wifi_iface_index(wlan->virtname)) {
		capwap_logging_error("Unable create interface %s, error code: %d", wlan->virtname, result);
		return NULL;
	}

	/* Init wlan */
	wlanhandle = (struct nl80211_wlan_handle*)capwap_alloc(sizeof(struct nl80211_wlan_handle));
	memset(wlanhandle, 0, sizeof(struct nl80211_wlan_handle));

	wlanhandle->devicehandle = devicehandle;
	wlanhandle->nl_fd = -1;

	return (wifi_wlan_handle)wlanhandle;
}

/* */
static void nl80211_event_receive(int fd, void** params, int paramscount) {
	int res;

	ASSERT(fd >= 0);
	ASSERT(params != NULL);
	ASSERT(paramscount == 2); 

	/* */
	res = nl_recvmsgs((struct nl_sock*)params[0], (struct nl_cb*)params[1]);
	if (res) {
		capwap_logging_warning("Receive nl80211 message failed: %d", res);
	}
}

/* */
static int nl80211_wlan_getfdevent(struct wifi_wlan* wlan, struct pollfd* fds, struct wifi_event* events) {
	struct nl80211_wlan_handle* wlanhandle;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);

	/* */
	wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;
	if (!(wlan->flags & WIFI_WLAN_RUNNING) || (wlanhandle->nl_fd < 0)) {
		return 0;
	}

	if (fds) {
		fds[0].fd = wlanhandle->nl_fd;
		fds[0].events = POLLIN | POLLERR | POLLHUP;
	}

	if (events) {
		events[0].event_handler = nl80211_event_receive;
		events[0].params[0] = (void*)wlanhandle->nl;
		events[0].params[1] = (void*)wlanhandle->nl_cb;
		events[0].paramscount = 2;
	}

	return 1;
}

/* */
static int nl80211_wlan_setbeacon(struct wifi_wlan* wlan) {
	int result;
	struct nl_msg* msg;
        uint8_t cmd = NL80211_CMD_START_AP;
	struct nl80211_wlan_handle* wlanhandle;
	struct ieee80211_beacon_params params;
	uint8_t buffer[IEEE80211_MTU];
        int beacon_set;

	/* */
	wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;

	/* Create beacon packet */
	memset(&params, 0, sizeof(struct ieee80211_beacon_params));
	memcpy(params.bssid, wlan->address, ETH_ALEN);
	params.beaconperiod = wlan->device->beaconperiod;
	params.capability = wifi_wlan_check_capability(wlan, wlan->capability);
	params.ssid = wlan->ssid;
	params.ssid_hidden = wlan->ssid_hidden;
	memcpy(params.supportedrates, wlan->device->supportedrates, wlan->device->supportedratescount);
	params.supportedratescount = wlan->device->supportedratescount;
	params.mode = wlan->device->currentfrequency.mode;
	params.erpinfo = ieee80211_get_erpinfo(wlan->device->currentfrequency.mode, wlan->device->olbc, wlan->device->stationsnonerpcount, wlan->device->stationsnoshortpreamblecount, wlan->device->shortpreamble);
	params.channel = wlan->device->currentfrequency.channel;

	params.beacon_ies = wlan->beacon_ies;
	params.beacon_ies_len = wlan->beacon_ies_len;
	params.response_ies = wlan->response_ies;
	params.response_ies_len = wlan->response_ies_len;

	/* Enable probe response offload only in CAPWAP Local Mac */
	if ((wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL) &&
	    (wlan->device->capability->capability & WIFI_CAPABILITY_FLAGS_PROBE_RESPONSE_OFFLOAD)) {
		params.flags |= IEEE80221_CREATE_BEACON_FLAGS_PROBE_RESPONSE_OFFLOAD;
	}

	/* */
	result = ieee80211_create_beacon(buffer, sizeof(buffer), &params);
	if (result < 0) {
		return -1;
	}

	beacon_set = !!(wlan->flags & WIFI_WLAN_SET_BEACON);

	log_printf(LOG_DEBUG, "nl80211: Set beacon (beacon_set=%d)",
		   beacon_set);
        if (beacon_set)
                cmd = NL80211_CMD_SET_BEACON;

        log_hexdump(LOG_DEBUG, "nl80211: Beacon head",
                    params.headbeacon, params.headbeaconlength);
        log_hexdump(LOG_DEBUG, "nl80211: Beacon tail",
                    params.tailbeacon, params.tailbeaconlength);
        log_printf(LOG_DEBUG, "nl80211: ifindex=%d", wlan->virtindex);
        log_printf(LOG_DEBUG, "nl80211: beacon_int=%d", wlan->device->beaconperiod);
        log_printf(LOG_DEBUG, "nl80211: dtim_period=%d", wlan->device->dtimperiod);
        log_hexdump(LOG_DEBUG, "nl80211: ssid",
		    (uint8_t *)wlan->ssid, strlen(wlan->ssid));

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, cmd, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlan->virtindex);
	nla_put(msg, NL80211_ATTR_BEACON_HEAD, params.headbeaconlength, params.headbeacon);
	nla_put(msg, NL80211_ATTR_BEACON_TAIL, params.tailbeaconlength, params.tailbeacon);
	nla_put_u32(msg, NL80211_ATTR_BEACON_INTERVAL, wlan->device->beaconperiod);
	nla_put_u32(msg, NL80211_ATTR_DTIM_PERIOD, wlan->device->dtimperiod);
	nla_put(msg, NL80211_ATTR_SSID, strlen(wlan->ssid), wlan->ssid);

	if ((wlan->device->capability->capability & WIFI_CAPABILITY_FLAGS_PROBE_RESPONSE_OFFLOAD) &&
	    (params.proberesponseoffloadlength > 0)) {
		log_hexdump(LOG_DEBUG, "nl80211: proberesp (offload)",
			    params.proberesponseoffload, params.proberesponseoffloadlength);
		nla_put(msg, NL80211_ATTR_PROBE_RESP, params.proberesponseoffloadlength, params.proberesponseoffload);
	}

	if (!wlan->ssid_hidden) {
		log_printf(LOG_DEBUG, "nl80211: hidden SSID not in use");
		nla_put_u32(msg, NL80211_ATTR_HIDDEN_SSID, NL80211_HIDDEN_SSID_NOT_IN_USE);
	} else {
                log_printf(LOG_DEBUG, "nl80211: hidden SSID zero len");
		nla_put_u32(msg, NL80211_ATTR_HIDDEN_SSID, NL80211_HIDDEN_SSID_ZERO_LEN);
	}

	nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE, ((wlan->authmode == CAPWAP_ADD_WLAN_AUTHTYPE_WEP) ? NL80211_AUTHTYPE_SHARED_KEY : NL80211_AUTHTYPE_OPEN_SYSTEM));
	nla_put_flag(msg, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);

	/* Start AP */
	result = nl80211_send_and_recv_msg(wlanhandle->devicehandle->globalhandle, msg, NULL, NULL);
	if (result) {
		capwap_logging_error("Unable set beacon, error code: %d", result);
	}

	nlmsg_free(msg);

	/* Configure AP */
	if (!result) {
		msg = nlmsg_alloc();
		if (!msg) {
			return -1;
		}

		/* */
		genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_SET_BSS, 0);
		nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlan->virtindex);

		/* */
		nla_put_u8(msg, NL80211_ATTR_BSS_CTS_PROT, ((params.erpinfo & IEEE80211_ERP_INFO_USE_PROTECTION) ? 1 : 0));
		nla_put_u8(msg, NL80211_ATTR_BSS_SHORT_PREAMBLE, ((!wlan->device->stationsnoshortpreamblecount && wlan->device->shortpreamble) ? 1 : 0));
		//nla_put_u16(msg, NL80211_ATTR_BSS_HT_OPMODE, ???);
		//nla_put_u8(msg, NL80211_ATTR_AP_ISOLATE, ???);

		if (wlan->device->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G) {
			nla_put_u8(msg, NL80211_ATTR_BSS_SHORT_SLOT_TIME, (!wlan->device->stationsnoshortslottimecount ? 1 : 0));
		}

		if (wlan->device->basicratescount > 0) {
			nla_put(msg, NL80211_ATTR_BSS_BASIC_RATES, wlan->device->basicratescount, wlan->device->basicrates);
		}

		if (wlan->ht_opmode >= 0) {
			log_printf(LOG_DEBUG, "nl80211: h_opmode=%04x", wlan->ht_opmode);
			nla_put_u16(msg, NL80211_ATTR_BSS_HT_OPMODE, wlan->ht_opmode);
		}

		/* */
		result = nl80211_send_and_recv_msg(wlanhandle->devicehandle->globalhandle, msg, NULL, NULL);
		if (!result) {
			wlan->flags |= WIFI_WLAN_SET_BEACON;
		} else {
			capwap_logging_error("Unable set BSS, error code: %d", result);
		}

		nlmsg_free(msg);
	}

	return result;
}

/* */
static int nl80211_wlan_startap(struct wifi_wlan* wlan) {
	int i;
	int result;
	struct nl80211_wlan_handle* wlanhandle;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);

	/* Configure interface with AP profile */
	if (nl80211_wlan_set_profile(wlan, NL80211_IFTYPE_AP)) {
		return -1;
	}

	/* Socket management */
	wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;
	wlanhandle->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!wlanhandle->nl_cb) {
		return -1;
	}

	/* */
	nl_cb_set(wlanhandle->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, nl80211_no_seq_check, NULL);
	nl_cb_set(wlanhandle->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_wlan_valid_handler, (void*)wlan);

	wlanhandle->nl = nl_create_handle(wlanhandle->nl_cb);
	if (wlanhandle->nl) {
		wlanhandle->nl_fd = nl_socket_get_fd(wlanhandle->nl);
	} else {
		return -1;
	}

	/* Register frames */
	for (i = 0; i < sizeof(g_stypes) / sizeof(g_stypes[0]); i++) {
		result = nl80211_wlan_registerframe(wlan, (IEEE80211_FRAMECONTROL_TYPE_MGMT << 2) | (g_stypes[i] << 4), NULL, 0);
		if (result) {
			capwap_logging_error("Unable to register frame %d, error code: %d", g_stypes[i], result);
			return -1;
		}
	}

	/* */
	if (wlan->tunnelmode != CAPWAP_ADD_WLAN_TUNNELMODE_LOCAL) {
		/* Join interface in kernel module */
		uint32_t flags = ((wlan->tunnelmode == CAPWAP_ADD_WLAN_TUNNELMODE_80211) ? WTP_KMOD_FLAGS_TUNNEL_NATIVE : WTP_KMOD_FLAGS_TUNNEL_8023);

		if (!wtp_kmod_join_mac80211_device(wlan, flags)) {
			capwap_logging_info("Joined the interface %d in kernel mode ", wlan->virtindex);
		} else {
			capwap_logging_error("Unable to join the interface %d in kernel mode ", wlan->virtindex);
			return -1;
		}
	}

	/* Enable interface */
	wlan->flags |= WIFI_WLAN_RUNNING;
	if (wifi_iface_up(wlanhandle->devicehandle->globalhandle->sock_util, wlan->virtname)) {
		return -1;
	}

	/* Configure device if first BSS device */
	if (!wlan->device->wlanactive) {
		/* Set device frequency */
		nl80211_device_changefrequency(wlan->device, &wlan->device->currentfrequency);
		/* TODO Get current frequency */
	}

	/* Set beacon */
	if (nl80211_wlan_setbeacon(wlan)) {
		return -1;
	}

	/* Enable operation status */
	wlan->flags |= WIFI_WLAN_OPERSTATE_RUNNING;
	netlink_set_link_status(wlanhandle->devicehandle->globalhandle->netlinkhandle, wlan->virtindex, -1, IF_OPER_UP);

	return 0;
}

/* */
static void nl80211_wlan_stopap(struct wifi_wlan* wlan) {
	struct nl_msg* msg;
	struct nl80211_wlan_handle* wlanhandle;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);

	/* */
	wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;

	/* */
	if (wlan->tunnelmode != CAPWAP_ADD_WLAN_TUNNELMODE_LOCAL) {
		/* Leave interface from kernel module */
		wtp_kmod_leave_mac80211_device(wlan);
	}

	/* */
	if (wlan->flags & WIFI_WLAN_SET_BEACON) {
		msg = nlmsg_alloc();
		if (msg) {
			genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_STOP_AP, 0);
			nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlan->virtindex);

			/* Stop AP */
			nl80211_send_and_recv_msg(wlanhandle->devicehandle->globalhandle, msg, NULL, NULL);
			nlmsg_free(msg);
		}
	}

	/* Disable interface */
	wifi_iface_down(wlanhandle->devicehandle->globalhandle->sock_util, wlan->virtname);

	/* Configure interface with station profile */
	nl80211_wlan_set_profile(wlan, NL80211_IFTYPE_STATION);

	/* */
	if (wlanhandle->nl) {
		nl_socket_free(wlanhandle->nl);
		wlanhandle->nl = NULL;
		wlanhandle->nl_fd = -1;
	}

	if (wlanhandle->nl_cb) {
		nl_cb_put(wlanhandle->nl_cb);
		wlanhandle->nl_cb = NULL;
	}
}

/* */
static int cb_wlan_send_frame(struct nl_msg* msg, void* arg) {
	struct nlattr* tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));

	/* */
	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
	if (tb_msg[NL80211_ATTR_COOKIE]) {
		*(uint64_t*)arg = nla_get_u64(tb_msg[NL80211_ATTR_COOKIE]);
	}

	return NL_SKIP;
}

/* */
static int nl80211_wlan_sendframe(struct wifi_wlan* wlan, uint8_t* frame, int length, uint32_t frequency, uint32_t duration, int offchannel_tx_ok, int no_cck_rate, int no_wait_ack) {
	int result;
	uint64_t cookie;
	struct nl_msg* msg;
	struct nl80211_wlan_handle* wlanhandle;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);
	ASSERT(frame != NULL);
	ASSERT(length > 0);

	/* */
	wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_FRAME, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlan->virtindex);

	if (frequency) {
		nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, frequency);
	}

	if (duration) {
		nla_put_u32(msg, NL80211_ATTR_DURATION, duration);
	}

	if (offchannel_tx_ok && (wlan->device->capability->capability & WIFI_CAPABILITY_FLAGS_OFFCHANNEL_TX_OK)) {
		nla_put_flag(msg, NL80211_ATTR_OFFCHANNEL_TX_OK);
	}

	if (no_cck_rate) {
		nla_put_flag(msg, NL80211_ATTR_TX_NO_CCK_RATE);
	}

	if (no_wait_ack) {
		nla_put_flag(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK);
	}

	nla_put(msg, NL80211_ATTR_FRAME, length, frame);

	/* Send frame */
	cookie = 0;
	result = nl80211_send_and_recv_msg(wlanhandle->devicehandle->globalhandle, msg, cb_wlan_send_frame, &cookie);
	if (result) {
		capwap_logging_error("Unable send frame, error code: %d", result);
	}

	nlmsg_free(msg);

	wlanhandle->last_cookie = (result || no_wait_ack ? 0 : cookie);
	return result;
}

/* */
static void nl80211_wlan_delete(struct wifi_wlan* wlan) {
	struct nl80211_wlan_handle* wlanhandle;

	ASSERT(wlan != NULL);

	/* */
	wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;
	if (wlanhandle) {
		if (wlan->virtindex) {
			nl80211_global_destroy_virtdevice(wlanhandle->devicehandle->globalhandle, wlan->virtindex);
		}

		capwap_free(wlanhandle);
	}
}

/* */
static uint32_t nl80211_station_get_flags(struct wifi_station* station) {
	uint32_t result = 0;

	ASSERT(station != NULL);

	if (station->flags & WIFI_STATION_FLAGS_AUTHORIZED) {
		result |= 1 << NL80211_STA_FLAG_AUTHORIZED;
	}

	if (!(station->flags & WIFI_STATION_FLAGS_NO_SHORT_PREAMBLE)) {
		result |= 1 << NL80211_STA_FLAG_SHORT_PREAMBLE;
	}

	if (station->flags & WIFI_STATION_FLAGS_WMM) {
		result |= 1 << NL80211_STA_FLAG_WME;
	}

	return result;
}

/* */
int nl80211_station_authorize(struct wifi_wlan* wlan, struct wifi_station* station) {
	int result;
	struct nl_msg* msg;
	struct nl80211_sta_flag_update flagstation;
	struct nl80211_wlan_handle* wlanhandle;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);
	ASSERT(station != NULL);
	ASSERT(wlan == station->wlan);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;

        log_printf(LOG_DEBUG, "nl80211: Add STA " MACSTR, MAC2STR(station->address));
	log_hexdump(LOG_DEBUG, "  * supported rates",
		    station->supportedrates, station->supportedratescount);
	log_printf(LOG_DEBUG, "  * aid=%u", station->aid);
	log_printf(LOG_DEBUG, "  * listen_interval=%u", station->listeninterval);
	log_printf(LOG_DEBUG, "  * capability=0x%x", station->capability);

	genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_NEW_STATION, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlan->virtindex);
	nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, station->address);
	nla_put(msg, NL80211_ATTR_STA_SUPPORTED_RATES, station->supportedratescount, station->supportedrates);
	nla_put_u16(msg, NL80211_ATTR_STA_AID, station->aid);
	nla_put_u16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL, station->listeninterval);
	nla_put_u16(msg, NL80211_ATTR_STA_CAPABILITY, station->capability);

	/* */
	memset(&flagstation, 0, sizeof(struct nl80211_sta_flag_update));
	flagstation.mask = nl80211_station_get_flags(station);
	flagstation.set = flagstation.mask;
        log_printf(LOG_DEBUG, "  * flags set=0x%x mask=0x%x",
                   flagstation.set, flagstation.mask);
	nla_put(msg, NL80211_ATTR_STA_FLAGS2, sizeof(struct nl80211_sta_flag_update), &flagstation);

	if (station->flags & WIFI_STATION_FLAGS_WMM) {
		struct nlattr *wme;

		log_printf(LOG_DEBUG, "  * qosinfo=0x%x", station->qosinfo);

		wme = nla_nest_start(msg, NL80211_ATTR_STA_WME);
		nla_put_u8(msg, NL80211_STA_WME_UAPSD_QUEUES,
			   station->qosinfo & WMM_QOSINFO_STA_AC_MASK);
		nla_put_u8(msg, NL80211_STA_WME_MAX_SP,
			   (station->qosinfo >> WMM_QOSINFO_STA_SP_SHIFT) &
			   WMM_QOSINFO_STA_SP_MASK);
		nla_nest_end(msg, wme);
	}

	if (station->flags & WIFI_STATION_FLAGS_HT_CAP) {
		log_hexdump(LOG_DEBUG, "  * ht_capabilities",
			    (uint8_t *)&station->ht_cap, sizeof(station->ht_cap));
		nla_put(msg, NL80211_ATTR_HT_CAPABILITY,
			sizeof(station->ht_cap), &station->ht_cap);
	}

	/* */
	result = nl80211_send_and_recv_msg(wlanhandle->devicehandle->globalhandle, msg, NULL, NULL);
	if (result) {
		if (result == -EEXIST) {
			result = 0;
		} else {
			capwap_logging_error("Unable to authorized station, error code: %d", result);
		}
	}

	/* */
	if (!result) {
		capwap_logging_info("Authorized station: %s", station->addrtext);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int nl80211_station_deauthorize(struct wifi_wlan* wlan, const uint8_t* address) {
	int result;
	struct nl_msg* msg;
	struct nl80211_wlan_handle* wlanhandle;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);
	ASSERT(address != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;
	genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_DEL_STATION, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlan->virtindex);
	nla_put(msg, NL80211_ATTR_MAC, MACADDRESS_EUI48_LENGTH, address);

	/* */
	result = nl80211_send_and_recv_msg(wlanhandle->devicehandle->globalhandle, msg, NULL, NULL);
	if (result) {
		if (result == -ENOENT) {
			result = 0;
		} else {
			capwap_logging_error("Unable delete station, error code: %d", result);
		}
	}

	/* */
	if (!result) {
		char addrtext[CAPWAP_MACADDRESS_EUI48_BUFFER];
		capwap_logging_info("Deauthorize station: %s", capwap_printf_macaddress(addrtext, address, MACADDRESS_EUI48_LENGTH));
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static int cb_device_init(struct nl_msg* msg, void* data) {
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
int nl80211_device_init(wifi_global_handle handle, struct wifi_device* device) {
	int result;
	struct nl_msg* msg;
	struct capwap_list* list;
	struct capwap_list_item* item;
	struct nl80211_device_handle* devicehandle = NULL;
	struct nl80211_global_handle* globalhandle = (struct nl80211_global_handle*)handle;

	ASSERT(handle != NULL);
	ASSERT(device != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, globalhandle->nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_WIPHY, 0);

	/* Retrieve all physical interface */
	list = capwap_list_create();
	result = nl80211_send_and_recv_msg(globalhandle, msg, cb_device_init, list);
	if (!result) {
		for (item = list->first; item; item = item->next) {
			struct nl80211_phydevice_item* phyitem = (struct nl80211_phydevice_item*)item->item;

			if (!strcmp(phyitem->name, device->phyname)) {
				/* Create device */
				devicehandle = (struct nl80211_device_handle*)capwap_alloc(sizeof(struct nl80211_device_handle));
				memset(devicehandle, 0, sizeof(struct nl80211_device_handle));

				/* */
				devicehandle->globalhandle = globalhandle;

				/* */
				device->handle = (wifi_device_handle)devicehandle;
				device->phyindex = phyitem->index;
				break;
			}
		}
	} else {
		/* Error get physical devices */
		capwap_logging_error("Unable retrieve physical device info, error code: %d", result);
	}

	/* */
	nlmsg_free(msg);
	capwap_list_free(list);
	if (!devicehandle) {
		return -1;
	}

	/* Remove all virtual adapter from wifi device */
	nl80211_global_destroy_all_virtdevice(globalhandle, device->phyindex);
	return 0;
}

/* */
static int nl80211_device_getfdevent(struct wifi_device* device, struct pollfd* fds, struct wifi_event* events) {
	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);

	return 0;
}

/* */
static unsigned long nl80211_get_cipher(uint32_t chiper) {
	switch (chiper) {
		case 0x000fac01: {
			return CIPHER_CAPABILITY_WEP40;
		}

		case 0x000fac05: {
			return CIPHER_CAPABILITY_WEP104;
		}

		case 0x000fac02: {
			return CIPHER_CAPABILITY_TKIP;
		}

		case 0x000fac04: {
			return CIPHER_CAPABILITY_CCMP;
		}

		case 0x000fac06: {
			return CIPHER_CAPABILITY_CMAC;
		}

		case 0x000fac08: {
			return CIPHER_CAPABILITY_GCMP;
		}

		case 0x00147201: {
			return CIPHER_CAPABILITY_WPI_SMS4;
		}
	}

	return CIPHER_CAPABILITY_UNKNOWN;
}

/* */
static int cb_get_phydevice_capability(struct nl_msg* msg, void* data) {
	int i, j;
	struct nlattr* tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct wifi_capability* capability = (struct wifi_capability*)data;
	int radio80211bg = 0;
	int radio80211a = 0;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_WIPHY] && (nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]) == capability->device->phyindex)) {
		/* Interface supported */
		if (tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES]) {
			struct nlattr* nl_mode;

			capability->flags |= WIFI_CAPABILITY_RADIOSUPPORTED;
			nla_for_each_nested(nl_mode, tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES], i) {
				switch (nla_type(nl_mode)) {
					case NL80211_IFTYPE_AP: {
						capability->radiosupported |= WIFI_CAPABILITY_AP_SUPPORTED;
						break;
					}

					case NL80211_IFTYPE_AP_VLAN: {
						capability->radiosupported |= WIFI_CAPABILITY_AP_VLAN_SUPPORTED;
						break;
					}

					case NL80211_IFTYPE_ADHOC: {
						capability->radiosupported |= WIFI_CAPABILITY_ADHOC_SUPPORTED;
						break;
					}

					case NL80211_IFTYPE_WDS: {
						capability->radiosupported |= WIFI_CAPABILITY_WDS_SUPPORTED;
						break;
					}

					case NL80211_IFTYPE_MONITOR: {
						capability->radiosupported |= WIFI_CAPABILITY_MONITOR_SUPPORTED;
						break;
					}
				}
			}
		}

		/* */
		if (tb_msg[NL80211_ATTR_MAX_NUM_SCAN_SSIDS]) {
			capability->flags |= WIFI_CAPABILITY_MAX_SCAN_SSIDS;
			capability->maxscanssids = nla_get_u8(tb_msg[NL80211_ATTR_MAX_NUM_SCAN_SSIDS]);
		}

		if (tb_msg[NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS]) {
			capability->flags |= WIFI_CAPABILITY_MAX_SCHED_SCAN_SSIDS;
			capability->maxschedscanssids = nla_get_u8(tb_msg[NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS]);
		}

		if (tb_msg[NL80211_ATTR_MAX_MATCH_SETS]) {
			capability->flags |= WIFI_CAPABILITY_MAX_MATCH_SETS;
			capability->maxmatchsets = nla_get_u8(tb_msg[NL80211_ATTR_MAX_MATCH_SETS]);
		}

		if (tb_msg[NL80211_ATTR_MAC_ACL_MAX]) {
			capability->flags |= WIFI_CAPABILITY_MAX_ACL_MACADDRESS;
			capability->maxaclmacaddress = nla_get_u8(tb_msg[NL80211_ATTR_MAC_ACL_MAX]);
		}

		if (tb_msg[NL80211_ATTR_OFFCHANNEL_TX_OK]) {
			capability->capability |= WIFI_CAPABILITY_FLAGS_OFFCHANNEL_TX_OK;
		}

		if (tb_msg[NL80211_ATTR_ROAM_SUPPORT]) {
			capability->capability |= WIFI_CAPABILITY_FLAGS_ROAM_SUPPORT;
		}

		if (tb_msg[NL80211_ATTR_SUPPORT_AP_UAPSD]) {
			capability->capability |= WIFI_CAPABILITY_FLAGS_SUPPORT_AP_UAPSD;
		}

		if (tb_msg[NL80211_ATTR_DEVICE_AP_SME]) {
			capability->capability |= WIFI_CAPABILITY_FLAGS_DEVICE_AP_SME;
		}

		if (tb_msg[NL80211_ATTR_PROBE_RESP_OFFLOAD]) {
			log_printf(LOG_DEBUG, "nl80211: Supports Probe Response offload in AP mode");
			capability->capability |= WIFI_CAPABILITY_FLAGS_PROBE_RESPONSE_OFFLOAD;
			/* TODO check offload protocol support */
		} else
			log_printf(LOG_DEBUG, "nl80211: Does not support Probe Response offload in AP mode");

		/* Cipher supported */
		if (tb_msg[NL80211_ATTR_CIPHER_SUITES]) {
			int count;
			uint32_t* ciphers;
			struct wifi_cipher_capability* ciphercap;

			/* */
			count = nla_len(tb_msg[NL80211_ATTR_CIPHER_SUITES]) / sizeof(uint32_t);
			if (count > 0) {
				capability->flags |= WIFI_CAPABILITY_CIPHERS;
				ciphers = (uint32_t*)nla_data(tb_msg[NL80211_ATTR_CIPHER_SUITES]);
				for (j = 0; j < count; j++) {
					ciphercap = (struct wifi_cipher_capability*)capwap_array_get_item_pointer(capability->ciphers, capability->ciphers->count);
					ciphercap->cipher = nl80211_get_cipher(ciphers[j]);
				}
			}
		}

		/* TX/RX Antenna count */
		if (tb_msg[NL80211_ATTR_WIPHY_ANTENNA_TX] && tb_msg[NL80211_ATTR_WIPHY_ANTENNA_RX]) {
			capability->flags |= WIFI_CAPABILITY_ANTENNA_MASK;
			capability->txantennamask = (unsigned long)nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_ANTENNA_TX]);
			capability->rxantennamask = (unsigned long)nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_ANTENNA_RX]);
		}

		/* Band and datarate supported */
		if (tb_msg[NL80211_ATTR_WIPHY_BANDS]) {
			struct nlattr* nl_band;
			struct nlattr* tb_band[NL80211_BAND_ATTR_MAX + 1];

			capability->flags |= WIFI_CAPABILITY_BANDS;
			nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], i) {
				struct wifi_band_capability* bandcap;

				nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);

				/* Init band */
				bandcap = (struct wifi_band_capability*)capwap_array_get_item_pointer(capability->bands, capability->bands->count);
				bandcap->freq = capwap_array_create(sizeof(struct wifi_freq_capability), 0, 1);
				bandcap->rate = capwap_array_create(sizeof(struct wifi_rate_capability), 0, 1);

				/* Check High Throughput capability */
				if (tb_band[NL80211_BAND_ATTR_HT_CAPA]) {
					bandcap->htcapability = (unsigned long)nla_get_u16(tb_band[NL80211_BAND_ATTR_HT_CAPA]);
					capability->flags |= WIFI_CAPABILITY_RADIOTYPE;
					capability->radiotype |= CAPWAP_RADIO_TYPE_80211N;
				}

				if (tb_band[NL80211_BAND_ATTR_HT_AMPDU_FACTOR])
					bandcap->a_mpdu_params |= nla_get_u8(tb_band[NL80211_BAND_ATTR_HT_AMPDU_FACTOR]) & 0x03;

				if (tb_band[NL80211_BAND_ATTR_HT_AMPDU_DENSITY])
					bandcap->a_mpdu_params |= nla_get_u8(tb_band[NL80211_BAND_ATTR_HT_AMPDU_DENSITY]) << 2;


				if (tb_band[NL80211_BAND_ATTR_HT_MCS_SET] &&
				    nla_len(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]) >= 16) {
					memcpy(bandcap->mcs_set, nla_data(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]), 16);
				}

				/* Frequency */
				if (tb_band[NL80211_BAND_ATTR_FREQS]) {
					struct nlattr* nl_freq;
					struct nlattr* tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
					struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
						[NL80211_FREQUENCY_ATTR_FREQ] = { .type = NLA_U32 },
						[NL80211_FREQUENCY_ATTR_DISABLED] = { .type = NLA_FLAG },
						[NL80211_FREQUENCY_ATTR_PASSIVE_SCAN] = { .type = NLA_FLAG },
						[NL80211_FREQUENCY_ATTR_NO_IBSS] = { .type = NLA_FLAG },
						[NL80211_FREQUENCY_ATTR_RADAR] = { .type = NLA_FLAG },
						[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = { .type = NLA_U32 },
					};

					nla_for_each_nested(nl_freq, tb_band[NL80211_BAND_ATTR_FREQS], j) {
						nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, nla_data(nl_freq), nla_len(nl_freq), freq_policy);

						if (tb_freq[NL80211_FREQUENCY_ATTR_FREQ]) {
							unsigned long frequency = (unsigned long)nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
							unsigned long band = (IS_IEEE80211_FREQ_BG(frequency) ? WIFI_BAND_2GHZ : (IS_IEEE80211_FREQ_A(frequency) ? WIFI_BAND_5GHZ : WIFI_BAND_UNKNOWN));

							if (band != WIFI_BAND_UNKNOWN) {
								struct wifi_freq_capability* freq = (struct wifi_freq_capability*)capwap_array_get_item_pointer(bandcap->freq, bandcap->freq->count);

								/* Set band */
								if (bandcap->band == WIFI_BAND_UNKNOWN) {
									bandcap->band = band;
								} else if (bandcap->band != band) {
									capwap_logging_warning("Multiple wireless band into logical band");
								}

								/* Retrieve frequency and channel */
								freq->frequency = frequency;
								freq->channel = ieee80211_frequency_to_channel(frequency);

								if (!radio80211bg && IS_IEEE80211_FREQ_BG(frequency)) {
									radio80211bg = 1;
									capability->flags |= WIFI_CAPABILITY_RADIOTYPE;
									capability->radiotype |= (CAPWAP_RADIO_TYPE_80211B | CAPWAP_RADIO_TYPE_80211G);
								} else if (!radio80211a && IS_IEEE80211_FREQ_A(frequency)) {
									radio80211a = 1;
									capability->flags |= WIFI_CAPABILITY_RADIOTYPE;
									capability->radiotype |= CAPWAP_RADIO_TYPE_80211A;
								}

								/* Get max tx power */
								if (tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]) {
									freq->maxtxpower = (unsigned long)nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]);
								}

								/* Get flags */
								if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED]) {
									freq->flags |= FREQ_CAPABILITY_DISABLED;
								} else {
									if (tb_freq[NL80211_FREQUENCY_ATTR_PASSIVE_SCAN]) {
										freq->flags |= FREQ_CAPABILITY_PASSIVE_SCAN;
									}

									if (tb_freq[NL80211_FREQUENCY_ATTR_NO_IBSS]) {
										freq->flags |= FREQ_CAPABILITY_NO_IBBS;
									}

									if (tb_freq[NL80211_FREQUENCY_ATTR_RADAR]) {
										freq->flags |= FREQ_CAPABILITY_RADAR;
									}

									if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]) {
										freq->flags |= FREQ_CAPABILITY_DFS_STATE;
										freq->dfsstate = (unsigned long)nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]);

										if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_TIME]) {
											freq->flags |= FREQ_CAPABILITY_DFS_TIME;
											freq->dfstime = (unsigned long)nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_DFS_TIME]);
										}
									}
								}
							}
						}
					}
				}

				/* Rate */
				if (tb_band[NL80211_BAND_ATTR_RATES]) {
					struct nlattr* nl_rate;
					struct nlattr* tb_rate[NL80211_FREQUENCY_ATTR_MAX + 1];
					struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
						[NL80211_BITRATE_ATTR_RATE] = { .type = NLA_U32 },
						[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] = { .type = NLA_FLAG },
					};

					nla_for_each_nested(nl_rate, tb_band[NL80211_BAND_ATTR_RATES], j) {
						nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX, nla_data(nl_rate), nla_len(nl_rate), rate_policy);

						if (tb_rate[NL80211_BITRATE_ATTR_RATE]) {
							struct wifi_rate_capability* rate = (struct wifi_rate_capability*)capwap_array_get_item_pointer(bandcap->rate, bandcap->rate->count);

							/* Set bitrate into multiple of 500Kbps */
							rate->bitrate = (uint8_t)(nla_get_u32(tb_rate[NL80211_BITRATE_ATTR_RATE]) / 5);

							if (tb_rate[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE]) {
								rate->flags |= RATE_CAPABILITY_SHORTPREAMBLE;
							}
						}
					}
				}
			}
		}
	}

	return NL_SKIP;
}

/* */
static int nl80211_device_getcapability(struct wifi_device* device, struct wifi_capability* capability) {
	int result;
	struct nl_msg* msg;
	struct nl80211_device_handle* devicehandle;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);
	ASSERT(capability != NULL);

	/* */
	devicehandle = (struct nl80211_device_handle*)device->handle;

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	genlmsg_put(msg, 0, 0, devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_GET_WIPHY, 0);
	nla_put_u32(msg, NL80211_ATTR_WIPHY, device->phyindex);

	/* Retrieve physical device capability */
	capability->device = device;
	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg, cb_get_phydevice_capability, capability);
	if (result) {
		capwap_logging_error("Unable retrieve physical device capability, error code: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static void nl80211_device_updatebeacons(struct wifi_device* device) {
	struct wifi_wlan* wlan;
	struct capwap_list_item* wlansearch;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);

	/* Update all wlan beacon */
	for (wlansearch = device->wlans->first; wlansearch; wlansearch = wlansearch->next) {
		wlan = (struct wifi_wlan*)wlansearch->item;
		if (wlan->flags & WIFI_WLAN_SET_BEACON) {
			if (nl80211_wlan_setbeacon(wlan)) {
				capwap_logging_warning("Unable to update beacon on interface %d", wlan->virtindex);
				wifi_wlan_stopap(wlan);
			}
		}
	}
}

/* */
static int nl80211_device_settxqueue(struct wifi_device* device, int queue, int aifs,
				     int cw_min, int cw_max, int txop)
{
	int result;
	struct nl_msg* msg;
	struct capwap_list_item* wlansearch;
	struct nl80211_device_handle* devicehandle;
	struct wifi_wlan* wlan = NULL;
	struct nlattr *txq, *params;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);

	/* Search a valid interface */
	for (wlansearch = device->wlans->first; wlansearch; wlansearch = wlansearch->next) {
		struct wifi_wlan* element = (struct wifi_wlan*)wlansearch->item;

		if (element->flags & WIFI_WLAN_RUNNING) {
			wlan = element;
			break;
		}
	}
	if (!wlan)
		return -1;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	/* Set TX Queue using device index of first BSS */
	devicehandle = (struct nl80211_device_handle*)device->handle;
	genlmsg_put(msg, 0, 0, devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_SET_WIPHY, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlan->virtindex);

	txq = nla_nest_start(msg, NL80211_ATTR_WIPHY_TXQ_PARAMS);

	/* We are only sending parameters for a single TXQ at a time */
	params = nla_nest_start(msg, 1);

	switch (queue) {
	case 0:
		nla_put_u8(msg, NL80211_TXQ_ATTR_QUEUE, NL80211_TXQ_Q_VO);
		break;
	case 1:
		nla_put_u8(msg, NL80211_TXQ_ATTR_QUEUE, NL80211_TXQ_Q_VI);
		break;
	case 2:
		nla_put_u8(msg, NL80211_TXQ_ATTR_QUEUE, NL80211_TXQ_Q_BE);
		break;
	case 3:
		nla_put_u8(msg, NL80211_TXQ_ATTR_QUEUE, NL80211_TXQ_Q_BK);
		break;
	default:
		nlmsg_free(msg);
		return -1;
	}

	nla_put_u16(msg, NL80211_TXQ_ATTR_TXOP, txop);
	nla_put_u16(msg, NL80211_TXQ_ATTR_CWMIN, cw_min);
	nla_put_u16(msg, NL80211_TXQ_ATTR_CWMAX, cw_max);
	nla_put_u8(msg, NL80211_TXQ_ATTR_AIFS, aifs);
	nla_nest_end(msg, params);

	nla_nest_end(msg, txq);

	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg, NULL, NULL);
	if (result)
		capwap_logging_error("Unable set TX Queue, error code: %d", result);

	nlmsg_free(msg);
	return result;
}

/* */
static int nl80211_device_setfrequency(struct wifi_device* device) {
	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);

	/* Delay request if not found BSS interface */
	if (!device->wlanactive) {
		return 0;
	}

	return nl80211_device_changefrequency(device, &device->currentfrequency);
}

/* */
static void nl80211_device_deinit(struct wifi_device* device) {
	struct nl80211_device_handle* devicehandle;

	ASSERT(device != NULL);

	devicehandle = (struct nl80211_device_handle*)device->handle;
	if (devicehandle) {
		capwap_free(devicehandle);
		device->handle = NULL;
	}
}

/* */
static void nl80211_global_deinit(wifi_global_handle handle) {
	struct nl80211_global_handle* globalhandle = (struct nl80211_global_handle*)handle;

	if (globalhandle) {
		if (globalhandle->netlinkhandle) {
			netlink_free(globalhandle->netlinkhandle);
		}

		if (globalhandle->nl) {
			nl_socket_free(globalhandle->nl);
		}

		if (globalhandle->nl_event) {
			nl_socket_free(globalhandle->nl_event);
		}

		if (globalhandle->nl_cb) {
			nl_cb_put(globalhandle->nl_cb);
		}

		if (globalhandle->sock_util >= 0) {
			close(globalhandle->sock_util);
		}

		capwap_free(globalhandle);
	}
}

/* */
static void nl80211_global_newlink_event(wifi_global_handle handle, struct ifinfomsg* infomsg, uint8_t* data, int length) {
	struct wifi_wlan* wlan;
	struct nl80211_global_handle* globalhandle = (struct nl80211_global_handle*)handle;

	ASSERT(handle != NULL);
	ASSERT(infomsg != NULL);

	/* Search device */
	wlan = wifi_get_wlan(infomsg->ifi_index);
	if (wlan) {
		if (!(wlan->flags & WIFI_WLAN_RUNNING)) {
			if ((infomsg->ifi_flags & IFF_UP) && (wifi_iface_getstatus(globalhandle->sock_util, wlan->virtname) > 0)) {
				wifi_iface_down(globalhandle->sock_util, wlan->virtname);
			}
		} else if (wlan->flags & WIFI_WLAN_SET_BEACON) {
			if ((wlan->flags & WIFI_WLAN_OPERSTATE_RUNNING) && (infomsg->ifi_flags & IFF_LOWER_UP) && !(infomsg->ifi_flags & (IFF_RUNNING | IFF_DORMANT))) {
				struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;
				netlink_set_link_status(wlanhandle->devicehandle->globalhandle->netlinkhandle, wlan->virtindex, -1, IF_OPER_UP);
			}
		}
	}
}

/* */
static void nl80211_global_dellink_event(wifi_global_handle handle, struct ifinfomsg* infomsg, uint8_t* data, int length) {
}

/* */
static int nl80211_global_valid_handler(struct nl_msg* msg, void* data) {
	uint32_t ifindex;
	struct wifi_wlan* wlan;
	struct nlattr* tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_IFINDEX]) {
		ifindex = (int)nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]);

		/* Search interface */
		wlan = wifi_get_wlan(ifindex);
		if (wlan) {
			return nl80211_wlan_event(wlan, gnlh, tb_msg);
		}
	}

	return NL_SKIP;
}

/* */
static wifi_global_handle nl80211_global_init(void) {
	int result;
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

	/* Create netlink socket for event */
	globalhandle->nl_event = nl_create_handle(globalhandle->nl_cb);
	if (globalhandle->nl_event) {
		globalhandle->nl_event_fd = nl_socket_get_fd(globalhandle->nl_event);
	} else {
		nl80211_global_deinit((wifi_global_handle)globalhandle);
		return NULL;
	}

	/* Add membership scan events */
	result = nl80211_get_multicast_id(globalhandle, "nl80211", "scan");
	if (result >= 0) {
		result = nl_socket_add_membership(globalhandle->nl_event, result);
	}
	
	if (result < 0) {
		nl80211_global_deinit((wifi_global_handle)globalhandle);
		return NULL;
	}

	/* Add membership mlme events */
	result = nl80211_get_multicast_id(globalhandle, "nl80211", "mlme");
	if (result >= 0) {
		result = nl_socket_add_membership(globalhandle->nl_event, result);
	}
	
	if (result < 0) {
		nl80211_global_deinit((wifi_global_handle)globalhandle);
		return NULL;
	}

	/* Add membership regulatory events */
	result = nl80211_get_multicast_id(globalhandle, "nl80211", "regulatory");
	if (result >= 0) {
		nl_socket_add_membership(globalhandle->nl_event, result);
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
	nl_cb_set(globalhandle->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_global_valid_handler, NULL);

	/* Netlink lisk status */
	globalhandle->netlinkhandle = netlink_init();
	if (!globalhandle->netlinkhandle) {
		nl80211_global_deinit((wifi_global_handle)globalhandle);
		return NULL;
	}

	globalhandle->netlinkhandle->newlink_event = nl80211_global_newlink_event;
	globalhandle->netlinkhandle->dellink_event = nl80211_global_dellink_event;

	/* Socket utils */
	globalhandle->sock_util = socket(AF_PACKET, SOCK_RAW, 0);
	if (globalhandle->sock_util < 0) {
		nl80211_global_deinit((wifi_global_handle)globalhandle);
		return NULL;
	}

	return (wifi_global_handle)globalhandle;
}

/* */
static int nl80211_global_getfdevent(wifi_global_handle handle, struct pollfd* fds, struct wifi_event* events) {
	struct nl80211_global_handle* globalhandle = (struct nl80211_global_handle*)handle;

	ASSERT(handle != NULL);
	ASSERT(globalhandle->nl_event_fd >= 0);
	ASSERT(globalhandle->netlinkhandle != NULL);
	ASSERT(globalhandle->netlinkhandle->sock >= 0);

	if (fds) {
		fds[0].fd = globalhandle->nl_event_fd;
		fds[0].events = POLLIN | POLLERR | POLLHUP;
		fds[1].fd = globalhandle->netlinkhandle->sock;
		fds[1].events = POLLIN | POLLERR | POLLHUP;
	}

	if (events) {
		events[0].event_handler = nl80211_event_receive;
		events[0].params[0] = (void*)globalhandle->nl_event;
		events[0].params[1] = (void*)globalhandle->nl_cb;
		events[0].paramscount = 2;
		events[1].event_handler = netlink_event_receive;
		events[1].params[0] = (void*)globalhandle->netlinkhandle;
		events[1].params[1] = (void*)globalhandle;
		events[1].paramscount = 2;
	}

	return 2;
}

/* Driver function */
const struct wifi_driver_ops wifi_driver_nl80211_ops = {
	.name = "nl80211",
	.description = "Linux nl80211/cfg80211",
	.global_init = nl80211_global_init,
	.global_getfdevent = nl80211_global_getfdevent,
	.global_deinit = nl80211_global_deinit,

	.device_init = nl80211_device_init,
	.device_getfdevent = nl80211_device_getfdevent,
	.device_getcapability = nl80211_device_getcapability,
	.device_updatebeacons = nl80211_device_updatebeacons,
	.device_settxqueue = nl80211_device_settxqueue,
	.device_setfrequency = nl80211_device_setfrequency,
	.device_deinit = nl80211_device_deinit,

	.wlan_create = nl80211_wlan_create,
	.wlan_getfdevent = nl80211_wlan_getfdevent,
	.wlan_startap = nl80211_wlan_startap,
	.wlan_stopap = nl80211_wlan_stopap,
	.wlan_sendframe = nl80211_wlan_sendframe,
	.wlan_delete = nl80211_wlan_delete,

	.station_authorize = nl80211_station_authorize,
	.station_deauthorize = nl80211_station_deauthorize
};
