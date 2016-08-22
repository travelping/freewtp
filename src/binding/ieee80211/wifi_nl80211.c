#include "wtp.h"
#include "array.h"
#include "list.h"
#include "element.h"
#include "element_80211_ie.h"

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include "kmod.h"

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

static const char * nl80211_command_to_string(enum nl80211_commands cmd)
{
#define C2S(x) case x: return #x;
	switch (cmd) {
	C2S(NL80211_CMD_UNSPEC)
	C2S(NL80211_CMD_GET_WIPHY)
	C2S(NL80211_CMD_SET_WIPHY)
	C2S(NL80211_CMD_NEW_WIPHY)
	C2S(NL80211_CMD_DEL_WIPHY)
	C2S(NL80211_CMD_GET_INTERFACE)
	C2S(NL80211_CMD_SET_INTERFACE)
	C2S(NL80211_CMD_NEW_INTERFACE)
	C2S(NL80211_CMD_DEL_INTERFACE)
	C2S(NL80211_CMD_GET_KEY)
	C2S(NL80211_CMD_SET_KEY)
	C2S(NL80211_CMD_NEW_KEY)
	C2S(NL80211_CMD_DEL_KEY)
	C2S(NL80211_CMD_GET_BEACON)
	C2S(NL80211_CMD_SET_BEACON)
	C2S(NL80211_CMD_START_AP)
	C2S(NL80211_CMD_STOP_AP)
	C2S(NL80211_CMD_GET_STATION)
	C2S(NL80211_CMD_SET_STATION)
	C2S(NL80211_CMD_NEW_STATION)
	C2S(NL80211_CMD_DEL_STATION)
	C2S(NL80211_CMD_GET_MPATH)
	C2S(NL80211_CMD_SET_MPATH)
	C2S(NL80211_CMD_NEW_MPATH)
	C2S(NL80211_CMD_DEL_MPATH)
	C2S(NL80211_CMD_SET_BSS)
	C2S(NL80211_CMD_SET_REG)
	C2S(NL80211_CMD_REQ_SET_REG)
	C2S(NL80211_CMD_GET_MESH_CONFIG)
	C2S(NL80211_CMD_SET_MESH_CONFIG)
	C2S(NL80211_CMD_SET_MGMT_EXTRA_IE)
	C2S(NL80211_CMD_GET_REG)
	C2S(NL80211_CMD_GET_SCAN)
	C2S(NL80211_CMD_TRIGGER_SCAN)
	C2S(NL80211_CMD_NEW_SCAN_RESULTS)
	C2S(NL80211_CMD_SCAN_ABORTED)
	C2S(NL80211_CMD_REG_CHANGE)
	C2S(NL80211_CMD_AUTHENTICATE)
	C2S(NL80211_CMD_ASSOCIATE)
	C2S(NL80211_CMD_DEAUTHENTICATE)
	C2S(NL80211_CMD_DISASSOCIATE)
	C2S(NL80211_CMD_MICHAEL_MIC_FAILURE)
	C2S(NL80211_CMD_REG_BEACON_HINT)
	C2S(NL80211_CMD_JOIN_IBSS)
	C2S(NL80211_CMD_LEAVE_IBSS)
	C2S(NL80211_CMD_TESTMODE)
	C2S(NL80211_CMD_CONNECT)
	C2S(NL80211_CMD_ROAM)
	C2S(NL80211_CMD_DISCONNECT)
	C2S(NL80211_CMD_SET_WIPHY_NETNS)
	C2S(NL80211_CMD_GET_SURVEY)
	C2S(NL80211_CMD_NEW_SURVEY_RESULTS)
	C2S(NL80211_CMD_SET_PMKSA)
	C2S(NL80211_CMD_DEL_PMKSA)
	C2S(NL80211_CMD_FLUSH_PMKSA)
	C2S(NL80211_CMD_REMAIN_ON_CHANNEL)
	C2S(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL)
	C2S(NL80211_CMD_SET_TX_BITRATE_MASK)
	C2S(NL80211_CMD_REGISTER_FRAME)
	C2S(NL80211_CMD_FRAME)
	C2S(NL80211_CMD_FRAME_TX_STATUS)
	C2S(NL80211_CMD_SET_POWER_SAVE)
	C2S(NL80211_CMD_GET_POWER_SAVE)
	C2S(NL80211_CMD_SET_CQM)
	C2S(NL80211_CMD_NOTIFY_CQM)
	C2S(NL80211_CMD_SET_CHANNEL)
	C2S(NL80211_CMD_SET_WDS_PEER)
	C2S(NL80211_CMD_FRAME_WAIT_CANCEL)
	C2S(NL80211_CMD_JOIN_MESH)
	C2S(NL80211_CMD_LEAVE_MESH)
	C2S(NL80211_CMD_UNPROT_DEAUTHENTICATE)
	C2S(NL80211_CMD_UNPROT_DISASSOCIATE)
	C2S(NL80211_CMD_NEW_PEER_CANDIDATE)
	C2S(NL80211_CMD_GET_WOWLAN)
	C2S(NL80211_CMD_SET_WOWLAN)
	C2S(NL80211_CMD_START_SCHED_SCAN)
	C2S(NL80211_CMD_STOP_SCHED_SCAN)
	C2S(NL80211_CMD_SCHED_SCAN_RESULTS)
	C2S(NL80211_CMD_SCHED_SCAN_STOPPED)
	C2S(NL80211_CMD_SET_REKEY_OFFLOAD)
	C2S(NL80211_CMD_PMKSA_CANDIDATE)
	C2S(NL80211_CMD_TDLS_OPER)
	C2S(NL80211_CMD_TDLS_MGMT)
	C2S(NL80211_CMD_UNEXPECTED_FRAME)
	C2S(NL80211_CMD_PROBE_CLIENT)
	C2S(NL80211_CMD_REGISTER_BEACONS)
	C2S(NL80211_CMD_UNEXPECTED_4ADDR_FRAME)
	C2S(NL80211_CMD_SET_NOACK_MAP)
	C2S(NL80211_CMD_CH_SWITCH_NOTIFY)
	C2S(NL80211_CMD_START_P2P_DEVICE)
	C2S(NL80211_CMD_STOP_P2P_DEVICE)
	C2S(NL80211_CMD_CONN_FAILED)
	C2S(NL80211_CMD_SET_MCAST_RATE)
	C2S(NL80211_CMD_SET_MAC_ACL)
	C2S(NL80211_CMD_RADAR_DETECT)
	C2S(NL80211_CMD_GET_PROTOCOL_FEATURES)
	C2S(NL80211_CMD_UPDATE_FT_IES)
	C2S(NL80211_CMD_FT_EVENT)
	C2S(NL80211_CMD_CRIT_PROTOCOL_START)
	C2S(NL80211_CMD_CRIT_PROTOCOL_STOP)
	/* C2S(NL80211_CMD_GET_COALESCE) */
	/* C2S(NL80211_CMD_SET_COALESCE) */
	/* C2S(NL80211_CMD_CHANNEL_SWITCH) */
	/* C2S(NL80211_CMD_VENDOR) */
	/* C2S(NL80211_CMD_SET_QOS_MAP) */
	/* C2S(NL80211_CMD_ADD_TX_TS) */
	/* C2S(NL80211_CMD_DEL_TX_TS) */
	default:
		return "NL80211_CMD_UNKNOWN";
	}
#undef C2S
}

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
static int nl80211_send_and_recv(struct nl_sock *nl,
				 struct nl_cb *nl_cb,
				 struct nl_msg *msg,
				 nl_valid_cb valid_cb,
				 void *data)
{
	struct nl_cb *cb;
	int result = -1;

	/* Clone netlink callback */
	cb = nl_cb_clone(nl_cb);
	if (!cb)
		goto out;

	/* Complete send message */
	result = nl_send_auto_complete(nl, msg);
	if (result < 0)
		goto out;

	result = 1;

	/* Customize message callback */
	nl_cb_err(cb, NL_CB_CUSTOM, nl80211_error_handler, &result);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, nl80211_finish_handler, &result);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, nl80211_ack_handler, &result);

	if (valid_cb)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_cb, data);

	while (result > 0) {
		int r = nl_recvmsgs(nl, cb);
		if (r < 0)
			log_printf(LOG_INFO, "nl80211: %s->nl_recvmsgs failed: %d", __func__, r);
	}

out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	return result;
}

/* */
static int nl80211_send_and_recv_msg(struct nl80211_global_handle* globalhandle,
				     struct nl_msg* msg,
				     nl_valid_cb valid_cb,
				     void* data)
{
	return nl80211_send_and_recv(globalhandle->nl, globalhandle->nl_cb, msg, valid_cb, data);
}

static int nl80211_wlan_send_and_recv_msg(struct wifi_wlan *wlan,
					  struct nl_msg *msg,
					  nl_valid_cb valid_cb,
					  void *data)
{
	struct nl80211_wlan_handle *wlanhandle
		= (struct nl80211_wlan_handle *)wlan->handle;

	ASSERT(wlanhandle != NULL);

	return nl80211_send_and_recv_msg(wlanhandle->devicehandle->globalhandle, msg, valid_cb, data);
}

/* */
static int cb_family_handler(struct nl_msg* msg, void* data)
{
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
static int nl80211_get_multicast_id(struct nl80211_global_handle* globalhandle,
				    const char* family, const char* group)
{
	int result;
	struct nl_msg* msg;
	struct family_data resource = { -1, group };

	ASSERT(globalhandle != NULL);
	ASSERT(family != NULL);
	ASSERT(group != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	/* */
	genlmsg_put(msg, 0, 0, genl_ctrl_resolve(globalhandle->nl, "nlctrl"), 0, 0, CTRL_CMD_GETFAMILY, 0);
	nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, family);

	/* */
	result = nl80211_send_and_recv_msg(globalhandle, msg, cb_family_handler, &resource);
	if (!result)
		result = resource.id;
	else
		log_printf(LOG_ERR, "Unable get multicast id, error code: %d", result);

	return result;
}

static void *nl80211_command(struct nl80211_global_handle *globalhandle,
			     struct nl_msg *msg, int flags, uint8_t cmd)
{
	return genlmsg_put(msg, 0, 0, globalhandle->nl80211_id,
			   0, flags, cmd, 0);
}

static struct nl_msg *nl80211_ifindex_msg(struct nl80211_global_handle *globalhandle,
					  int ifindex, int flags, uint8_t cmd)
{
        struct nl_msg *msg;

        msg = nlmsg_alloc();
        if (!msg)
                return NULL;

        if (!nl80211_command(globalhandle, msg, flags, cmd) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex)) {
                nlmsg_free(msg);
                return NULL;
        }

        return msg;
}

static struct nl_msg *nl80211_wlan_msg(struct wifi_wlan *wlan, int flags, uint8_t cmd)
{
	struct nl80211_wlan_handle *wlanhandle
		= (struct nl80211_wlan_handle*)wlan->handle;;

	return nl80211_ifindex_msg(wlanhandle->devicehandle->globalhandle,
				   wlan->virtindex, flags, cmd);
}

/* */
static int nl80211_wlan_set_type(struct wifi_wlan* wlan, uint32_t type) {
	int result;
	struct nl_msg* msg;

	/* */
	msg = nl80211_wlan_msg(wlan, 0, NL80211_CMD_SET_INTERFACE);
	if (!msg ||
	    nla_put_u32(msg, NL80211_ATTR_IFTYPE, type)) {
		nlmsg_free(msg);
		return -1;
	}

	/* */


	/* */
	result = nl80211_wlan_send_and_recv_msg(wlan, msg, NULL, NULL);
	if (result)
		log_printf(LOG_ERR, "Unable set type, error code: %d", result);

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

	/* */
	msg = nl80211_wlan_msg(wlan, 0, NL80211_CMD_GET_INTERFACE);
	if (!msg)
		return NL80211_IFTYPE_UNSPECIFIED;

	/* */
	result = nl80211_wlan_send_and_recv_msg(wlan, msg, cb_get_type, &type);
	if (result) {
		log_printf(LOG_ERR, "Unable get type, error code: %d", result);
		type = NL80211_IFTYPE_UNSPECIFIED;
	}

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
	struct nl80211_device_handle* devicehandle
		= (struct nl80211_device_handle*)device->handle;
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
	if (!wlan)
		return -1;

	/* Set frequecy using device index of first BSS */
	msg = nl80211_ifindex_msg(devicehandle->globalhandle,
				  wlan->virtindex, 0, NL80211_CMD_SET_WIPHY);
	if (!msg ||
	    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq->frequency)) {
		nlmsg_free(msg);
		return -1;
	}

	/* Set wifi frequency */
	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg, NULL, NULL);
	if (!result)
		log_printf(LOG_INFO, "Change %s frequency %d", wlan->virtname, (int)freq->frequency);
	else
		log_printf(LOG_ERR, "Unable set frequency %d, error code: %d", (int)freq->frequency, result);

	return result;
}

/* */
static void nl80211_wlan_client_probe_event(struct wifi_wlan* wlan,
					   struct nlattr** tb_msg)
{
        if (!tb_msg[NL80211_ATTR_MAC] || !tb_msg[NL80211_ATTR_ACK])
                return;

	wifi_wlan_client_probe_event(wlan, nla_data(tb_msg[NL80211_ATTR_MAC]));
}

/* */
static int nl80211_wlan_event(struct wifi_wlan* wlan,
			      struct genlmsghdr* gnlh,
			      struct nlattr** tb_msg)
{
	switch (gnlh->cmd) {
	case NL80211_CMD_FRAME: {
		uint32_t frequency = 0;
		int8_t rssi = 0;

		if (!tb_msg[NL80211_ATTR_FRAME])
			break;

		if (tb_msg[NL80211_ATTR_WIPHY_FREQ])
			frequency = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]);
		if (tb_msg[NL80211_ATTR_RX_SIGNAL_DBM])
			rssi = (uint8_t)nla_get_u32(tb_msg[NL80211_ATTR_RX_SIGNAL_DBM]);

		/* */
		wifi_wlan_receive_station_frame(
			wlan,
			(struct ieee80211_header*)nla_data(tb_msg[NL80211_ATTR_FRAME]),
			nla_len(tb_msg[NL80211_ATTR_FRAME]), frequency, rssi, 0, 0);
		break;
	}

	case NL80211_CMD_FRAME_TX_STATUS: {
		struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;
		uint64_t cookie;

		if (!tb_msg[NL80211_ATTR_FRAME] ||
		    !tb_msg[NL80211_ATTR_COOKIE])
			break;

		cookie = nla_get_u64(tb_msg[NL80211_ATTR_COOKIE]);

		if (wlanhandle->last_cookie == cookie) {
			wlanhandle->last_cookie = 0;
			wifi_wlan_receive_station_ackframe(
				wlan,
				(struct ieee80211_header*)nla_data(tb_msg[NL80211_ATTR_FRAME]),
				nla_len(tb_msg[NL80211_ATTR_FRAME]),
				(tb_msg[NL80211_ATTR_ACK] ? 1 : 0));
		}

		break;
	}

	case NL80211_CMD_TRIGGER_SCAN:
	case NL80211_CMD_NEW_SCAN_RESULTS:
	case NL80211_CMD_NEW_STATION:
	case NL80211_CMD_DEL_STATION:
		break;

        case NL80211_CMD_PROBE_CLIENT:
                nl80211_wlan_client_probe_event(wlan, tb_msg);
                break;

	default:
		log_printf(LOG_DEBUG, "*** nl80211_wlan_event: %s (%d)",
			   nl80211_command_to_string((int)gnlh->cmd), (int)gnlh->cmd);
		break;
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
static int nl80211_wlan_registerframe(struct wifi_wlan* wlan, uint16_t type,
				      const uint8_t* match, int lengthmatch)
{
	struct nl_msg* msg;
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;

	/* */
	msg = nl80211_wlan_msg(wlan, 0, NL80211_CMD_REGISTER_FRAME);
	if (!msg ||
	    nla_put_u16(msg, NL80211_ATTR_FRAME_TYPE, type) ||
	    nla_put(msg, NL80211_ATTR_FRAME_MATCH, lengthmatch, match)) {
		nlmsg_free(msg);
		return -1;
	}

	/* Destroy virtual device */
	return nl80211_send_and_recv(wlanhandle->nl, wlanhandle->nl_cb, msg, NULL, NULL);
}

/* */
static int nl80211_global_destroy_virtdevice(struct nl80211_global_handle* globalhandle, uint32_t virtindex) {
	int result;
	struct nl_msg* msg;

	ASSERT(globalhandle != NULL);

	/* */
	msg = nl80211_ifindex_msg(globalhandle, virtindex, 0, NL80211_CMD_DEL_INTERFACE);
	if (!msg)
		return -1;

	/* Destroy virtual device */
	result = nl80211_send_and_recv_msg(globalhandle, msg, NULL, NULL);
	if (result)
		log_printf(LOG_ERR, "Unable destroy interface, error code: %d", result);

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
	if (!msg ||
	    !nl80211_command(globalhandle, msg, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE) ||
	    nla_put_u32(msg, NL80211_ATTR_WIPHY, phyindex)) {
		nlmsg_free(msg);
		return;
	}

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
					log_printf(LOG_ERR, "Unable to destroy virtual device, error code: %d", result);
				}
			}
		}
	} else {
		/* Error get virtual devices */
		log_printf(LOG_ERR, "Unable retrieve virtual device info, error code: %d", result);
	}

	capwap_list_free(list);
}

/* */
static wifi_wlan_handle nl80211_wlan_create(struct wifi_device* device, struct wifi_wlan* wlan) {
	int result;
	struct nl_msg* msg;
	struct nl80211_wlan_handle* wlanhandle;
	struct nl80211_device_handle* devicehandle
		= (struct nl80211_device_handle*)device->handle;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);
	ASSERT(wlan != NULL);

	if (!wlan->device->capability->supp_cmds.poll_command_supported) {
		log_printf(LOG_CRIT, "unable to run nl80211 WTP on device %s without "
			   "probe_client command support", wlan->device->phyname);
                return NULL;
        }

	/* */
	msg = nlmsg_alloc();
	if (!msg ||
	    /* Create wlan interface */
	    !nl80211_command(devicehandle->globalhandle, msg, 0, NL80211_CMD_NEW_INTERFACE) ||
	    nla_put_u32(msg, NL80211_ATTR_WIPHY, device->phyindex) ||
#if defined(NL80211_ATTR_IFACE_SOCKET_OWNER)
	    nla_put_flag(msg, NL80211_ATTR_IFACE_SOCKET_OWNER) ||
#endif
	    nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION) ||
	    nla_put_string(msg, NL80211_ATTR_IFNAME, wlan->virtname)) {
		nlmsg_free(msg);
		return NULL;
	}

	/* */
	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg, NULL, NULL);

	/* Check interface */
	if (result || !wifi_iface_index(wlan->virtname)) {
		log_printf(LOG_ERR, "Unable create interface %s, error code: %d", wlan->virtname, result);
		return NULL;
	}

	/* Init wlan */
	wlanhandle = (struct nl80211_wlan_handle*)capwap_alloc(sizeof(struct nl80211_wlan_handle));
	memset(wlanhandle, 0, sizeof(struct nl80211_wlan_handle));

	wlanhandle->devicehandle = devicehandle;

	return (wifi_wlan_handle)wlanhandle;
}

/* */
static void nl80211_global_event_receive_cb(EV_P_ ev_io *w, int revents)
{
	struct nl80211_global_handle *globalhandle = (struct nl80211_global_handle *)
		(((char *)w) - offsetof(struct nl80211_global_handle, nl_event_ev));
	int res;

	log_printf(LOG_WARNING, "nl80211_global_event_receive_cb on fd %d", w->fd);
	/* */
	res = nl_recvmsgs(globalhandle->nl_event, globalhandle->nl_cb);
	if (res) {
		log_printf(LOG_WARNING, "Receive nl80211 message failed: %d", res);
	}
}

static void nl80211_wlan_event_receive_cb(EV_P_ ev_io *w, int revents)
{
	struct nl80211_wlan_handle *wlanhandle = (struct nl80211_wlan_handle *)
		(((char *)w) - offsetof(struct nl80211_wlan_handle, nl_ev));
	int res;

	log_printf(LOG_WARNING, "nl80211_wlan_event_receive_cb on fd %d", w->fd);
	/* */
	res = nl_recvmsgs(wlanhandle->nl, wlanhandle->nl_cb);
	if (res) {
		log_printf(LOG_WARNING, "Receive nl80211 message failed: %d", res);
	}
}

/* */
static int nl80211_wlan_setbeacon(struct wifi_wlan* wlan) {
	int result;
	struct nl_msg* msg;
        uint8_t cmd = NL80211_CMD_START_AP;
	struct ieee80211_beacon_params params;
	uint8_t buffer[IEEE80211_MTU];
        int beacon_set;

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

	msg = nl80211_wlan_msg(wlan, 0, cmd);
	if (!msg ||
	    nla_put(msg, NL80211_ATTR_BEACON_HEAD, params.headbeaconlength, params.headbeacon) ||
	    nla_put(msg, NL80211_ATTR_BEACON_TAIL, params.tailbeaconlength, params.tailbeacon) ||
	    nla_put_u32(msg, NL80211_ATTR_BEACON_INTERVAL, wlan->device->beaconperiod) ||
	    nla_put_u32(msg, NL80211_ATTR_DTIM_PERIOD, wlan->device->dtimperiod) ||
	    nla_put(msg, NL80211_ATTR_SSID, strlen(wlan->ssid), wlan->ssid))
	    goto out_err;

	if ((wlan->device->capability->capability & WIFI_CAPABILITY_FLAGS_PROBE_RESPONSE_OFFLOAD) &&
	    (params.proberesponseoffloadlength > 0)) {
		log_hexdump(LOG_DEBUG, "nl80211: proberesp (offload)",
			    params.proberesponseoffload, params.proberesponseoffloadlength);
		if (nla_put(msg, NL80211_ATTR_PROBE_RESP,
			    params.proberesponseoffloadlength,
			    params.proberesponseoffload))
		    goto out_err;
	}

	if (!wlan->ssid_hidden) {
		log_printf(LOG_DEBUG, "nl80211: hidden SSID not in use");
		if (nla_put_u32(msg, NL80211_ATTR_HIDDEN_SSID, NL80211_HIDDEN_SSID_NOT_IN_USE))
			goto out_err;
	} else {
                log_printf(LOG_DEBUG, "nl80211: hidden SSID zero len");
		if (nla_put_u32(msg, NL80211_ATTR_HIDDEN_SSID, NL80211_HIDDEN_SSID_ZERO_LEN))
			goto out_err;
	}

	if (nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE,
			((wlan->authmode == CAPWAP_ADD_WLAN_AUTHTYPE_WEP) ?
			 NL80211_AUTHTYPE_SHARED_KEY : NL80211_AUTHTYPE_OPEN_SYSTEM)) ||
	    nla_put_flag(msg, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT))
			goto out_err;

	/* privacy */
	if (wlan->rsne)
		log_printf(LOG_DEBUG, "RSNE capability: %04x", wlan->capability);

	if (wlan->rsne &&
	    wlan->capability & IEEE80211_CAPABILITY_PRIVACY) {
		uint8_t *data = (uint8_t *)(wlan->rsne + 1);
		uint16_t suites_num;
		uint32_t *suites;
		int i;

		data += 2;

		nla_put_flag(msg, NL80211_ATTR_PRIVACY);
		nla_put_u32(msg, NL80211_ATTR_WPA_VERSIONS, NL80211_WPA_VERSION_2);
		log_printf(LOG_ERR, "nl80211: Cipher Suite Group: %08x", ntohl(*(uint32_t *)data));
		/* find a better place for the cipher suite assignment */
		wlan->group_cipher_suite = ntohl(*(uint32_t *)data);
		nla_put_u32(msg, NL80211_ATTR_CIPHER_SUITE_GROUP, ntohl(*(uint32_t *)data));
		data += sizeof(uint32_t);

		suites_num = *(uint16_t *)data;
		data += 2;
		suites = alloca(suites_num * sizeof(uint32_t));

		for (i = 0; i < suites_num; i++) {
			suites[i] = ntohl(*(uint32_t *)data);
			log_printf(LOG_ERR, "nl80211: Cipher Suite Pairwise[%d]: %08x", i, suites[i]);
			data +=sizeof(uint32_t);
		}
		nla_put(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE, suites_num * sizeof(uint32_t), suites);

		suites_num = *(uint16_t *)data;
		data += 2;
		suites = alloca(suites_num * sizeof(uint32_t));

		for (i = 0; i < suites_num; i++) {
			suites[i] = ntohl(*(uint32_t *)data);
			log_printf(LOG_ERR, "nl80211: AKM Suite[%d]: %08x", i, suites[i]);
			data +=sizeof(uint32_t);
		}
		nla_put(msg, NL80211_ATTR_AKM_SUITES, suites_num * sizeof(uint32_t), suites);
	}

	/* Start AP */
	result = nl80211_wlan_send_and_recv_msg(wlan, msg, NULL, NULL);
	if (result)
		log_printf(LOG_ERR, "Unable set beacon, error code: %d", result);

	/* Configure AP */
	if (!result) {
		msg = nl80211_wlan_msg(wlan, 0, NL80211_CMD_SET_BSS);
		if (!msg ||
		    nla_put_u8(msg, NL80211_ATTR_BSS_CTS_PROT,
			       ((params.erpinfo & IEEE80211_ERP_INFO_USE_PROTECTION) ? 1 : 0)) ||
		    nla_put_u8(msg, NL80211_ATTR_BSS_SHORT_PREAMBLE,
			       ((!wlan->device->stationsnoshortpreamblecount && wlan->device->shortpreamble) ? 1 : 0)))
			goto out_err;

		//nla_put_u8(msg, NL80211_ATTR_AP_ISOLATE, ???);

		if (wlan->device->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G)
			if (nla_put_u8(msg, NL80211_ATTR_BSS_SHORT_SLOT_TIME,
				       (!wlan->device->stationsnoshortslottimecount ? 1 : 0)))
				goto out_err;

		if (wlan->device->basicratescount > 0)
			if (nla_put(msg, NL80211_ATTR_BSS_BASIC_RATES,
				    wlan->device->basicratescount,
				    wlan->device->basicrates))
				goto out_err;

		if (wlan->ht_opmode >= 0) {
			log_printf(LOG_DEBUG, "nl80211: h_opmode=%04x", wlan->ht_opmode);
			if (nla_put_u16(msg, NL80211_ATTR_BSS_HT_OPMODE, wlan->ht_opmode))
				goto out_err;
		}

		/* */
		result = nl80211_wlan_send_and_recv_msg(wlan, msg, NULL, NULL);
		if (!result)
			wlan->flags |= WIFI_WLAN_SET_BEACON;
		else
			log_printf(LOG_ERR, "Unable set BSS, error code: %d", result);
	}

	return result;

out_err:
	nlmsg_free(msg);
	return -1;
}

static inline int is_broadcast_ether_addr(const uint8_t *a)
{
        return (a[0] & a[1] & a[2] & a[3] & a[4] & a[5]) == 0xff;
}

#define broadcast_ether_addr (const uint8_t *) "\xff\xff\xff\xff\xff\xff"

static int nl80211_set_key(struct wifi_wlan* wlan,
			   uint32_t alg, const uint8_t *addr,
			   int key_idx, int set_tx,
			   const uint8_t *seq, size_t seq_len,
			   const uint8_t *key, size_t key_len)
{
        struct nl_msg *msg;
        int ret;

        log_printf(LOG_DEBUG, "%s: ifindex=%d alg=%08x addr=%p key_idx=%d "
                   "set_tx=%d seq_len=%lu key_len=%lu",
                   __func__, wlan->virtindex, alg, addr, key_idx, set_tx,
                   (unsigned long) seq_len, (unsigned long) key_len);

        if (alg == 0) {
		msg = nl80211_wlan_msg(wlan, 0, NL80211_CMD_DEL_KEY);
                if (!msg)
                        return -ENOBUFS;
        } else {
		msg = nl80211_wlan_msg(wlan, 0, NL80211_CMD_NEW_KEY);
                if (!msg ||
                    nla_put(msg, NL80211_ATTR_KEY_DATA, key_len, key) ||
                    nla_put_u32(msg, NL80211_ATTR_KEY_CIPHER, alg))
                        goto fail;
                log_hexdump(LOG_DEBUG, "nl80211: KEY_DATA", key, key_len);
        }

        if (seq && seq_len) {
                if (nla_put(msg, NL80211_ATTR_KEY_SEQ, seq_len, seq))
                        goto fail;
                log_hexdump(LOG_DEBUG, "nl80211: KEY_SEQ", seq, seq_len);
        }

        if (addr && !is_broadcast_ether_addr(addr)) {
                log_printf(LOG_DEBUG, "   addr=" MACSTR, MAC2STR(addr));
                if (nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr))
                        goto fail;

                if (key_idx && !set_tx) {
                        log_printf(LOG_DEBUG, "   RSN IBSS RX GTK");
                        if (nla_put_u32(msg, NL80211_ATTR_KEY_TYPE,
                                        NL80211_KEYTYPE_GROUP))
                                goto fail;
                }
        } else if (addr && is_broadcast_ether_addr(addr)) {
                struct nlattr *types;

                log_printf(LOG_DEBUG, "   broadcast key");

                types = nla_nest_start(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
                if (!types ||
                    nla_put_flag(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST))
                        goto fail;
                nla_nest_end(msg, types);
        }
        if (nla_put_u8(msg, NL80211_ATTR_KEY_IDX, key_idx))
                goto fail;

        ret = nl80211_wlan_send_and_recv_msg(wlan, msg, NULL, NULL);
        if ((ret == -ENOENT || ret == -ENOLINK) && alg == 0)
                ret = 0;
        if (ret)
                log_printf(LOG_DEBUG, "nl80211: set_key failed; err=%d %s)",
                           ret, strerror(-ret));

        /*
         * If we failed or don't need to set the default TX key (below),
         * we're done here.
         */
        if (ret || !set_tx || alg == 0)
                return ret;

        if (addr && is_broadcast_ether_addr(addr)) {
                struct nlattr *types;

		msg = nl80211_wlan_msg(wlan, 0, NL80211_CMD_SET_KEY);
		if (!msg ||
		    nla_put_u8(msg, NL80211_ATTR_KEY_IDX, key_idx) ||
		    nla_put_flag(msg, (alg == IEEE80211_CIPHER_SUITE_AES_CMAC ||
				       alg == IEEE80211_CIPHER_SUITE_BIP_GMAC_128 ||
				       alg == IEEE80211_CIPHER_SUITE_BIP_GMAC_256 ||
				       alg == IEEE80211_CIPHER_SUITE_BIP_CMAC_256) ?
				 NL80211_ATTR_KEY_DEFAULT_MGMT :
				 NL80211_ATTR_KEY_DEFAULT))
			goto fail;

                types = nla_nest_start(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
                if (!types ||
                    nla_put_flag(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST))
                        goto fail;
                nla_nest_end(msg, types);

		ret = nl80211_wlan_send_and_recv_msg(wlan, msg, NULL, NULL);
		if (ret == -ENOENT)
			ret = 0;
		if (ret)
			log_printf(LOG_DEBUG, "nl80211: set_key default failed; "
				   "err=%d %s)", ret, strerror(-ret));
	}

        return ret;

fail:
        nlmsg_free(msg);
        return -ENOBUFS;
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
	if (!wlanhandle->nl)
		return -1;

	/* Register frames */
	for (i = 0; i < sizeof(g_stypes) / sizeof(g_stypes[0]); i++) {
		result = nl80211_wlan_registerframe(wlan, (IEEE80211_FRAMECONTROL_TYPE_MGMT << 2) | (g_stypes[i] << 4), NULL, 0);
		if (result) {
			log_printf(LOG_ERR, "Unable to register frame %d, error code: %d", g_stypes[i], result);
			return -1;
		}
	}

	/* */
	if (wlan->tunnelmode != CAPWAP_ADD_WLAN_TUNNELMODE_LOCAL) {
		/* Join interface in kernel module */
		uint32_t flags = ((wlan->tunnelmode == CAPWAP_ADD_WLAN_TUNNELMODE_80211) ? WTP_KMOD_FLAGS_TUNNEL_NATIVE : WTP_KMOD_FLAGS_TUNNEL_8023);

		if (!wtp_kmod_join_mac80211_device(wlan, flags)) {
			log_printf(LOG_INFO, "Joined the interface %d in kernel mode ", wlan->virtindex);
		} else {
			log_printf(LOG_ERR, "Unable to join the interface %d in kernel mode ", wlan->virtindex);
			return -1;
		}
	}

	/* Enable interface */
	wlan->flags |= WIFI_WLAN_RUNNING;

	/* hook into I/O loop */
	ev_io_init(&wlanhandle->nl_ev, nl80211_wlan_event_receive_cb,
		   nl_socket_get_fd(wlanhandle->nl), EV_READ);
	ev_io_start(EV_DEFAULT_UC_ &wlanhandle->nl_ev);

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

	if (wlan->keylength && wlan->key)
		nl80211_set_key(wlan, wlan->group_cipher_suite, broadcast_ether_addr,
				wlan->keyindex, 1, NULL, 0, wlan->key, wlan->keylength);

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
		msg = nl80211_wlan_msg(wlan, 0, NL80211_CMD_STOP_AP);
		if (msg)
			/* Stop AP */
			nl80211_wlan_send_and_recv_msg(wlan, msg, NULL, NULL);
	}

	/* Disable interface */
	wifi_iface_down(wlanhandle->devicehandle->globalhandle->sock_util, wlan->virtname);

	/* Configure interface with station profile */
	nl80211_wlan_set_profile(wlan, NL80211_IFTYPE_STATION);

	/* */
	if (ev_is_active(&wlanhandle->nl_ev))
		ev_io_stop(EV_DEFAULT_UC_ &wlanhandle->nl_ev);

	if (wlanhandle->nl) {
		nl_socket_free(wlanhandle->nl);
		wlanhandle->nl = NULL;
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
static int
nl80211_wlan_sendframe(struct wifi_wlan* wlan,
		       uint8_t* frame, int length,
		       uint32_t frequency, uint32_t duration,
		       int offchannel_tx_ok, int no_cck_rate,
		       int no_wait_ack)
{
	int result;
	uint64_t cookie;
	struct nl_msg* msg;
	struct nl80211_wlan_handle* wlanhandle
		= (struct nl80211_wlan_handle*)wlan->handle;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);
	ASSERT(frame != NULL);
	ASSERT(length > 0);

	log_printf(LOG_DEBUG, "nl80211: CMD_FRAME frequency=%u duration=%u no_cck=%d "
		   "no_ack=%d offchanok=%d",
		   frequency, duration, no_cck_rate, no_wait_ack, offchannel_tx_ok);
	log_hexdump(LOG_DEBUG, "CMD_FRAME", frame, length);

	/* */
	msg = nl80211_wlan_msg(wlan, 0, NL80211_CMD_FRAME);
	if (!msg)
		goto out_err;

	if (frequency)
		if (nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, frequency))
			goto out_err;
	if (duration)
		if (nla_put_u32(msg, NL80211_ATTR_DURATION, duration))
			goto out_err;
	if (offchannel_tx_ok &&
	    (wlan->device->capability->capability & WIFI_CAPABILITY_FLAGS_OFFCHANNEL_TX_OK))
		if (nla_put_flag(msg, NL80211_ATTR_OFFCHANNEL_TX_OK))
			goto out_err;
	if (no_cck_rate)
		if (nla_put_flag(msg, NL80211_ATTR_TX_NO_CCK_RATE))
			goto out_err;
	if (no_wait_ack)
		if (nla_put_flag(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK))
			goto out_err;
	if (nla_put(msg, NL80211_ATTR_FRAME, length, frame))
		goto out_err;

	/* Send frame */
	cookie = 0;
	result = nl80211_wlan_send_and_recv_msg(wlan, msg, cb_wlan_send_frame, &cookie);
	if (result)
                log_printf(LOG_DEBUG, "nl80211: Frame command failed: ret=%d "
                           "(%s) (frequency=%u duration=%u)", result, strerror(-result),
                           frequency, duration);

	wlanhandle->last_cookie = (result || no_wait_ack ? 0 : cookie);
	return result;

out_err:
	nlmsg_free(msg);
	return -1;
}

#if 0
/* Sending non-Mgmt Frames via nl80211_wlan_sendframe does not work,
   disable this till the WTP kernel mode supports frame injection from userspace */


/* Send data frame to poll STA and check whether this frame is ACKed */
static void nl80211_wlan_send_null_frame(struct wifi_wlan* wlan, const uint8_t* address, int qos)
{
        struct {
                struct ieee80211_header hdr;
                uint16_t qos_ctl;
        } STRUCT_PACKED nulldata;
        size_t size;

        memset(&nulldata, 0, sizeof(nulldata));

        if (qos) {
                nulldata.hdr.framecontrol =
			IEEE80211_FRAME_CONTROL(IEEE80211_FRAMECONTROL_TYPE_DATA,
						IEEE80211_FRAMECONTROL_DATA_SUBTYPE_QOSNULL);
                size = sizeof(nulldata);
        } else {
                nulldata.hdr.framecontrol =
			IEEE80211_FRAME_CONTROL(IEEE80211_FRAMECONTROL_TYPE_DATA,
						IEEE80211_FRAMECONTROL_DATA_SUBTYPE_NULL);
                size = sizeof(struct ieee80211_header);
        }

        nulldata.hdr.framecontrol |= __cpu_to_le16(IEEE80211_FRAME_CONTROL_MASK_FROMDS);
        memcpy(nulldata.hdr.address1, address, ETH_ALEN);
        memcpy(nulldata.hdr.address2, wlan->address, ETH_ALEN);
        memcpy(nulldata.hdr.address3, wlan->address, ETH_ALEN);

        if (nl80211_wlan_sendframe(wlan, (uint8_t *)&nulldata, size,
				   wlan->device->currentfrequency.frequency,
				   0, 0, 0, 0))
                log_printf(LOG_DEBUG, "nl80211_send_null_frame: Failed to send poll frame");
}
#endif

/* */
static void nl80211_wlan_poll_station(struct wifi_wlan* wlan, const uint8_t* address, int qos)
{
	int result;
	struct nl_msg* msg;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);
	ASSERT(address != NULL);

#if 0	/* see nl80211_wlan_send_null_frame for explanation */
        if (!wlan->device->capability->supp_cmds.poll_command_supported) {
                nl80211_wlan_send_null_frame(wlan, address, qos);
                return;
        }
#endif

	/* */
	msg = nl80211_wlan_msg(wlan, 0, NL80211_CMD_PROBE_CLIENT);
	if (!msg ||
	    nla_put(msg, NL80211_ATTR_MAC, MACADDRESS_EUI48_LENGTH, address)) {
		nlmsg_free(msg);
		return;
	}

	/* */
	result = nl80211_wlan_send_and_recv_msg(wlan, msg, NULL, NULL);
	if (result < 0)
                log_printf(LOG_DEBUG, "nl80211: Client probe request for "
                           MACSTR " failed: ret=%d (%s)",
                           MAC2STR(address), result, strerror(-result));
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

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);
	ASSERT(station != NULL);
	ASSERT(wlan == station->wlan);

        log_printf(LOG_DEBUG, "nl80211: Add STA " MACSTR, MAC2STR(station->address));
	log_hexdump(LOG_DEBUG, "  * supported rates",
		    station->supportedrates, station->supportedratescount);
	log_printf(LOG_DEBUG, "  * aid=%u", station->aid);
	log_printf(LOG_DEBUG, "  * listen_interval=%u", station->listeninterval);
	log_printf(LOG_DEBUG, "  * capability=0x%x", station->capability);

	msg = nl80211_wlan_msg(wlan, 0, NL80211_CMD_NEW_STATION);
	if (!msg ||
	    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, station->address) ||
	    nla_put(msg, NL80211_ATTR_STA_SUPPORTED_RATES,
		    station->supportedratescount, station->supportedrates) ||
	    nla_put_u16(msg, NL80211_ATTR_STA_AID, station->aid) ||
	    nla_put_u16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL, station->listeninterval) ||
	    nla_put_u16(msg, NL80211_ATTR_STA_CAPABILITY, station->capability))
		goto out_err;

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
		if (!wme ||
		    nla_put_u8(msg, NL80211_STA_WME_UAPSD_QUEUES,
			       station->qosinfo & WMM_QOSINFO_STA_AC_MASK) ||
		    nla_put_u8(msg, NL80211_STA_WME_MAX_SP,
			       (station->qosinfo >> WMM_QOSINFO_STA_SP_SHIFT) &
			       WMM_QOSINFO_STA_SP_MASK))
			goto out_err;
		nla_nest_end(msg, wme);
	}

	if (station->flags & WIFI_STATION_FLAGS_HT_CAP) {
		log_hexdump(LOG_DEBUG, "  * ht_capabilities",
			    (uint8_t *)&station->ht_cap, sizeof(station->ht_cap));
		if (nla_put(msg, NL80211_ATTR_HT_CAPABILITY,
			    sizeof(station->ht_cap), &station->ht_cap))
			goto out_err;
	}

	/* */
	result = nl80211_wlan_send_and_recv_msg(wlan, msg, NULL, NULL);
	switch (result) {
	case -EEXIST:
		result = 0;
		/* FALL THROUGH */

	case 0:
		log_printf(LOG_INFO, "Authorized station: " MACSTR, MAC2STR(station->address));
		break;

	default:
		log_printf(LOG_ERR, "Unable to authorized station, error code: %d", result);
		break;
	}
	return result;

out_err:
	nlmsg_free(msg);
	return -1;
}

/* */
int nl80211_station_deauthorize(struct wifi_wlan* wlan, const uint8_t* address) {
	int result;
	struct nl_msg* msg;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);
	ASSERT(address != NULL);

	/* */
	msg = nl80211_wlan_msg(wlan, 0, NL80211_CMD_DEL_STATION);
	if (!msg ||
	    nla_put(msg, NL80211_ATTR_MAC, MACADDRESS_EUI48_LENGTH, address)) {
		nlmsg_free(msg);
		return -1;
	}

	/* */
	result = nl80211_wlan_send_and_recv_msg(wlan, msg, NULL, NULL);
	switch (result) {
	case -ENOENT:
		result = 0;
		/* FALL THROUGH */

	case 0:
		log_printf(LOG_INFO, "Deauthorize station: " MACSTR, MAC2STR(address));
		break;

	default:
		log_printf(LOG_ERR, "Unable delete station, error code: %d", result);
		break;
	}
	return result;
}

static int cb_nl80211_station_data(struct nl_msg *msg, void *arg)
{
        struct nlattr *tb[NL80211_ATTR_MAX + 1];
        struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
        struct nl80211_station_data *data = arg;
        struct nlattr *stats[NL80211_STA_INFO_MAX + 1];
        static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
                [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
                [NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
                [NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
                [NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
                [NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
                [NL80211_STA_INFO_TX_FAILED] = { .type = NLA_U32 },
                [NL80211_STA_INFO_RX_BYTES64] = { .type = NLA_U64 },
                [NL80211_STA_INFO_TX_BYTES64] = { .type = NLA_U64 },
        };

        nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

        if (!tb[NL80211_ATTR_STA_INFO]) {
                log_printf(LOG_DEBUG, "sta stats missing!");
                return NL_SKIP;
        }
        if (nla_parse_nested(stats, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO], stats_policy))
                return NL_SKIP;

        if (stats[NL80211_STA_INFO_INACTIVE_TIME])
                data->inactive_msec = nla_get_u32(stats[NL80211_STA_INFO_INACTIVE_TIME]);

        /* Fetch the 32-bit counters first. */
        if (stats[NL80211_STA_INFO_RX_BYTES])
                data->rx_bytes = nla_get_u32(stats[NL80211_STA_INFO_RX_BYTES]);
        if (stats[NL80211_STA_INFO_TX_BYTES])
                data->tx_bytes = nla_get_u32(stats[NL80211_STA_INFO_TX_BYTES]);
        if (stats[NL80211_STA_INFO_RX_BYTES64] &&
            stats[NL80211_STA_INFO_TX_BYTES64]) {
                /*
                 * The driver supports 64-bit counters, so use them to override
                 * the 32-bit values.
                 */
                data->rx_bytes = nla_get_u64(stats[NL80211_STA_INFO_RX_BYTES64]);
                data->tx_bytes = nla_get_u64(stats[NL80211_STA_INFO_TX_BYTES64]);
                data->bytes_64bit = 1;
        }
        if (stats[NL80211_STA_INFO_RX_PACKETS])
                data->rx_packets = nla_get_u32(stats[NL80211_STA_INFO_RX_PACKETS]);
        if (stats[NL80211_STA_INFO_TX_PACKETS])
                data->tx_packets = nla_get_u32(stats[NL80211_STA_INFO_TX_PACKETS]);
        if (stats[NL80211_STA_INFO_TX_FAILED])
                data->tx_retry_failed = nla_get_u32(stats[NL80211_STA_INFO_TX_FAILED]);

        return NL_SKIP;
}

/* */
static int nl80211_station_data(struct wifi_wlan *wlan, const uint8_t *address,
				struct nl80211_station_data *data)
{
	struct nl_msg* msg;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);
	ASSERT(address != NULL);
	ASSERT(data != NULL);

	/* */
	msg = nl80211_wlan_msg(wlan, 0, NL80211_CMD_GET_STATION);
	if (!msg ||
	    nla_put(msg, NL80211_ATTR_MAC, MACADDRESS_EUI48_LENGTH, address)) {
		nlmsg_free(msg);
		return -1;
	}

	/* */
	return nl80211_wlan_send_and_recv_msg(wlan, msg, cb_nl80211_station_data, data);
}

/* */
static int nl80211_station_get_inact_sec(struct wifi_wlan* wlan, const uint8_t* address)
{
	int result;
	struct nl80211_station_data data;

	ASSERT(wlan != NULL);
	ASSERT(wlan->handle != NULL);
	ASSERT(address != NULL);

	result = nl80211_station_data(wlan, address, &data);
	if (!result)
		return data.inactive_msec / 1000;

	return -1;
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
	if (!msg ||
	    !nl80211_command(globalhandle, msg, NLM_F_DUMP, NL80211_CMD_GET_WIPHY)) {
		nlmsg_free(msg);
		return -1;
	}

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
		log_printf(LOG_ERR, "Unable retrieve physical device info, error code: %d", result);
	}

	/* */
	capwap_list_free(list);
	if (!devicehandle) {
		return -1;
	}

	/* Remove all virtual adapter from wifi device */
	nl80211_global_destroy_all_virtdevice(globalhandle, device->phyindex);
	return 0;
}

static void phydevice_capability_supported_iftypes(struct wifi_capability *capability,
						   struct nlattr *tb)
{
	struct nlattr *nl_mode;
	int i;

	if (tb == NULL)
		return;

	capability->flags |= WIFI_CAPABILITY_RADIOSUPPORTED;
	nla_for_each_nested(nl_mode, tb, i) {
		switch (nla_type(nl_mode)) {
		case NL80211_IFTYPE_AP:
			capability->radiosupported |= WIFI_CAPABILITY_AP_SUPPORTED;
			break;

		case NL80211_IFTYPE_AP_VLAN:
			capability->radiosupported |= WIFI_CAPABILITY_AP_VLAN_SUPPORTED;
			break;

		case NL80211_IFTYPE_ADHOC:
			capability->radiosupported |= WIFI_CAPABILITY_ADHOC_SUPPORTED;
			break;

		case NL80211_IFTYPE_WDS:
			capability->radiosupported |= WIFI_CAPABILITY_WDS_SUPPORTED;
			break;

		case NL80211_IFTYPE_MONITOR:
			capability->radiosupported |= WIFI_CAPABILITY_MONITOR_SUPPORTED;
			break;
		}
	}
}

static void phydevice_capability_feature_flags(struct wifi_capability *capability,
					       struct nlattr *tb)
{
        uint32_t flags;

	if (tb == NULL)
		return;

        flags = nla_get_u32(tb);

	log_printf(LOG_DEBUG, "nl80211: Feature Flag: %08x", flags);

        if (flags & NL80211_FEATURE_INACTIVITY_TIMER) {
		capability->flags |= WIFI_CAPABILITY_FLAGS_INACTIVITY_TIMER;
		log_printf(LOG_WARNING, "Driver supports NL80211 INACTIVITY_TIMER, but we don't");
	}
}

static void phydevice_capability_supp_cmds(struct wifi_commands_capability *cmd_cap,
					   struct nlattr *tb)
{
        int i;
        struct nlattr *nl_cmd;

	if (tb == NULL)
		return;

	nla_for_each_nested(nl_cmd, tb, i) {
                switch (nla_get_u32(nl_cmd)) {
		case NL80211_CMD_PROBE_CLIENT:
                        cmd_cap->poll_command_supported = 1;
                        break;
		}
	}
}

static void phydevice_capability_cipher_suites(struct wifi_capability *capability,
					       struct nlattr *tb)
{
	size_t size;

	if (tb == NULL)
		return;

	size = nla_len(tb);
	if (size == 0 || (size % sizeof(uint32_t)) != 0)
		return;

	capability->ciphers = capwap_clone(nla_data(tb), size);
	if (!capability->ciphers)
		return;

	capability->ciphers_count = size  / sizeof(uint32_t);
	capability->flags |= WIFI_CAPABILITY_CIPHERS;
}

static void phydevice_capability_freq(struct wifi_capability *capability,
				      struct wifi_band_capability *bandcap,
				      struct nlattr *tb_freq[])
{
	unsigned long frequency;
	unsigned long band;
	struct wifi_freq_capability *freq;

	frequency = (unsigned long)nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
	band = (IS_IEEE80211_FREQ_BG(frequency) ? WIFI_BAND_2GHZ :
		(IS_IEEE80211_FREQ_A(frequency) ? WIFI_BAND_5GHZ : WIFI_BAND_UNKNOWN));

	if (band == WIFI_BAND_UNKNOWN)
		return;

	freq = (struct wifi_freq_capability *)
		capwap_array_get_item_pointer(bandcap->freq, bandcap->freq->count);

	/* Set band */
	if (bandcap->band == WIFI_BAND_UNKNOWN) {
		bandcap->band = band;
	} else if (bandcap->band != band) {
		log_printf(LOG_WARNING, "Multiple wireless band into logical band");
	}

	/* Retrieve frequency and channel */
	freq->frequency = frequency;
	freq->channel = ieee80211_frequency_to_channel(frequency);

	if (IS_IEEE80211_FREQ_BG(frequency)) {
		capability->flags |= WIFI_CAPABILITY_RADIOTYPE;
		capability->radiotype |= (CAPWAP_RADIO_TYPE_80211B | CAPWAP_RADIO_TYPE_80211G);
	} else if (IS_IEEE80211_FREQ_A(frequency)) {
		capability->flags |= WIFI_CAPABILITY_RADIOTYPE;
		capability->radiotype |= CAPWAP_RADIO_TYPE_80211A;
	}

	/* Get max tx power */
	if (tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER])
		freq->maxtxpower = (unsigned long)nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]);

	/* Get flags */
	if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED]) {
		freq->flags |= FREQ_CAPABILITY_DISABLED;
	} else {
		if (tb_freq[NL80211_FREQUENCY_ATTR_PASSIVE_SCAN])
			freq->flags |= FREQ_CAPABILITY_PASSIVE_SCAN;

		if (tb_freq[NL80211_FREQUENCY_ATTR_NO_IBSS])
			freq->flags |= FREQ_CAPABILITY_NO_IBBS;

		if (tb_freq[NL80211_FREQUENCY_ATTR_RADAR])
			freq->flags |= FREQ_CAPABILITY_RADAR;

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

static void phydevice_capability_freqs(struct wifi_capability *capability,
				       struct wifi_band_capability *bandcap,
				       struct nlattr *tb_band)
{
	int i;
	struct nlattr *nl_freq;
	struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
	struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
		[NL80211_FREQUENCY_ATTR_FREQ] = { .type = NLA_U32 },
		[NL80211_FREQUENCY_ATTR_DISABLED] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_PASSIVE_SCAN] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_NO_IBSS] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_RADAR] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = { .type = NLA_U32 },
	};

	if (!tb_band)
		return;

	nla_for_each_nested(nl_freq, tb_band, i) {
		nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
			  nla_data(nl_freq), nla_len(nl_freq), freq_policy);

                if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
                        continue;

		phydevice_capability_freq(capability, bandcap, tb_freq);
	}
}

static void phydevice_capability_rates(struct wifi_band_capability *bandcap,
				       struct nlattr *tb)
{
	int i;
	struct nlattr *nl_rate;
	struct nlattr *tb_rate[NL80211_FREQUENCY_ATTR_MAX + 1];
	struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
		[NL80211_BITRATE_ATTR_RATE] = { .type = NLA_U32 },
		[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] = { .type = NLA_FLAG },
	};
	struct wifi_rate_capability *rate;

	if (!tb)
		return;

	nla_for_each_nested(nl_rate, tb, i) {
		nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX, nla_data(nl_rate), nla_len(nl_rate), rate_policy);

		if (!tb_rate[NL80211_BITRATE_ATTR_RATE])
			continue;

		rate = (struct wifi_rate_capability *)
			capwap_array_get_item_pointer(bandcap->rate, bandcap->rate->count);

		/* Set bitrate into multiple of 500Kbps */
		rate->bitrate = (uint8_t)(nla_get_u32(tb_rate[NL80211_BITRATE_ATTR_RATE]) / 5);

		if (tb_rate[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE])
			rate->flags |= RATE_CAPABILITY_SHORTPREAMBLE;
	}
}

static void phydevice_capability_band(struct wifi_capability *capability,
				      struct nlattr *nl_band)
{
	struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
	struct wifi_band_capability *bandcap;

	nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);

	/* Init band */
	bandcap = (struct wifi_band_capability *)
		capwap_array_get_item_pointer(capability->bands, capability->bands->count);
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
	    nla_len(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]) >= 16)
		memcpy(bandcap->mcs_set, nla_data(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]), 16);

	/* Frequency */
	phydevice_capability_freqs(capability, bandcap, tb_band[NL80211_BAND_ATTR_FREQS]);

	/* Rate */
	phydevice_capability_rates(bandcap, tb_band[NL80211_BAND_ATTR_RATES]);

}

static void phydevice_capability_bands(struct wifi_capability *capability,
				       struct nlattr *tb)
{
	int i;
	struct nlattr *nl_band;

	if (tb == NULL)
		return;

	capability->flags |= WIFI_CAPABILITY_BANDS;
	nla_for_each_nested(nl_band, tb, i)
		phydevice_capability_band(capability, nl_band);

}

/* */
static int cb_get_phydevice_capability(struct nl_msg* msg, void* data)
{
	struct nlattr* tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct wifi_capability* capability = (struct wifi_capability*)data;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb_msg[NL80211_ATTR_WIPHY] ||
	    nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]) != capability->device->phyindex)
		return NL_SKIP;

	/* Interface supported */
	phydevice_capability_supported_iftypes(capability, tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES]);

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

	if (tb_msg[NL80211_ATTR_OFFCHANNEL_TX_OK])
		capability->capability |= WIFI_CAPABILITY_FLAGS_OFFCHANNEL_TX_OK;

	if (tb_msg[NL80211_ATTR_ROAM_SUPPORT])
		capability->capability |= WIFI_CAPABILITY_FLAGS_ROAM_SUPPORT;

	if (tb_msg[NL80211_ATTR_SUPPORT_AP_UAPSD])
		capability->capability |= WIFI_CAPABILITY_FLAGS_SUPPORT_AP_UAPSD;

	if (tb_msg[NL80211_ATTR_DEVICE_AP_SME])
		capability->capability |= WIFI_CAPABILITY_FLAGS_DEVICE_AP_SME;

	if (tb_msg[NL80211_ATTR_PROBE_RESP_OFFLOAD]) {
		log_printf(LOG_DEBUG, "nl80211: Supports Probe Response offload in AP mode");
		capability->capability |= WIFI_CAPABILITY_FLAGS_PROBE_RESPONSE_OFFLOAD;
		/* TODO check offload protocol support */
	} else
		log_printf(LOG_DEBUG, "nl80211: Does not support Probe Response offload in AP mode");

	phydevice_capability_feature_flags(capability, tb_msg[NL80211_ATTR_FEATURE_FLAGS]);

	/* Commands supported */
	phydevice_capability_supp_cmds(&capability->supp_cmds, tb_msg[NL80211_ATTR_SUPPORTED_COMMANDS]);

	/* Cipher supported */
	phydevice_capability_cipher_suites(capability, tb_msg[NL80211_ATTR_CIPHER_SUITES]);

	/* TX/RX Antenna count */
	if (tb_msg[NL80211_ATTR_WIPHY_ANTENNA_TX] && tb_msg[NL80211_ATTR_WIPHY_ANTENNA_RX]) {
		capability->flags |= WIFI_CAPABILITY_ANTENNA_MASK;
		capability->txantennamask = (unsigned long)nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_ANTENNA_TX]);
		capability->rxantennamask = (unsigned long)nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_ANTENNA_RX]);
	}

	/* Band and datarate supported */
	phydevice_capability_bands(capability, tb_msg[NL80211_ATTR_WIPHY_BANDS]);

	return NL_SKIP;
}

/* */
static int nl80211_device_getcapability(struct wifi_device* device, struct wifi_capability* capability) {
	int result;
	struct nl_msg* msg;
	struct nl80211_device_handle* devicehandle
		= (struct nl80211_device_handle*)device->handle;

	ASSERT(device != NULL);
	ASSERT(device->handle != NULL);
	ASSERT(capability != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg ||
	    !nl80211_command(devicehandle->globalhandle, msg, 0, NL80211_CMD_GET_WIPHY) ||
	    nla_put_u32(msg, NL80211_ATTR_WIPHY, device->phyindex)) {
		nlmsg_free(msg);
		return -1;
	}

	/* Retrieve physical device capability */
	capability->device = device;
	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg,
					   cb_get_phydevice_capability, capability);
	if (result)
		log_printf(LOG_ERR, "Unable retrieve physical device capability, error code: %d", result);

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
				log_printf(LOG_WARNING, "Unable to update beacon on interface %d", wlan->virtindex);
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
	struct nl80211_device_handle* devicehandle
		= (struct nl80211_device_handle*)device->handle;
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

	/* Set TX Queue using device index of first BSS */
	msg = nl80211_ifindex_msg(devicehandle->globalhandle, wlan->virtindex,
				  0, NL80211_CMD_SET_WIPHY);
	if (!msg)
		return -1;

	txq = nla_nest_start(msg, NL80211_ATTR_WIPHY_TXQ_PARAMS);
	if (!txq)
		goto out_err;

	/* We are only sending parameters for a single TXQ at a time */
	params = nla_nest_start(msg, 1);
	if (!params)
		goto out_err;

	switch (queue) {
	case 0:
		if (nla_put_u8(msg, NL80211_TXQ_ATTR_QUEUE, NL80211_TXQ_Q_VO))
			goto out_err;
		break;
	case 1:
		if (nla_put_u8(msg, NL80211_TXQ_ATTR_QUEUE, NL80211_TXQ_Q_VI))
		goto out_err;
		break;
	case 2:
		if (nla_put_u8(msg, NL80211_TXQ_ATTR_QUEUE, NL80211_TXQ_Q_BE))
			goto out_err;
		break;
	case 3:
		if (nla_put_u8(msg, NL80211_TXQ_ATTR_QUEUE, NL80211_TXQ_Q_BK))
			goto out_err;
		break;
	default:
		goto out_err;
	}

	if (nla_put_u16(msg, NL80211_TXQ_ATTR_TXOP, txop) ||
	    nla_put_u16(msg, NL80211_TXQ_ATTR_CWMIN, cw_min) ||
	    nla_put_u16(msg, NL80211_TXQ_ATTR_CWMAX, cw_max) ||
	    nla_put_u8(msg, NL80211_TXQ_ATTR_AIFS, aifs))
		goto out_err;

	nla_nest_end(msg, params);

	nla_nest_end(msg, txq);

	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg, NULL, NULL);
	if (result)
		log_printf(LOG_ERR, "Unable set TX Queue, error code: %d", result);

	return result;

out_err:
	nlmsg_free(msg);
	return -1;
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
static void nl80211_device_deinit(struct wifi_device* device)
{
	struct nl80211_device_handle* devicehandle;

	ASSERT(device != NULL);

	devicehandle = (struct nl80211_device_handle*)device->handle;
	if (devicehandle) {
		capwap_free(devicehandle);
		device->handle = NULL;
	}
}

/* */
static void nl80211_global_deinit(wifi_global_handle handle)
{
	struct nl80211_global_handle* globalhandle = (struct nl80211_global_handle*)handle;

	if (!globalhandle)
		return;

	if (globalhandle->netlinkhandle)
		netlink_free(globalhandle->netlinkhandle);

	if (globalhandle->nl)
		nl_socket_free(globalhandle->nl);

	if (globalhandle->nl_event)
		nl_socket_free(globalhandle->nl_event);

	if (ev_is_active(&globalhandle->nl_event_ev))
		ev_io_stop(EV_DEFAULT_UC_ &globalhandle->nl_event_ev);

	if (globalhandle->nl_cb)
		nl_cb_put(globalhandle->nl_cb);

	if (globalhandle->sock_util >= 0)
		close(globalhandle->sock_util);

	capwap_free(globalhandle);
}

/* */
static void nl80211_global_newlink_event(wifi_global_handle handle, struct ifinfomsg* infomsg,
					 uint8_t* data, int length)
{
	struct wifi_wlan* wlan;
	struct nl80211_global_handle* globalhandle = (struct nl80211_global_handle*)handle;

	ASSERT(handle != NULL);
	ASSERT(infomsg != NULL);

	/* Search device */
	wlan = wifi_get_wlan(infomsg->ifi_index);
	if (!wlan)
		return;

	if (!(wlan->flags & WIFI_WLAN_RUNNING)) {
		if ((infomsg->ifi_flags & IFF_UP) &&
		    (wifi_iface_getstatus(globalhandle->sock_util, wlan->virtname) > 0)) {
			wifi_iface_down(globalhandle->sock_util, wlan->virtname);
		}
	} else if (wlan->flags & WIFI_WLAN_SET_BEACON) {
		if ((wlan->flags & WIFI_WLAN_OPERSTATE_RUNNING) &&
		    (infomsg->ifi_flags & IFF_LOWER_UP) &&
		    !(infomsg->ifi_flags & (IFF_RUNNING | IFF_DORMANT))) {
			struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)wlan->handle;
			netlink_set_link_status(wlanhandle->devicehandle->globalhandle->netlinkhandle,
						wlan->virtindex, -1, IF_OPER_UP);
		}
	}
}

/* */
static void nl80211_global_dellink_event(wifi_global_handle handle, struct ifinfomsg* infomsg,
					 uint8_t* data, int length)
{
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
static wifi_global_handle nl80211_global_init()
{
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
	if (!globalhandle->nl_event) {
		nl80211_global_deinit((wifi_global_handle)globalhandle);
		return NULL;
	}

	/* hook into I/O loop */
	ev_io_init(&globalhandle->nl_event_ev, nl80211_global_event_receive_cb,
		   nl_socket_get_fd(globalhandle->nl_event), EV_READ);
	ev_io_start(EV_DEFAULT_UC_ &globalhandle->nl_event_ev);

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
		log_printf(LOG_WARNING, "Unable to found mac80211 kernel module");
		nl80211_global_deinit((wifi_global_handle)globalhandle);
		return NULL;
	}

	/* Configure global callback function */
	nl_cb_set(globalhandle->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, nl80211_no_seq_check, NULL);
	nl_cb_set(globalhandle->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_global_valid_handler, NULL);

	/* Netlink lisk status */
	globalhandle->netlinkhandle = netlink_init((wifi_global_handle)globalhandle);
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

/* Driver function */
const struct wifi_driver_ops wifi_driver_nl80211_ops = {
	.name = "nl80211",
	.description = "Linux nl80211/cfg80211",
	.global_init = nl80211_global_init,
	.global_deinit = nl80211_global_deinit,

	.device_init = nl80211_device_init,
	.device_getcapability = nl80211_device_getcapability,
	.device_updatebeacons = nl80211_device_updatebeacons,
	.device_settxqueue = nl80211_device_settxqueue,
	.device_setfrequency = nl80211_device_setfrequency,
	.device_deinit = nl80211_device_deinit,

	.wlan_create = nl80211_wlan_create,
	.wlan_startap = nl80211_wlan_startap,
	.wlan_stopap = nl80211_wlan_stopap,
	.wlan_sendframe = nl80211_wlan_sendframe,
	.wlan_poll_station = nl80211_wlan_poll_station,
	.wlan_delete = nl80211_wlan_delete,
	.wlan_set_key = nl80211_set_key,

	.station_authorize = nl80211_station_authorize,
	.station_deauthorize = nl80211_station_deauthorize,
	.station_get_inact_sec = nl80211_station_get_inact_sec
};
