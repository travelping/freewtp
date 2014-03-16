#include "capwap.h"
#include "capwap_array.h"
#include "capwap_list.h"
#include "capwap_element.h"
#include "wtp.h"
#include "wtp_radio.h"
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

/* Local version of nl80211 with all feature to remove the problem of frag version of nl80211 */
#include "nl80211_v3_10.h"

#include "wifi_drivers.h"
#include "wifi_nl80211.h"

/* */
static char g_bufferIEEE80211[4096];

/* */
static void nl80211_wlan_stopap(wifi_wlan_handle handle);

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
static int nl80211_cookie_handler(struct nl_msg* msg, void* arg) {
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
static int nl80211_wlan_set_type(struct nl80211_wlan_handle* wlanhandle, uint32_t type) {
	int result;
	struct nl_msg* msg;

	ASSERT(wlanhandle != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_SET_INTERFACE, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlanhandle->virtindex);
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
static uint32_t nl80211_wlan_get_type(struct nl80211_wlan_handle* wlanhandle) {
	int result;
	struct nl_msg* msg;
	uint32_t type = NL80211_IFTYPE_UNSPECIFIED;

	ASSERT(wlanhandle != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return NL80211_IFTYPE_UNSPECIFIED;
	}

	/* */
	genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_GET_INTERFACE, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlanhandle->virtindex);

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
static int nl80211_wlan_send_frame(wifi_wlan_handle handle, struct wlan_send_frame_params* params) {
	int result;
	uint64_t cookie;
	struct nl_msg* msg;
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)handle;

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_FRAME, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlanhandle->virtindex);

	if (params->frequency) {
		nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, params->frequency);
	}

	if (params->duration) {
		nla_put_u32(msg, NL80211_ATTR_DURATION, params->duration);
	}

	if (params->offchannel_tx_ok && (wlanhandle->devicehandle->capability->capability & WIFI_CAPABILITY_FLAGS_OFFCHANNEL_TX_OK)) {
		nla_put_flag(msg, NL80211_ATTR_OFFCHANNEL_TX_OK);
	}

	if (params->no_cck_rate) {
		nla_put_flag(msg, NL80211_ATTR_TX_NO_CCK_RATE);
	}

	if (params->no_wait_ack) {
		nla_put_flag(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK);
	}

	nla_put(msg, NL80211_ATTR_FRAME, params->length, params->packet);

	/* Send frame */
	cookie = 0;
	result = nl80211_send_and_recv_msg(wlanhandle->devicehandle->globalhandle, msg, nl80211_cookie_handler, &cookie);
	if (result) {
		capwap_logging_error("Unable send frame, error code: %d", result);
	}

	nlmsg_free(msg);

	params->cookie = (result || params->no_wait_ack ? 0 : cookie);

	return result;
}

/* */
static uint16_t nl80211_wlan_check_capability(struct nl80211_wlan_handle* wlanhandle, uint16_t capability) {
	uint16_t result = capability;

	/* Force ESS capability */
	result |= IEEE80211_CAPABILITY_ESS;

	/* Check short preamble capability */
	if (wlanhandle->devicehandle->shortpreamble && !wlanhandle->devicehandle->stationsnoshortpreamblecount) {
		result |= IEEE80211_CAPABILITY_SHORTPREAMBLE;
	} else {
		result &= ~IEEE80211_CAPABILITY_SHORTPREAMBLE;
	}

	/* Check privacy capability */
	/* TODO */

	/* Check short slot time capability */
	if ((wlanhandle->devicehandle->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G) && !wlanhandle->devicehandle->stationsnoshortslottimecount) {
		result |= IEEE80211_CAPABILITY_SHORTSLOTTIME;
	} else {
		result &= ~IEEE80211_CAPABILITY_SHORTSLOTTIME;
	}

	return capability;
}

/* */
static int nl80211_wlan_setbeacon(struct nl80211_wlan_handle* wlanhandle) {
	int result;
	struct nl_msg* msg;
	struct ieee80211_beacon_params ieee80211_params;

	/* Create beacon packet */
	memset(&ieee80211_params, 0, sizeof(struct ieee80211_beacon_params));
	memcpy(ieee80211_params.bssid, wlanhandle->address, ETH_ALEN);
	ieee80211_params.beaconperiod = wlanhandle->devicehandle->beaconperiod;
	ieee80211_params.capability = nl80211_wlan_check_capability(wlanhandle, wlanhandle->capability);
	ieee80211_params.ssid = wlanhandle->ssid;
	ieee80211_params.ssid_hidden = wlanhandle->ssid_hidden;
	memcpy(ieee80211_params.supportedrates, wlanhandle->devicehandle->supportedrates, wlanhandle->devicehandle->supportedratescount);
	ieee80211_params.supportedratescount = wlanhandle->devicehandle->supportedratescount;
	ieee80211_params.mode = wlanhandle->devicehandle->currentfrequency.mode;
	ieee80211_params.erpinfo = ieee80211_get_erpinfo(wlanhandle->devicehandle->currentfrequency.mode, wlanhandle->devicehandle->olbc, wlanhandle->devicehandle->stationsnonerpcount, wlanhandle->devicehandle->stationsnoshortpreamblecount, wlanhandle->devicehandle->shortpreamble);
	ieee80211_params.channel = wlanhandle->devicehandle->currentfrequency.channel;

	/* Enable probe response offload only in CAPWAP Local Mac */
	if ((wlanhandle->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL) && (wlanhandle->devicehandle->capability->capability & WIFI_CAPABILITY_FLAGS_PROBE_RESPONSE_OFFLOAD)) {
		ieee80211_params.flags |= IEEE80221_CREATE_BEACON_FLAGS_PROBE_RESPONSE_OFFLOAD;
	}

	/* */
	result = ieee80211_create_beacon(g_bufferIEEE80211, sizeof(g_bufferIEEE80211), &ieee80211_params);
	if (result < 0) {
		return -1;
	}

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, ((wlanhandle->flags & NL80211_WLAN_SET_BEACON) ? NL80211_CMD_SET_BEACON : NL80211_CMD_START_AP), 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlanhandle->virtindex);
	nla_put(msg, NL80211_ATTR_BEACON_HEAD, ieee80211_params.headbeaconlength, ieee80211_params.headbeacon);
	nla_put(msg, NL80211_ATTR_BEACON_TAIL, ieee80211_params.tailbeaconlength, ieee80211_params.tailbeacon);
	nla_put_u32(msg, NL80211_ATTR_BEACON_INTERVAL, wlanhandle->devicehandle->beaconperiod);
	nla_put_u32(msg, NL80211_ATTR_DTIM_PERIOD, wlanhandle->devicehandle->dtimperiod);
	nla_put(msg, NL80211_ATTR_SSID, strlen(wlanhandle->ssid), wlanhandle->ssid);
	nla_put_u32(msg, NL80211_ATTR_HIDDEN_SSID, (wlanhandle->ssid_hidden ? NL80211_HIDDEN_SSID_ZERO_LEN : NL80211_HIDDEN_SSID_NOT_IN_USE));
	nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE, wlanhandle->authenticationtype);
	nla_put_flag(msg, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);

	if ((wlanhandle->devicehandle->capability->capability & WIFI_CAPABILITY_FLAGS_PROBE_RESPONSE_OFFLOAD) && (ieee80211_params.proberesponseoffloadlength > 0)) {
		nla_put(msg, NL80211_ATTR_PROBE_RESP, ieee80211_params.proberesponseoffloadlength, ieee80211_params.proberesponseoffload);
	}

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
		nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlanhandle->virtindex);

		/* */
		nla_put_u8(msg, NL80211_ATTR_BSS_CTS_PROT, ((ieee80211_params.erpinfo & IEEE80211_ERP_INFO_USE_PROTECTION) ? 1 : 0));
		nla_put_u8(msg, NL80211_ATTR_BSS_SHORT_PREAMBLE, ((!wlanhandle->devicehandle->stationsnoshortpreamblecount && wlanhandle->devicehandle->shortpreamble) ? 1 : 0));
		//nla_put_u16(msg, NL80211_ATTR_BSS_HT_OPMODE, ???);
		//nla_put_u8(msg, NL80211_ATTR_AP_ISOLATE, ???);

		if (wlanhandle->devicehandle->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G) {
			nla_put_u8(msg, NL80211_ATTR_BSS_SHORT_SLOT_TIME, (!wlanhandle->devicehandle->stationsnoshortslottimecount ? 1 : 0));
		}

		if (wlanhandle->devicehandle->basicratescount > 0) {
			nla_put(msg, NL80211_ATTR_BSS_BASIC_RATES, wlanhandle->devicehandle->basicratescount, wlanhandle->devicehandle->basicrates);
		}

		/* */
		result = nl80211_send_and_recv_msg(wlanhandle->devicehandle->globalhandle, msg, NULL, NULL);
		if (!result) {
			wlanhandle->flags |= NL80211_WLAN_SET_BEACON;
		} else {
			capwap_logging_error("Unable set BSS, error code: %d", result);
		}

		nlmsg_free(msg);
	}

	return result;
}

/* */
static void nl80211_device_updatebeacons(struct nl80211_device_handle* devicehandle) {
	struct capwap_list_item* wlansearch;
	struct nl80211_wlan_handle* wlanhandle;

	ASSERT(devicehandle != NULL);

	/* Update all wlan beacon */
	wlansearch = devicehandle->wlanlist->first;
	while (wlansearch) {
		wlanhandle = (struct nl80211_wlan_handle*)wlansearch->item;
		if (wlanhandle->flags & NL80211_WLAN_SET_BEACON) {
			if (nl80211_wlan_setbeacon(wlanhandle)) {
				capwap_logging_warning("Unable to update beacon on interface %d", wlanhandle->virtindex);
				nl80211_wlan_stopap((wifi_wlan_handle)wlanhandle);
			}
		}

		/* */
		wlansearch = wlansearch->next;
	}
}

/* */
static void nl80211_station_clean(struct nl80211_wlan_handle* wlanhandle, struct nl80211_station* station) {
	int updatebeacons = 0;

	ASSERT(wlanhandle != NULL);
	ASSERT(station != NULL);

	if (station->aid) {
		ieee80211_aid_free(wlanhandle->aidbitfield, station->aid);
	}

	if (station->flags & NL80211_STATION_FLAGS_NON_ERP) {
		wlanhandle->devicehandle->stationsnonerpcount--;
		if (!wlanhandle->devicehandle->stationsnonerpcount) {
			updatebeacons = 1;
		}
	}

	if (station->flags & NL80211_STATION_FLAGS_NO_SHORT_SLOT_TIME) {
		wlanhandle->devicehandle->stationsnoshortslottimecount--;
		if (!wlanhandle->devicehandle->stationsnoshortslottimecount && (wlanhandle->devicehandle->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G)) {
			updatebeacons = 1;
		}
	}

	if (station->flags & NL80211_STATION_FLAGS_NO_SHORT_PREAMBLE) {
		wlanhandle->devicehandle->stationsnoshortpreamblecount--;
		if (!wlanhandle->devicehandle->stationsnoshortpreamblecount && (wlanhandle->devicehandle->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G)) {
			updatebeacons = 1;
		}
	}

	/* Reset state */
	station->flags = 0;
	station->supportedratescount = 0;

	/* Update beacons */
	if (updatebeacons) {
		nl80211_device_updatebeacons(wlanhandle->devicehandle);
	}
}

/* */
static void nl80211_station_delete(struct nl80211_wlan_handle* wlanhandle, const uint8_t* macaddress) {
	struct nl80211_station* station;

	ASSERT(wlanhandle != NULL);
	ASSERT(macaddress != NULL);

	station = (struct nl80211_station*)capwap_hash_search(wlanhandle->stations, macaddress);
	if (station) {
		nl80211_station_clean(wlanhandle, station);

		/* Free station into hash callback */
		wlanhandle->stationscount--;
		capwap_hash_delete(wlanhandle->stations, macaddress);
	}
}

/* */
static struct nl80211_station* nl80211_station_get(struct nl80211_wlan_handle* wlanhandle, const uint8_t* macaddress) {
	ASSERT(macaddress != NULL);

	return (struct nl80211_station*)capwap_hash_search(wlanhandle->stations, macaddress);
}

/* */
static struct nl80211_station* nl80211_station_create(struct nl80211_wlan_handle* wlanhandle, const uint8_t* macaddress) {
	struct nl80211_station* station;

	ASSERT(macaddress != NULL);

	/* Disconnect from another WLAN */
	/* TODO */

	/* */
	station = nl80211_station_get(wlanhandle, macaddress);
	if (station) {
		nl80211_station_clean(wlanhandle, station);			/* Reuse station */
	} else {
		/* Checks if it has reached the maximum number of stations */
		if (wlanhandle->stationscount >= wlanhandle->maxstationscount) {
			return NULL;
		}

		/* Create new station */
		station = (struct nl80211_station*)capwap_alloc(sizeof(struct nl80211_station));
		memset(station, 0, sizeof(struct nl80211_station));

		/* */
		wlanhandle->stationscount++;
		capwap_hash_add(wlanhandle->stations, macaddress, station);
	}

	return station;
}

/* */
static void nl80211_wlan_send_deauthentication(struct nl80211_wlan_handle* wlanhandle, const uint8_t* stationaddress, uint16_t reasoncode) {
	int responselength;
	struct ieee80211_deauthentication_params ieee80211_params;
	struct wlan_send_frame_params wlan_params;

	/* Create deauthentication packet */
	memset(&ieee80211_params, 0, sizeof(struct ieee80211_deauthentication_params));
	memcpy(ieee80211_params.bssid, wlanhandle->address, ETH_ALEN);
	memcpy(ieee80211_params.station, stationaddress, ETH_ALEN);
	ieee80211_params.reasoncode = reasoncode;

	responselength = ieee80211_create_deauthentication(g_bufferIEEE80211, sizeof(g_bufferIEEE80211), &ieee80211_params);
	if (responselength < 0) {
		return;
	}

	/* Send deauthentication */
	memset(&wlan_params, 0, sizeof(struct wlan_send_frame_params));
	wlan_params.packet = g_bufferIEEE80211;
	wlan_params.length = responselength;
	wlan_params.frequency = wlanhandle->devicehandle->currentfrequency.frequency;

	if (!nl80211_wlan_send_frame((wifi_wlan_handle)wlanhandle, &wlan_params)) {
		wlanhandle->last_cookie = wlan_params.cookie;
	} else {
		capwap_logging_warning("Unable to send IEEE802.11 Deuthentication");
	}
}

/* */
static void nl80211_do_mgmt_probe_request_event(struct nl80211_wlan_handle* wlanhandle, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	int ssidcheck;
	int responselength;
	struct ieee80211_ie_items ieitems;
	struct wlan_send_frame_params wlan_params;
	struct ieee80211_probe_response_params ieee80211_params;

	/* Information Elements packet length */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->proberequest));
	if (ielength < 0) {
		return;
	}

	/* Parsing Information Elements */
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->proberequest.ie[0], ielength)) {
		return;
	}

	/* Validate Probe Request Packet */
	if (!ieitems.ssid || !ieitems.supported_rates) {
		return;
	}

	/* Verify the SSID */
	ssidcheck = ieee80211_is_valid_ssid(wlanhandle->ssid, ieitems.ssid, ieitems.ssid_list);
	if (ssidcheck == IEEE80211_WRONG_SSID) {
		return;
	}

	/* Create probe response */
	memset(&ieee80211_params, 0, sizeof(struct ieee80211_probe_response_params));
	memcpy(ieee80211_params.bssid, wlanhandle->address, ETH_ALEN);
	memcpy(ieee80211_params.station, mgmt->sa, ETH_ALEN);
	ieee80211_params.beaconperiod = wlanhandle->devicehandle->beaconperiod;
	ieee80211_params.capability = nl80211_wlan_check_capability(wlanhandle, wlanhandle->capability);
	ieee80211_params.ssid = wlanhandle->ssid;
	memcpy(ieee80211_params.supportedrates, wlanhandle->devicehandle->supportedrates, wlanhandle->devicehandle->supportedratescount);
	ieee80211_params.supportedratescount = wlanhandle->devicehandle->supportedratescount;
	ieee80211_params.mode = wlanhandle->devicehandle->currentfrequency.mode;
	ieee80211_params.erpinfo = ieee80211_get_erpinfo(wlanhandle->devicehandle->currentfrequency.mode, wlanhandle->devicehandle->olbc, wlanhandle->devicehandle->stationsnonerpcount, wlanhandle->devicehandle->stationsnoshortpreamblecount, wlanhandle->devicehandle->shortpreamble);
	ieee80211_params.channel = wlanhandle->devicehandle->currentfrequency.channel;

	responselength = ieee80211_create_probe_response(g_bufferIEEE80211, sizeof(g_bufferIEEE80211), &ieee80211_params);
	if (responselength < 0) {
		return;
	}

	/* Send probe response */
	memset(&wlan_params, 0, sizeof(struct wlan_send_frame_params));
	wlan_params.packet = g_bufferIEEE80211;
	wlan_params.length = responselength;
	wlan_params.frequency = wlanhandle->devicehandle->currentfrequency.frequency;
	wlan_params.no_wait_ack = ((ssidcheck == IEEE80211_WILDCARD_SSID) && ieee80211_is_broadcast_addr(mgmt->da) ? 1 : 0);

	if (nl80211_wlan_send_frame((wifi_wlan_handle)wlanhandle, &wlan_params)) {
		capwap_logging_warning("Unable to send IEEE802.11 Probe Response");
		return;
	}

	/* If enable Split Mac send the probe request message to AC */
	if (wlanhandle->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
		wlanhandle->send_mgmtframe(wlanhandle->send_mgmtframe_to_ac_cbparam, mgmt, mgmtlength);
	}
}

/* */
static void nl80211_do_mgmt_authentication_event(struct nl80211_wlan_handle* wlanhandle, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int acl;
	int ielength;
	struct ieee80211_ie_items ieitems;
	int responselength;
	uint16_t algorithm;
	uint16_t transactionseqnumber;
	uint16_t responsestatuscode;
	struct ieee80211_authentication_params ieee80211_params;
	struct wlan_send_frame_params wlan_params;
	struct nl80211_station* station;

	/* Information Elements packet length */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->authetication));
	if (ielength < 0) {
		return;
	}

	/* Ignore authentication packet from same AP */
	if (!memcmp(mgmt->sa, wlanhandle->address, ETH_ALEN)) {
		return;
	}

	/* Get ACL Station */
	acl = wtp_radio_acl_station(mgmt->sa);
	if (acl == WTP_RADIO_ACL_STATION_DENY) {
		return;
	}

	/* Parsing Information Elements */
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->authetication.ie[0], ielength)) {
		return;
	}

	/* Create station reference */
	station = nl80211_station_create(wlanhandle, mgmt->sa);
	if (station) {
		algorithm = __le16_to_cpu(mgmt->authetication.algorithm);
		transactionseqnumber = __le16_to_cpu(mgmt->authetication.transactionseqnumber);

		/* Check authentication algorithm */
		responsestatuscode = IEEE80211_STATUS_NOT_SUPPORTED_AUTHENTICATION_ALGORITHM;
		if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_OPEN) && (wlanhandle->authenticationtype == CAPWAP_ADD_WLAN_AUTHTYPE_OPEN)) {
			if (transactionseqnumber == 1) {
				responsestatuscode = IEEE80211_STATUS_SUCCESS;
				station->authalgorithm = IEEE80211_AUTHENTICATION_ALGORITHM_OPEN;
			} else {
				responsestatuscode = IEEE80211_STATUS_UNKNOWN_AUTHENTICATION_TRANSACTION;
			}
		} else if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_SHARED_KEY) && (wlanhandle->authenticationtype == CAPWAP_ADD_WLAN_AUTHTYPE_WEP)) {
			/* TODO */
		}
	} else {
		responsestatuscode = IEEE80211_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
	}

	/* */
	if (wlanhandle->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL) {
		/* Create authentication packet */
		memset(&ieee80211_params, 0, sizeof(struct ieee80211_authentication_params));
		memcpy(ieee80211_params.bssid, wlanhandle->address, ETH_ALEN);
		memcpy(ieee80211_params.station, mgmt->sa, ETH_ALEN);
		ieee80211_params.algorithm = algorithm;
		ieee80211_params.transactionseqnumber = transactionseqnumber + 1;
		ieee80211_params.statuscode = responsestatuscode;

		responselength = ieee80211_create_authentication_response(g_bufferIEEE80211, sizeof(g_bufferIEEE80211), &ieee80211_params);
		if (responselength < 0) {
			return;
		}

		/* Send authentication response */
		memset(&wlan_params, 0, sizeof(struct wlan_send_frame_params));
		wlan_params.packet = g_bufferIEEE80211;
		wlan_params.length = responselength;
		wlan_params.frequency = wlanhandle->devicehandle->currentfrequency.frequency;

		if (nl80211_wlan_send_frame((wifi_wlan_handle)wlanhandle, &wlan_params)) {
			capwap_logging_warning("Unable to send IEEE802.11 Authentication Response");
			return;
		}

		wlanhandle->last_cookie = wlan_params.cookie;

		/* Notify authentication message also to AC */
		wlanhandle->send_mgmtframe(wlanhandle->send_mgmtframe_to_ac_cbparam, mgmt, mgmtlength);
	} else if ((wlanhandle->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) && (responsestatuscode == IEEE80211_STATUS_SUCCESS)) {
		wlanhandle->send_mgmtframe(wlanhandle->send_mgmtframe_to_ac_cbparam, mgmt, mgmtlength);
	}
}

/* */
static int nl80211_set_station_information(struct nl80211_wlan_handle* wlanhandle, const struct ieee80211_header_mgmt* mgmt, struct ieee80211_ie_items* ieitems, struct nl80211_station* station) {
	int updatebeacons = 0;

	/* Verify SSID */
	if (ieee80211_is_valid_ssid(wlanhandle->ssid, ieitems->ssid, NULL) != IEEE80211_VALID_SSID) {
		return IEEE80211_STATUS_UNSPECIFIED_FAILURE;
	}

	/* */
	station->capability = __le16_to_cpu(mgmt->associationrequest.capability);
	station->listeninterval = __le16_to_cpu(mgmt->associationrequest.listeninterval);
	if (ieee80211_aid_create(wlanhandle->aidbitfield, &station->aid)) {
		return IEEE80211_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
	}

	/* Get supported rates */
	if (!ieitems->supported_rates) {
		return IEEE80211_STATUS_UNSPECIFIED_FAILURE;
	} else if ((ieitems->supported_rates->len + (ieitems->extended_supported_rates ? ieitems->extended_supported_rates->len : 0)) > sizeof(station->supportedrates)) {
		return IEEE80211_STATUS_UNSPECIFIED_FAILURE;
	}

	station->supportedratescount = ieitems->supported_rates->len;
	memcpy(station->supportedrates, ieitems->supported_rates->rates, ieitems->supported_rates->len);
	if (ieitems->extended_supported_rates) {
		station->supportedratescount += ieitems->extended_supported_rates->len;
		memcpy(&station->supportedrates[ieitems->supported_rates->len], ieitems->extended_supported_rates->rates, ieitems->extended_supported_rates->len);
	}

	/* Check NON ERP */
	if (wlanhandle->devicehandle->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G) {
		int i;
		int stationnonerp = 1;

		for (i = 0; i < station->supportedratescount; i++) {
			if (IS_IEEE80211_RATE_G(station->supportedrates[i])) {
				stationnonerp = 0;
				break;
			}
		}

		if (stationnonerp) {
			station->flags |= NL80211_STATION_FLAGS_NON_ERP;
			wlanhandle->devicehandle->stationsnonerpcount++;
			if (wlanhandle->devicehandle->stationsnonerpcount == 1) {
				updatebeacons = 1;
			}
		}
	}

	/* Check short slot capability */
	if (!(station->capability & IEEE80211_CAPABILITY_SHORTSLOTTIME)) {
		station->flags |= NL80211_STATION_FLAGS_NO_SHORT_SLOT_TIME;
		wlanhandle->devicehandle->stationsnoshortslottimecount++;
		if ((wlanhandle->devicehandle->stationsnoshortslottimecount == 1) && (wlanhandle->devicehandle->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G)) {
			updatebeacons = 1;
		}
	}

	/* Check short preamble capability */
	if (!(station->capability & IEEE80211_CAPABILITY_SHORTPREAMBLE)) {
		station->flags |= NL80211_STATION_FLAGS_NO_SHORT_PREAMBLE;
		wlanhandle->devicehandle->stationsnoshortpreamblecount++;
		if ((wlanhandle->devicehandle->stationsnoshortpreamblecount == 1) && (wlanhandle->devicehandle->currentfrequency.mode & IEEE80211_RADIO_TYPE_80211G)) {
			updatebeacons = 1;
		}
	}

	/* Update beacon */
	if (updatebeacons) {
		nl80211_device_updatebeacons(wlanhandle->devicehandle);
	}

	return IEEE80211_STATUS_SUCCESS;
}

/* */
static void nl80211_do_mgmt_disassociation_event(struct nl80211_wlan_handle* wlanhandle, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;

	/* TODO */

	/* Information Elements packet length */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->disassociation));
	if (ielength < 0) {
		return;
	}

	/* TODO */

	/* Notify disassociation message also to AC */
	wlanhandle->send_mgmtframe(wlanhandle->send_mgmtframe_to_ac_cbparam, mgmt, mgmtlength);
}

/* */
static void nl80211_do_mgmt_reassociation_request_event(struct nl80211_wlan_handle* wlanhandle, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;

	/* TODO */

	/* Information Elements packet length */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->reassociationrequest));
	if (ielength < 0) {
		return;
	}

	/* TODO */
}

/* */
static void nl80211_do_mgmt_association_request_event(struct nl80211_wlan_handle* wlanhandle, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	int responselength;
	struct ieee80211_ie_items ieitems;
	struct ieee80211_associationresponse_params ieee80211_params;
	struct wlan_send_frame_params wlan_params;
	struct nl80211_station* station;
	uint16_t resultstatuscode = IEEE80211_STATUS_SUCCESS;

	/* Information Elements packet length */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->associationrequest));
	if (ielength < 0) {
		return;
	}

	/* Get station reference */
	station = nl80211_station_get(wlanhandle, mgmt->sa);
	if (!station || !(station->flags & NL80211_STATION_FLAGS_AUTHENTICATED)) {
		/* Invalid station, send deauthentication message */
		nl80211_wlan_send_deauthentication(wlanhandle, mgmt->sa, IEEE80211_REASON_CLASS2_FRAME_FROM_NONAUTH_STA);
		return;
	}

	/* Parsing Information Elements */
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->associationrequest.ie[0], ielength)) {
		return;
	}

	resultstatuscode = nl80211_set_station_information(wlanhandle, mgmt, &ieitems, station);

	/* */
	if (wlanhandle->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL) {
		if (resultstatuscode == IEEE80211_STATUS_SUCCESS) {
			if (ieee80211_aid_create(wlanhandle->aidbitfield, &station->aid)) {
				resultstatuscode = IEEE80211_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
			}
		}

		/* Create association response packet */
		memset(&ieee80211_params, 0, sizeof(struct ieee80211_authentication_params));
		memcpy(ieee80211_params.bssid, wlanhandle->address, ETH_ALEN);
		memcpy(ieee80211_params.station, mgmt->sa, ETH_ALEN);
		ieee80211_params.capability = nl80211_wlan_check_capability(wlanhandle, wlanhandle->capability);
		ieee80211_params.statuscode = resultstatuscode;
		ieee80211_params.aid = IEEE80211_AID_FIELD | station->aid;
		memcpy(ieee80211_params.supportedrates, wlanhandle->devicehandle->supportedrates, wlanhandle->devicehandle->supportedratescount);
		ieee80211_params.supportedratescount = wlanhandle->devicehandle->supportedratescount;

		responselength = ieee80211_create_associationresponse_response(g_bufferIEEE80211, sizeof(g_bufferIEEE80211), &ieee80211_params);
		if (responselength < 0) {
			return;
		}

		/* Send authentication response */
		memset(&wlan_params, 0, sizeof(struct wlan_send_frame_params));
		wlan_params.packet = g_bufferIEEE80211;
		wlan_params.length = responselength;
		wlan_params.frequency = wlanhandle->devicehandle->currentfrequency.frequency;

		if (nl80211_wlan_send_frame((wifi_wlan_handle)wlanhandle, &wlan_params)) {
			capwap_logging_warning("Unable to send IEEE802.11 Association Response");
			return;
		}

		wlanhandle->last_cookie = wlan_params.cookie;

		/* Notify association request message also to AC */
		wlanhandle->send_mgmtframe(wlanhandle->send_mgmtframe_to_ac_cbparam, mgmt, mgmtlength);
	} else if ((wlanhandle->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) && (resultstatuscode == IEEE80211_STATUS_SUCCESS)) {
		wlanhandle->send_mgmtframe(wlanhandle->send_mgmtframe_to_ac_cbparam, mgmt, mgmtlength);
	}
}

/* */
static void nl80211_do_mgmt_deauthentication_event(struct nl80211_wlan_handle* wlanhandle, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct nl80211_station* station;

	/* TODO */

	/* Information Elements packet length */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->deauthetication));
	if (ielength < 0) {
		return;
	}

	/* Get station reference */
	station = nl80211_station_get(wlanhandle, mgmt->sa);
	if (!station) {
		return;
	}

	/* Free station */
	nl80211_station_delete(wlanhandle, mgmt->sa);

	/* Notify deauthentication message also to AC */
	wlanhandle->send_mgmtframe(wlanhandle->send_mgmtframe_to_ac_cbparam, mgmt, mgmtlength);
}

/* */
static void nl80211_do_mgmt_frame_event(struct nl80211_wlan_handle* wlanhandle, const struct ieee80211_header_mgmt* mgmt, int mgmtlength, uint16_t framecontrol_subtype, uint32_t frequency) {
	int broadcast;

	/* Check frequency */
	if (frequency && (wlanhandle->devicehandle->currentfrequency.frequency != frequency)) {
		return;
	}

	/* Check if sent packet to correct AP */
	broadcast = ieee80211_is_broadcast_addr(mgmt->bssid);
	if (!broadcast && memcmp(mgmt->bssid, wlanhandle->address, ETH_ALEN)) {
		return;
	}

	/* */
	if (framecontrol_subtype == IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_PROBE_REQUEST) {
		nl80211_do_mgmt_probe_request_event(wlanhandle, mgmt, mgmtlength);
	} else if (!memcmp(mgmt->da, wlanhandle->address, ETH_ALEN)) {
		switch (framecontrol_subtype) {
			case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTHENTICATION: {
				nl80211_do_mgmt_authentication_event(wlanhandle, mgmt, mgmtlength);
				break;
			}

			case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_REQUEST: {
				nl80211_do_mgmt_association_request_event(wlanhandle, mgmt, mgmtlength);
				break;
			}

			case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_REASSOCIATION_REQUEST: {
				nl80211_do_mgmt_reassociation_request_event(wlanhandle, mgmt, mgmtlength);
				break;
			}

			case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DISASSOCIATION: {
				nl80211_do_mgmt_disassociation_event(wlanhandle, mgmt, mgmtlength);
				break;
			}

			case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTHENTICATION: {
				nl80211_do_mgmt_deauthentication_event(wlanhandle, mgmt, mgmtlength);
				break;
			}

			case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ACTION: {
				/* TODO */
				break;
			}
		}
	}
}

/* */
static void nl80211_do_frame_event(struct nl80211_wlan_handle* wlanhandle, const uint8_t* framedata, int framelength, uint32_t frequency) {
	const struct ieee80211_header* header;
	uint16_t framecontrol;
	uint16_t framecontrol_type;
	uint16_t framecontrol_subtype;

	/* Check frame */
	if (!framedata || (framelength < sizeof(struct ieee80211_header))) {
		return;
	}

	/* Get type frame */
	header = (const struct ieee80211_header*)framedata;
	framecontrol = __le16_to_cpu(header->framecontrol);
	framecontrol_type = IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol);
	framecontrol_subtype = IEEE80211_FRAME_CONTROL_GET_SUBTYPE(framecontrol);

	/* Parsing frame */
	if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_MGMT) {
		nl80211_do_mgmt_frame_event(wlanhandle, (const struct ieee80211_header_mgmt*)framedata, framelength, framecontrol_subtype, frequency);
	}
}

/* */
static void nl80211_do_mgmt_frame_tx_status_authentication_event(struct nl80211_wlan_handle* wlanhandle, const struct ieee80211_header_mgmt* mgmt, int mgmtlength, uint64_t cookie, int ack) {
	uint16_t algorithm;
	uint16_t transactionseqnumber;
	uint16_t statuscode;
	struct nl80211_station* station;

	/* Accept only acknowledge authentication response with same cookie */
	if (!ack || (wlanhandle->last_cookie != cookie)) {
		return;
	}

	/* Check packet */
	if (mgmtlength < (sizeof(struct ieee80211_header) + sizeof(mgmt->authetication))) {
		return;
	}

	/* Get station information */
	station = nl80211_station_get(wlanhandle, mgmt->da);
	if (!station) {
		return;
	}

	/* */
	statuscode = __le16_to_cpu(mgmt->authetication.statuscode);
	if (statuscode == IEEE80211_STATUS_SUCCESS) {
		algorithm = __le16_to_cpu(mgmt->authetication.algorithm);
		transactionseqnumber = __le16_to_cpu(mgmt->authetication.transactionseqnumber);

		/* Check if authenticate */
		if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_OPEN) && (transactionseqnumber == 2)) {
			station->flags |= NL80211_STATION_FLAGS_AUTHENTICATED;
		} else if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_SHARED_KEY) && (transactionseqnumber == 4)) {
			/* TODO */
		}
	}
}

/* */
static void nl80211_do_mgmt_frame_tx_status_association_response_event(struct nl80211_wlan_handle* wlanhandle, const struct ieee80211_header_mgmt* mgmt, int mgmtlength, uint64_t cookie, int ack) {
	uint16_t statuscode;
	struct nl80211_station* station;

	/* Accept only acknowledge association response with same cookie */
	if (!ack || (wlanhandle->last_cookie != cookie)) {
		return;
	}

	/* Check packet */
	if (mgmtlength < (sizeof(struct ieee80211_header) + sizeof(mgmt->associationresponse))) {
		return;
	}

	/* Get station information */
	station = nl80211_station_get(wlanhandle, mgmt->da);
	if (!station) {
		return;
	}

	/* */
	statuscode = __le16_to_cpu(mgmt->associationresponse.statuscode);
	if (statuscode == IEEE80211_STATUS_SUCCESS) {
		station->flags |= NL80211_STATION_FLAGS_ASSOCIATE;
	}
}

/* */
static void nl80211_do_mgmt_frame_tx_status_event(struct nl80211_wlan_handle* wlanhandle, const struct ieee80211_header_mgmt* mgmt, int mgmtlength, uint16_t framecontrol_subtype, uint64_t cookie, int ack) {
	/* Ignore packet if not sent to AP */
	if (memcmp(mgmt->bssid, wlanhandle->address, ETH_ALEN)) {
		return;
	}

	/* */
	switch (framecontrol_subtype) {
		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTHENTICATION: {
			nl80211_do_mgmt_frame_tx_status_authentication_event(wlanhandle, mgmt, mgmtlength, cookie, ack);
			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_RESPONSE: {
			nl80211_do_mgmt_frame_tx_status_association_response_event(wlanhandle, mgmt, mgmtlength, cookie, ack);
			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTHENTICATION: {
			/* TODO */
			break;
		}
	}

	/* Remove cookie */
	wlanhandle->last_cookie = 0;
}

/* */
static void nl80211_do_frame_tx_status_event(struct nl80211_wlan_handle* wlanhandle, const uint8_t* framedata, int framelength, uint64_t cookie, int ack) {
	const struct ieee80211_header* header;
	uint16_t framecontrol;
	uint16_t framecontrol_type;
	uint16_t framecontrol_subtype;

	/* Check frame */
	if (!framedata || (framelength < sizeof(struct ieee80211_header))) {
		return;
	}

	/* Get type frame */
	header = (const struct ieee80211_header*)framedata;
	framecontrol = __le16_to_cpu(header->framecontrol);
	framecontrol_type = IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol);
	framecontrol_subtype = IEEE80211_FRAME_CONTROL_GET_SUBTYPE(framecontrol);

	/* Parsing frame */
	if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_MGMT) {
		nl80211_do_mgmt_frame_tx_status_event(wlanhandle, (const struct ieee80211_header_mgmt*)framedata, framelength, framecontrol_subtype, cookie, ack);
	}
}

/* */
static int nl80211_execute_bss_event(struct nl80211_wlan_handle* wlanhandle, struct genlmsghdr* gnlh, struct nlattr** tb_msg) {
	switch (gnlh->cmd) {
		case NL80211_CMD_FRAME: {
			if (tb_msg[NL80211_ATTR_FRAME]) {
				uint32_t frequency = 0;

				if (tb_msg[NL80211_ATTR_WIPHY_FREQ]) {
					frequency = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]);
				}

				nl80211_do_frame_event(wlanhandle, nla_data(tb_msg[NL80211_ATTR_FRAME]), nla_len(tb_msg[NL80211_ATTR_FRAME]), frequency);
			}

			break;
		}

		case NL80211_CMD_FRAME_TX_STATUS: {
			if (tb_msg[NL80211_ATTR_FRAME] && tb_msg[NL80211_ATTR_COOKIE]) {
				nl80211_do_frame_tx_status_event(wlanhandle, nla_data(tb_msg[NL80211_ATTR_FRAME]), nla_len(tb_msg[NL80211_ATTR_FRAME]), nla_get_u64(tb_msg[NL80211_ATTR_COOKIE]), (tb_msg[NL80211_ATTR_ACK] ? 1 : 0));
			}

			break;
		}

		case NL80211_CMD_TRIGGER_SCAN: {
			break;
		}

		case NL80211_CMD_NEW_SCAN_RESULTS: {
			break;
		}

		default: {
			capwap_logging_debug("*** nl80211_execute_bss_event: %d", (int)gnlh->cmd);
			break;
		}
	}

	return NL_SKIP;
}

/* */
static int nl80211_process_bss_event(struct nl_msg* msg, void* arg) {
	struct nlattr* tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)arg;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	return nl80211_execute_bss_event(wlanhandle, gnlh, tb_msg);
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
static unsigned long nl80211_hash_station_gethash(const void* key, unsigned long keysize, unsigned long hashsize) {
	uint8_t* macaddress = (uint8_t*)key;

	ASSERT(keysize == ETH_ALEN);

	return ((macaddress[3] ^ macaddress[4] ^ macaddress[5]) >> 2);
}

/* */
static void nl80211_hash_station_free(const void* key, unsigned long keysize, void* data) {
	struct nl80211_station* station = (struct nl80211_station*)data;

	ASSERT(data != NULL);

	capwap_free(station);
}

/* */
static struct nl80211_wlan_handle* nl80211_global_search_wlan(struct nl80211_global_handle* globalhandle, uint32_t ifindex) {
	struct nl80211_device_handle* devicehandle;
	struct nl80211_wlan_handle* wlanhandle;
	struct capwap_list_item* devicesearch;
	struct capwap_list_item* wlansearch;

	ASSERT(globalhandle != NULL);

	/* Search device */
	devicesearch = globalhandle->devicelist->first;
	while (devicesearch) {
		devicehandle = (struct nl80211_device_handle*)devicesearch->item;

		/* Search wlan */
		wlansearch = devicehandle->wlanlist->first;
		while (wlansearch) {
			wlanhandle = (struct nl80211_wlan_handle*)wlansearch->item;
			if (wlanhandle->virtindex == ifindex) {
				return wlanhandle;
			}

			/* */
			wlansearch = wlansearch->next;
		}

		/* */
		devicesearch = devicesearch->next;
	}

	return NULL;
}

/* */
static int nl80211_global_valid_handler(struct nl_msg* msg, void* data) {
	uint32_t ifindex;
	struct nl80211_wlan_handle* wlanhandle;
	struct nlattr* tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nl80211_global_handle* globalhandle = (struct nl80211_global_handle*)data;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_IFINDEX]) {
		ifindex = (int)nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]);

		/* Search interface */
		wlanhandle = nl80211_global_search_wlan(globalhandle, ifindex);
		if (wlanhandle) {
			return nl80211_execute_bss_event(wlanhandle, gnlh, tb_msg);
		} else {
			capwap_logging_debug("*** Receive nl80211_global_valid_handler without found interface: %d", (int)ifindex);
		}
	} else {
		capwap_logging_debug("*** Receive nl80211_global_valid_handler without interface index");
	}

	return NL_SKIP;
}

/* */
static void nl80211_global_newlink_event(wifi_global_handle handle, struct ifinfomsg* infomsg, uint8_t* data, int length) {
	struct nl80211_wlan_handle* wlanhandle;
	struct nl80211_global_handle* globalhandle = (struct nl80211_global_handle*)handle;

	ASSERT(handle != NULL);
	ASSERT(infomsg != NULL);

	/* Search device */
	wlanhandle = nl80211_global_search_wlan(globalhandle, infomsg->ifi_index);
	if (wlanhandle) {
		if (!(wlanhandle->flags & NL80211_WLAN_RUNNING)) {
			if ((infomsg->ifi_flags & IFF_UP) && (wifi_iface_getstatus(globalhandle->sock_util, wlanhandle->virtname) > 0)) {
				wifi_iface_down(globalhandle->sock_util, wlanhandle->virtname);
			}
		} else if (wlanhandle->flags & NL80211_WLAN_SET_BEACON) {
			if ((wlanhandle->flags & NL80211_WLAN_OPERSTATE_RUNNING) && (infomsg->ifi_flags & IFF_LOWER_UP) && !(infomsg->ifi_flags & (IFF_RUNNING | IFF_DORMANT))) {
				netlink_set_link_status(wlanhandle->devicehandle->globalhandle->netlinkhandle, wlanhandle->virtindex, -1, IF_OPER_UP);
			}
		}
	}
}

/* */
static void nl80211_global_dellink_event(wifi_global_handle handle, struct ifinfomsg* infomsg, uint8_t* data, int length) {
	/* TODO */
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
static int nl80211_get_virtdevice_list(struct nl80211_global_handle* globalhandle, uint32_t phyindex, struct capwap_list* list) {
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
	nla_put_u32(msg, NL80211_ATTR_WIPHY, phyindex);

	/* Retrieve all virtual interface */
	result = nl80211_send_and_recv_msg(globalhandle, msg, cb_get_virtdevice_list, list);
	if (result) {
		capwap_logging_error("Unable get interfaces, error code: %d", result);
	}

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
	if (result) {
		capwap_logging_error("Unable get physical interfaces, error code: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static int cb_get_phydevice_capability(struct nl_msg* msg, void* data) {
	int i, j;
	struct nlattr* tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr* gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct wifi_capability* capability = (struct wifi_capability*)data;
	struct nl80211_device_handle* devicehandle = (struct nl80211_device_handle*)capability->device;
	int radio80211bg = 0;
	int radio80211a = 0;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_WIPHY] && (nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]) == devicehandle->phyindex)) {
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
			capability->capability |= WIFI_CAPABILITY_FLAGS_PROBE_RESPONSE_OFFLOAD;
			/* TODO check offload protocol support */
		}

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
	if (result) {
		capwap_logging_error("Unable destroy interface, error code: %d", result);
	}

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
	result = nl80211_get_virtdevice_list(globalhandle, phyindex, list);
	if (!result) {
		struct capwap_list_item* item = list->first;

		/* Search virtual device by physical device */
		while (item) {
			struct nl80211_virtdevice_item* virtitem = (struct nl80211_virtdevice_item*)item->item;

			/* Destroy virtual device */
			if (virtitem->phyindex == phyindex) {
				wifi_iface_down(globalhandle->sock_util, virtitem->virtname);
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
static int nl80211_registerframe(struct nl80211_wlan_handle* wlanhandle, uint16_t type, const uint8_t* match, int lengthmatch) {
	int result;
	struct nl_msg* msg;

	ASSERT(wlanhandle != NULL);

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_REGISTER_FRAME, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlanhandle->virtindex);
	nla_put_u16(msg, NL80211_ATTR_FRAME_TYPE, type);
	nla_put(msg, NL80211_ATTR_FRAME_MATCH, lengthmatch, match);

	/* Destroy virtual device */
	result = nl80211_send_and_recv(wlanhandle->nl, wlanhandle->nl_cb, msg, NULL, NULL);

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static int nl80211_device_getcapability(struct nl80211_device_handle* devicehandle) {
	int result;
	struct nl_msg* msg;

	ASSERT(devicehandle != NULL);

	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	genlmsg_put(msg, 0, 0, devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_GET_WIPHY, 0);
	nla_put_u32(msg, NL80211_ATTR_WIPHY, devicehandle->phyindex);

	/* Retrieve physical device capability */
	devicehandle->capability->device = (wifi_device_handle)devicehandle;
	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg, cb_get_phydevice_capability, devicehandle->capability);
	if (result) {
		capwap_logging_error("Unable retrieve physical device capability, error code: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static const struct wifi_capability* nl80211_device_getcachedcapability(wifi_device_handle handle) {
	struct nl80211_device_handle* devicehandle = (struct nl80211_device_handle*)handle;

	ASSERT(handle != NULL);
	ASSERT(devicehandle->capability != NULL);

	return devicehandle->capability;
}

/* */
static wifi_device_handle nl80211_device_init(wifi_global_handle handle, struct device_init_params* params) {
	int result;
	struct capwap_list* list;
	struct capwap_list_item* item;
	struct nl80211_device_handle* devicehandle = NULL;
	struct nl80211_global_handle* globalhandle = (struct nl80211_global_handle*)handle;

	if (!handle || !params) {
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
				devicehandle->globalhandle = globalhandle;
				strcpy(devicehandle->phyname, phyitem->name);
				devicehandle->phyindex = phyitem->index;

				/* Device capability */
				devicehandle->capability = (struct wifi_capability*)capwap_alloc(sizeof(struct wifi_capability));
				memset(devicehandle->capability, 0, sizeof(struct wifi_capability));

				devicehandle->capability->bands = capwap_array_create(sizeof(struct wifi_band_capability), 0, 1);
				devicehandle->capability->ciphers = capwap_array_create(sizeof(struct wifi_cipher_capability), 0, 1);

				/* Retrieve device capability */
				nl80211_device_getcapability(devicehandle);
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

	/* Remove all virtual adapter from wifi device */
	nl80211_destroy_all_virtdevice(globalhandle, devicehandle->phyindex);

	/* AP list */
	devicehandle->wlanlist = capwap_list_create();

	/* Save device handle into global handle */
	item = capwap_itemlist_create_with_item(devicehandle, sizeof(struct nl80211_device_handle));
	item->autodelete = 0;
	capwap_itemlist_insert_after(globalhandle->devicelist, NULL, item);

	return devicehandle;
}

/* */
static int nl80211_device_getfdevent(wifi_device_handle handle, struct pollfd* fds, struct wifi_event* events) {
	return 0;
}

/* */
static int nl80211_device_setconfiguration(wifi_device_handle handle, struct device_setconfiguration_params* params) {
	struct nl80211_device_handle* devicehandle = (struct nl80211_device_handle*)handle;

	ASSERT(handle != NULL);

	/* */
	devicehandle->flags |= NL80211_DEVICE_SET_CONFIGURATION;
	devicehandle->beaconperiod = params->beaconperiod;
	devicehandle->dtimperiod = params->dtimperiod;
	devicehandle->shortpreamble = (params->shortpreamble ? 1 : 0);

	/* Update beacons */
	if (devicehandle->wlanlist->count) {
		nl80211_device_updatebeacons(devicehandle);
	}

	return 0;
}

/* */
static int nl80211_device_changefrequency(struct nl80211_device_handle* devicehandle, struct wifi_frequency* freq) {
	int result;
	struct nl_msg* msg;
	struct capwap_list_item* wlansearch;
	struct nl80211_wlan_handle* wlanhandle = NULL;

	ASSERT(devicehandle != NULL);
	ASSERT(freq != NULL);

	/* Delay request if not found BSS interface */
	if (!devicehandle->wlanactive) {
		return 0;
	}

	/* Search a valid interface */
	wlansearch = devicehandle->wlanlist->first;
	while (wlansearch) {
		struct nl80211_wlan_handle* element = (struct nl80211_wlan_handle*)wlansearch->item;

		if (element->flags & NL80211_WLAN_RUNNING) {
			wlanhandle = element;
			break;
		}

		/* */
		wlansearch = wlansearch->next;
	}

	/* */
	if (!wlanhandle) {
		return -1;
	}

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* Set frequecy using device index of first BSS */
	genlmsg_put(msg, 0, 0, devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_SET_WIPHY, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlanhandle->virtindex);
	nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq->frequency);

	/* Set wifi frequency */
	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg, NULL, NULL);
	if (result) {
		capwap_logging_error("Unable set frequency %d, error code: %d", (int)freq->frequency, result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static int nl80211_device_setfrequency(wifi_device_handle handle, struct wifi_frequency* freq) {
	struct nl80211_device_handle* devicehandle = (struct nl80211_device_handle*)handle;

	ASSERT(handle != NULL);
	ASSERT(freq != NULL);

	/* Save frequency before change */
	devicehandle->flags |= NL80211_DEVICE_SET_FREQUENCY;
	memcpy(&devicehandle->currentfrequency, freq, sizeof(struct wifi_frequency));
	return nl80211_device_changefrequency(devicehandle, &devicehandle->currentfrequency);
}

/* */
static int nl80211_device_setrates(wifi_device_handle handle, struct device_setrates_params* params) {
	struct nl80211_device_handle* devicehandle = (struct nl80211_device_handle*)handle;

	ASSERT(handle != NULL);
	ASSERT(params != NULL);

	/* */
	if (!params->supportedratescount || (params->supportedratescount > IEEE80211_SUPPORTEDRATE_MAX_COUNT)) {
		return -1;
	} else if (!params->basicratescount || (params->basicratescount > IEEE80211_SUPPORTEDRATE_MAX_COUNT)) {
		return -1;
	}

	/* Set new rates */
	devicehandle->flags |= NL80211_DEVICE_SET_RATES;
	memcpy(devicehandle->supportedrates, params->supportedrates, params->supportedratescount);
	devicehandle->supportedratescount = params->supportedratescount;
	memcpy(devicehandle->basicrates, params->basicrates, params->basicratescount);
	devicehandle->basicratescount = params->basicratescount;

	/* Update beacons */
	if (devicehandle->wlanlist->count) {
		nl80211_device_updatebeacons(devicehandle);
	}

	return 0;
}

/* */
static void nl80211_wlan_delete(wifi_wlan_handle handle) {
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)handle;

	if (wlanhandle) {
		/* Terminate service */
		nl80211_wlan_stopap(handle);

		/* Release resource */
		if (wlanhandle->devicehandle) {
			struct capwap_list_item* search;

			/* Remove wlan handle from device handle */
			search = wlanhandle->devicehandle->wlanlist->first;
			while (search) {
				if ((struct nl80211_wlan_handle*)search->item == wlanhandle) {
					/* Remove item from list */
					capwap_itemlist_free(capwap_itemlist_remove(wlanhandle->devicehandle->wlanlist, search));
					break;
				}

				search = search->next;
			}
		}

		if (wlanhandle->virtindex) {
			nl80211_destroy_virtdevice(wlanhandle->devicehandle->globalhandle, wlanhandle->virtindex);
		}

		if (wlanhandle->stations) {
			capwap_hash_free(wlanhandle->stations);
		}

		capwap_free(wlanhandle);
	}
}

/* */
static void nl80211_device_deinit(wifi_device_handle handle) {
	int i;
	struct nl80211_device_handle* devicehandle = (struct nl80211_device_handle*)handle;

	if (devicehandle) {
		struct capwap_list_item* search;

		/* Destroy AP */
		while (devicehandle->wlanlist->first) {
			nl80211_wlan_delete((wifi_wlan_handle)devicehandle->wlanlist->first->item);
		}

		/* Remove device handle from global handle */
		search = devicehandle->globalhandle->devicelist->first;
		while (search) {
			if ((struct nl80211_device_handle*)search->item == devicehandle) {
				/* Remove item from list */
				capwap_itemlist_free(capwap_itemlist_remove(devicehandle->globalhandle->devicelist, search));
				break;
			}

			search = search->next;
		}

		/* Free capability */
		if (devicehandle->capability) {
			if (devicehandle->capability->bands) {
				for (i = 0; i < devicehandle->capability->bands->count; i++) {
					struct wifi_band_capability* bandcap = (struct wifi_band_capability*)capwap_array_get_item_pointer(devicehandle->capability->bands, i);

					if (bandcap->freq) {
						capwap_array_free(bandcap->freq);
					}

					if (bandcap->rate) {
						capwap_array_free(bandcap->rate);
					}
				}

				capwap_array_free(devicehandle->capability->bands);
			}

			if (devicehandle->capability->ciphers) {
				capwap_array_free(devicehandle->capability->ciphers);
			}

			capwap_free(devicehandle->capability);
		}

		if (devicehandle->wlanlist) {
			ASSERT(devicehandle->wlanlist->count == 0);
			capwap_list_free(devicehandle->wlanlist);
		}

		/* */
		capwap_free(devicehandle);
	}
}

/* */
static int nl80211_wlan_set_profile(struct nl80211_wlan_handle* wlanhandle, uint32_t type) {
	int result;

	ASSERT(wlanhandle != NULL);

	/* Check current type */
	/*if (type == nl80211_wlan_get_type(wlanhandle)) {
		return 0;
	}*/

	/* Change interface type */
	result = nl80211_wlan_set_type(wlanhandle, type);
	if (result && (type == nl80211_wlan_get_type(wlanhandle))) {
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
static wifi_wlan_handle nl80211_wlan_create(wifi_device_handle handle, const char* ifname) {
	int result;
	uint32_t ifindex;
	struct nl_msg* msg;
	struct capwap_list_item* item;
	struct nl80211_wlan_handle* wlanhandle;
	struct nl80211_device_handle* devicehandle = (struct nl80211_device_handle*)handle;

	ASSERT(handle != NULL);
	ASSERT(ifname != NULL);
	ASSERT(*ifname != 0);

	if (!devicehandle) {
		return NULL;
	}

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return NULL;
	}

	/* Create wlan interface */
	genlmsg_put(msg, 0, 0, devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_NEW_INTERFACE, 0);
	nla_put_u32(msg, NL80211_ATTR_WIPHY, devicehandle->phyindex);
	nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
	nla_put_string(msg, NL80211_ATTR_IFNAME, ifname);

	/* */
	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg, NULL, NULL);
	nlmsg_free(msg);

	/* Check interface */
	if (result) {
		capwap_logging_error("Unable create interface %s, error code: %d", ifname, result);
		return NULL;
	}

	ifindex = wifi_iface_index(ifname);
	if (!ifindex) {
		return NULL;
	}

	/* Init wlan */
	wlanhandle = (struct nl80211_wlan_handle*)capwap_alloc(sizeof(struct nl80211_wlan_handle));
	memset(wlanhandle, 0, sizeof(struct nl80211_wlan_handle));

	/* */
	wlanhandle->devicehandle = devicehandle;
	wlanhandle->virtindex = ifindex;
	strcpy(wlanhandle->virtname, ifname);
	wlanhandle->nl_fd = -1;

	/* Save AP handle into device handle */
	item = capwap_itemlist_create_with_item(wlanhandle, sizeof(struct nl80211_wlan_handle));
	item->autodelete = 0;
	capwap_itemlist_insert_after(devicehandle->wlanlist, NULL, item);

	/* Mac address */
	if (wifi_iface_hwaddr(devicehandle->globalhandle->sock_util, wlanhandle->virtname, wlanhandle->address)) {
		nl80211_wlan_delete((wifi_wlan_handle)wlanhandle);
		return NULL;
	}

	/* Stations */
	wlanhandle->stations = capwap_hash_create(WIFI_NL80211_STATIONS_HASH_SIZE, WIFI_NL80211_STATIONS_KEY_SIZE, nl80211_hash_station_gethash, NULL, nl80211_hash_station_free);
	wlanhandle->maxstationscount = IEEE80211_MAX_STATIONS;

	return wlanhandle;
}

/* */
static int nl80211_wlan_getfdevent(wifi_wlan_handle handle, struct pollfd* fds, struct wifi_event* events) {
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)handle;

	ASSERT(handle != NULL);

	if (!(wlanhandle->flags & NL80211_WLAN_RUNNING) || (wlanhandle->nl_fd < 0)) {
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
static int nl80211_wlan_startap(wifi_wlan_handle handle, struct wlan_startap_params* params) {
	int i;
	int result;
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)handle;

	ASSERT(handle != NULL);
	ASSERT(params != NULL);

	/* Check device */
	if ((wlanhandle->flags & NL80211_WLAN_RUNNING) || ((wlanhandle->devicehandle->flags & NL80211_DEVICE_REQUIRED_FOR_BSS) != NL80211_DEVICE_REQUIRED_FOR_BSS)) {
		return -1;
	}

	/* Configure interface with AP profile */
	if (nl80211_wlan_set_profile(wlanhandle, NL80211_IFTYPE_AP)) {
		return -1;
	}

	/* Socket management */
	wlanhandle->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!wlanhandle->nl_cb) {
		return -1;
	}

	nl_cb_set(wlanhandle->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, nl80211_no_seq_check, NULL);
	nl_cb_set(wlanhandle->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_process_bss_event, (void*)wlanhandle);

	wlanhandle->nl = nl_create_handle(wlanhandle->nl_cb);
	if (wlanhandle->nl) {
		wlanhandle->nl_fd = nl_socket_get_fd(wlanhandle->nl);
	} else {
		nl80211_wlan_stopap(handle);
		return -1;
	}

	/* Register frames */
	for (i = 0; i < sizeof(g_stypes) / sizeof(g_stypes[0]); i++) {
		result = nl80211_registerframe(wlanhandle, (IEEE80211_FRAMECONTROL_TYPE_MGMT << 2) | (g_stypes[i] << 4), NULL, 0);
		if (result) {
			capwap_logging_error("Unable to register frame %d, error code: %d", g_stypes[i], result);
			nl80211_wlan_stopap(handle);
			return -1;
		}
	}

	/* Enable interface */
	wlanhandle->flags |= NL80211_WLAN_RUNNING;
	if (wifi_iface_up(wlanhandle->devicehandle->globalhandle->sock_util, wlanhandle->virtname)) {
		nl80211_wlan_stopap(handle);
		return -1;
	}

	/* Configure device if first BSS device */
	if (!wlanhandle->devicehandle->wlanactive) {
		/* Set device frequency */
		nl80211_device_changefrequency(wlanhandle->devicehandle, &wlanhandle->devicehandle->currentfrequency);
		/* TODO Get current frequency */
	}

	/* Save configuration */
	strcpy(wlanhandle->ssid, params->ssid);
	wlanhandle->ssid_hidden = params->ssid_hidden;
	wlanhandle->capability = params->capability;
	wlanhandle->authenticationtype = ((params->authmode == CAPWAP_ADD_WLAN_AUTHTYPE_WEP) ? NL80211_AUTHTYPE_SHARED_KEY : NL80211_AUTHTYPE_OPEN_SYSTEM);
	wlanhandle->macmode = params->macmode;
	wlanhandle->tunnelmode = params->tunnelmode;
	wlanhandle->send_mgmtframe = params->send_mgmtframe;
	wlanhandle->send_mgmtframe_to_ac_cbparam = params->send_mgmtframe_to_ac_cbparam;
	wlanhandle->timeout = params->timeout;

	/* Set beacon */
	if (nl80211_wlan_setbeacon(wlanhandle)) {
		nl80211_wlan_stopap(handle);
		return -1;
	}

	/* Enable operation status */
	wlanhandle->flags |= NL80211_WLAN_OPERSTATE_RUNNING;
	netlink_set_link_status(wlanhandle->devicehandle->globalhandle->netlinkhandle, wlanhandle->virtindex, -1, IF_OPER_UP);

	/* Configuration complete */
	wlanhandle->devicehandle->wlanactive++;
	return 0;
}

/* */
static void nl80211_wlan_stopap(wifi_wlan_handle handle) {
	struct nl_msg* msg;
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)handle;

	ASSERT(handle);

	/* */
	if (wlanhandle->flags & NL80211_WLAN_SET_BEACON) {
		msg = nlmsg_alloc();
		if (msg) {
			genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_STOP_AP, 0);
			nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlanhandle->virtindex);

			/* Stop AP */
			nl80211_send_and_recv_msg(wlanhandle->devicehandle->globalhandle, msg, NULL, NULL);
			nlmsg_free(msg);
		}
	}

	/* Disable interface */
	wifi_iface_down(wlanhandle->devicehandle->globalhandle->sock_util, wlanhandle->virtname);

	/* Configure interface with station profile */
	nl80211_wlan_set_profile(wlanhandle, NL80211_IFTYPE_STATION);

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

	if (wlanhandle->flags & NL80211_WLAN_RUNNING) {
		wlanhandle->devicehandle->wlanactive--;
	}

	/* */
	wlanhandle->flags = 0;
}

/* */
static int nl80211_wlan_getmacaddress(wifi_wlan_handle handle, uint8_t* address) {
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)handle;

	ASSERT(handle != NULL);
	ASSERT(address != NULL);

	/* Return cached mac address */
	memcpy(address, wlanhandle->address, ETH_ALEN);
	return 0;
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
		result = nl_socket_add_membership(globalhandle->nl_event, result);
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
	nl_cb_set(globalhandle->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_global_valid_handler, globalhandle);

	/* Netlink lisk status */
	globalhandle->netlinkhandle = netlink_init();
	if (!globalhandle->netlinkhandle) {
		nl80211_global_deinit((wifi_global_handle)globalhandle);
		return NULL;
	}

	globalhandle->netlinkhandle->newlink_event = nl80211_global_newlink_event;
	globalhandle->netlinkhandle->dellink_event = nl80211_global_dellink_event;

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
	.device_getcapability = nl80211_device_getcachedcapability,
	.device_setconfiguration = nl80211_device_setconfiguration,
	.device_setfrequency = nl80211_device_setfrequency,
	.device_setrates = nl80211_device_setrates,
	.device_deinit = nl80211_device_deinit,
	.wlan_create = nl80211_wlan_create,
	.wlan_getfdevent = nl80211_wlan_getfdevent,
	.wlan_startap = nl80211_wlan_startap,
	.wlan_stopap = nl80211_wlan_stopap,
	.wlan_getmacaddress = nl80211_wlan_getmacaddress,
	.wlan_delete = nl80211_wlan_delete
};
