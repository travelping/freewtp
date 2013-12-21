#include "capwap.h"
#include "capwap_array.h"
#include "capwap_list.h"
#include "capwap_element.h"
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

/* Local version of nl80211 with all feature to remove the problem of frag version of nl80211 */
#include "nl80211_v3_10.h"

#include "wifi_drivers.h"
#include "wifi_nl80211.h"
#include "ieee80211.h"

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
static int nl80211_process_bss_event(struct nl_msg* msg, void* arg) {
	/* TODO */
	return NL_SKIP;
}

/* */
static void nl80211_event_receive(int fd, void* param1, void* param2) {
	int res;
	struct nl_sock* nl = (struct nl_sock*)param1;
	struct nl_cb* nl_cb = (struct nl_cb*)param2;

	/* */
	res = nl_recvmsgs(nl, nl_cb);
	if (res) {
		capwap_logging_warning("Receive nl80211 message failed: %d", res);
	}
}

/* */
static int nl80211_global_valid_handler(struct nl_msg* msg, void* arg) {
	/* TODO */
	capwap_logging_debug("nl80211_global_valid_handler");
	/* TODO */

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
								freq->channel = wifi_frequency_to_channel(frequency);

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

	/* Save device handle into global handle */
	item = capwap_itemlist_create_with_item(devicehandle, sizeof(struct nl80211_device_handle));
	item->autodelete = 0;
	capwap_itemlist_insert_after(globalhandle->devicelist, NULL, item);

	return devicehandle;
}

/* */
int nl80211_device_getfdevent(wifi_device_handle handle, struct pollfd* fds, struct wifi_event* events) {
	return 0;
}

/* */
int nl80211_device_getcapability(wifi_device_handle handle, struct wifi_capability* capability) {
	int result;
	struct nl_msg* msg;
	struct nl80211_device_handle* devicehandle = (struct nl80211_device_handle*)handle;

	ASSERT(handle != NULL);
	ASSERT(capability != NULL);

	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	genlmsg_put(msg, 0, 0, devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_GET_WIPHY, 0);
	nla_put_u32(msg, NL80211_ATTR_WIPHY, devicehandle->phyindex);

	/* Retrieve physical device capability */
	capability->device = (wifi_device_handle)devicehandle;
	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg, cb_get_phydevice_capability, capability);
	if (result) {
		capwap_logging_error("Unable retrieve physical device capability, error code: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
int nl80211_device_setfrequency(wifi_device_handle handle, struct wifi_frequency* freq) {
	int result;
	struct nl_msg* msg;
	struct nl80211_device_handle* devicehandle = (struct nl80211_device_handle*)handle;

	ASSERT(handle != NULL);
	ASSERT(freq != NULL);

	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	genlmsg_put(msg, 0, 0, devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_SET_WIPHY, 0);
	nla_put_u32(msg, NL80211_ATTR_WIPHY, devicehandle->phyindex);
	nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq->frequency);

	/* Set wifi frequency */
	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg, NULL, NULL);
	if (result) {
		capwap_logging_error("Unable retrieve physical device capability, error code: %d", result);
	}

	/* */
	nlmsg_free(msg);
	return result;
}

/* */
static void nl80211_device_deinit(wifi_device_handle handle) {
	struct nl80211_device_handle* devicehandle = (struct nl80211_device_handle*)handle;

	if (devicehandle) {
		struct capwap_list_item* search;

		/* Remove device handle from global handle */
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
static void nl80211_wlan_delete(wifi_wlan_handle handle) {
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)handle;

	ASSERT(handle != NULL);

	if (wlanhandle->headbeacon) {
		capwap_free(wlanhandle->headbeacon);
	}

	if (wlanhandle->tailbeaconlength) {
		capwap_free(wlanhandle->tailbeacon);
	}

	if (wlanhandle->virtindex) {
		nl80211_destroy_virtdevice(wlanhandle->devicehandle->globalhandle, wlanhandle->virtindex);
	}

	if (wlanhandle->nl) {
		nl_socket_free(wlanhandle->nl);
	}

	if (wlanhandle->nl_cb) {
		nl_cb_put(wlanhandle->nl_cb);
	}

	capwap_free(wlanhandle);
}

/* */
static wifi_wlan_handle nl80211_wlan_create(wifi_device_handle handle, struct wlan_init_params* params) {
	int result;
	uint32_t ifindex;
	struct nl_msg* msg;
	struct nl80211_wlan_handle* wlanhandle = NULL;
	struct nl80211_device_handle* devicehandle = (struct nl80211_device_handle*)handle;

	ASSERT(handle != NULL);
	ASSERT(params != NULL);
	ASSERT(params->ifname != NULL);
	ASSERT(params->type == WLAN_INTERFACE_AP);

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
	nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);
	nla_put_string(msg, NL80211_ATTR_IFNAME, params->ifname);

	/* */
	result = nl80211_send_and_recv_msg(devicehandle->globalhandle, msg, NULL, NULL);
	nlmsg_free(msg);

	/* Check interface */
	if (result) {
		return NULL;
	}

	ifindex = wifi_iface_index(params->ifname);
	if (!ifindex) {
		return NULL;
	}

	/* Init wlan */
	wlanhandle = (struct nl80211_wlan_handle*)capwap_alloc(sizeof(struct nl80211_wlan_handle));
	memset(wlanhandle, 0, sizeof(struct nl80211_wlan_handle));

	/* */
	wlanhandle->devicehandle = devicehandle;
	wlanhandle->virtindex = ifindex;
	strcpy(wlanhandle->virtname, params->ifname);

	/* Mac address */
	if (wifi_iface_hwaddr(devicehandle->globalhandle->sock_util, wlanhandle->virtname, wlanhandle->address)) {
		nl80211_wlan_delete((wifi_wlan_handle)wlanhandle);
		return NULL;
	}

	/* BSS management */
	wlanhandle->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!wlanhandle->nl_cb) {
		nl80211_wlan_delete((wifi_wlan_handle)wlanhandle);
		return NULL;
	}

	nl_cb_set(wlanhandle->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, nl80211_no_seq_check, NULL);
	nl_cb_set(wlanhandle->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_process_bss_event, NULL);

	wlanhandle->nl = nl_create_handle(wlanhandle->nl_cb);
	if (wlanhandle->nl) {
		wlanhandle->nl_fd = nl_socket_get_fd(wlanhandle->nl);
	} else {
		nl80211_wlan_delete((wifi_wlan_handle)wlanhandle);
		return NULL;
	}

	return wlanhandle;
}

/* */
static int nl80211_wlan_getfdevent(wifi_wlan_handle handle, struct pollfd* fds, struct wifi_event* events) {
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)handle;

	ASSERT(handle != NULL);

	if (fds) {
		fds[0].fd = wlanhandle->nl_fd;
		fds[0].events = POLLIN | POLLERR | POLLHUP;
	}

	if (events) {
		events[0].event_handler = nl80211_event_receive;
		events[0].param1 = (void*)wlanhandle->nl;
		events[0].param2 = (void*)wlanhandle->nl_cb;
	}

	return 1;
}

/* */
static int nl80211_wlan_setupap(wifi_wlan_handle handle, struct wlan_setupap_params* params) {
	int i;
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)handle;
	static const int stypes[] = {
		IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOC_REQ,
		IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_REASSOC_REQ,
		IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_PROBE_REQ,
		IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DISASSOC,
		IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTH,
		IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTH,
		IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ACTION
	};

	ASSERT(handle != NULL);

	/* Register frames */
	for (i = 0; i < sizeof(stypes) / sizeof(stypes[0]); i++) {
		nl80211_registerframe(wlanhandle, (IEEE80211_FRAMECONTROL_TYPE_MGMT << 2) | (stypes[i] << 4), NULL, 0);
	}

	/* Save wireless configuration */
	wlanhandle->headbeaconlength = params->headbeaconlength;
	if (params->headbeaconlength) {
		wlanhandle->headbeacon = capwap_clone(params->headbeacon, params->headbeaconlength);
	}

	wlanhandle->tailbeaconlength = params->tailbeaconlength;
	if (params->tailbeaconlength) {
		wlanhandle->tailbeacon = capwap_clone(params->tailbeacon, params->tailbeaconlength);
	}

	strcpy(wlanhandle->ssid, params->ssid);
	wlanhandle->suppressssid = (params->suppressssid ? NL80211_HIDDEN_SSID_ZERO_LEN : NL80211_HIDDEN_SSID_NOT_IN_USE);

	wlanhandle->beaconinterval = (uint32_t)params->beaconinterval;
	wlanhandle->dtimperiod = (uint32_t)params->dtimperiod;
	wlanhandle->authenticationtype = ((params->authenticationtype == CAPWAP_ADD_WLAN_AUTHTYPE_WEP) ? NL80211_AUTHTYPE_SHARED_KEY : NL80211_AUTHTYPE_OPEN_SYSTEM);

	return 0;
}

/* */
static int nl80211_wlan_startap(wifi_wlan_handle handle) {
	int result;
	struct nl_msg* msg;
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)handle;

	/* Enable interface */
	if (wifi_iface_up(wlanhandle->devicehandle->globalhandle->sock_util, wlanhandle->virtname)) {
		return -1;
	}

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_START_AP, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlanhandle->virtindex);
	nla_put(msg, NL80211_ATTR_BEACON_HEAD, wlanhandle->headbeaconlength, wlanhandle->headbeacon);
	nla_put(msg, NL80211_ATTR_BEACON_TAIL, wlanhandle->tailbeaconlength, wlanhandle->tailbeacon);
	nla_put_u32(msg, NL80211_ATTR_BEACON_INTERVAL, wlanhandle->beaconinterval);
	nla_put_u32(msg, NL80211_ATTR_DTIM_PERIOD, wlanhandle->dtimperiod);
	nla_put(msg, NL80211_ATTR_SSID, strlen(wlanhandle->ssid), wlanhandle->ssid);
	nla_put_u32(msg, NL80211_ATTR_HIDDEN_SSID, wlanhandle->suppressssid);
	nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE, wlanhandle->authenticationtype);
	nla_put_flag(msg, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);

	/* Start AP */
	result = nl80211_send_and_recv_msg(wlanhandle->devicehandle->globalhandle, msg, NULL, NULL);
	nlmsg_free(msg);

	return result;
}

/* */
static int nl80211_wlan_stopap(wifi_wlan_handle handle) {
	int result;
	struct nl_msg* msg;
	struct nl80211_wlan_handle* wlanhandle = (struct nl80211_wlan_handle*)handle;

	/* */
	msg = nlmsg_alloc();
	if (!msg) {
		return -1;
	}

	/* */
	genlmsg_put(msg, 0, 0, wlanhandle->devicehandle->globalhandle->nl80211_id, 0, 0, NL80211_CMD_STOP_AP, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, wlanhandle->virtindex);

	/* Stop AP */
	result = nl80211_send_and_recv_msg(wlanhandle->devicehandle->globalhandle, msg, NULL, NULL);
	nlmsg_free(msg);

	/* Disable interface */
	if (wifi_iface_down(wlanhandle->devicehandle->globalhandle->sock_util, wlanhandle->virtname)) {
		return -1;
	}

	return result;
}

/* */
int nl80211_wlan_getmacaddress(wifi_wlan_handle handle, uint8_t* address) {
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
		capwap_logging_warning("Unable to found mac80211 kernel module: %s", nl_geterror());
		nl80211_global_deinit((wifi_global_handle)globalhandle);
		return NULL;
	}

	/* Configure global callback function */
	nl_cb_set(globalhandle->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, nl80211_no_seq_check, NULL);
	nl_cb_set(globalhandle->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_global_valid_handler, globalhandle);

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
	return 0;
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
	.device_setfrequency = nl80211_device_setfrequency,
	.device_deinit = nl80211_device_deinit,
	.wlan_create = nl80211_wlan_create,
	.wlan_getfdevent = nl80211_wlan_getfdevent,
	.wlan_setupap = nl80211_wlan_setupap,
	.wlan_startap = nl80211_wlan_startap,
	.wlan_stopap = nl80211_wlan_stopap,
	.wlan_getmacaddress = nl80211_wlan_getmacaddress,
	.wlan_delete = nl80211_wlan_delete
};
