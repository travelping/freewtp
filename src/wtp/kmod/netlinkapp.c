#include "config.h"
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/rcupdate.h>
#include <linux/err.h>
#include <net/mac80211.h>
#include <linux/ieee80211.h>
#include "nlsmartcapwap.h"
#include "netlinkapp.h"
#include "capwap.h"

/* */
struct sc_netlink_device {
	struct list_head list;
	struct ieee80211_pcktunnel pcktunnel_handler;

	uint32_t ifindex;
	uint8_t radioid;
	uint8_t wlanid;
	uint8_t binding;
	struct net_device* dev;
	uint32_t flags;
};

/* */
static uint32_t sc_netlink_usermodeid;
static LIST_HEAD(sc_netlink_dev_list);

/* */
static int sc_netlink_pre_doit(__genl_const struct genl_ops* ops, struct sk_buff* skb, struct genl_info* info) {
	TRACEKMOD("### sc_netlink_pre_doit\n");

	rtnl_lock();
	return 0;
}

/* */
static void sc_netlink_post_doit(__genl_const struct genl_ops* ops, struct sk_buff* skb, struct genl_info* info) {
	TRACEKMOD("### sc_netlink_post_doit\n");

	rtnl_unlock();
}

/* Netlink Family */
static struct genl_family sc_netlink_family = {
	.id = GENL_ID_GENERATE,
	.name = NLSMARTCAPWAP_GENL_NAME,
	.hdrsize = 0,
	.version = 1,
	.maxattr = NLSMARTCAPWAP_ATTR_MAX,
	.netnsok = true,
	.pre_doit = sc_netlink_pre_doit,
	.post_doit = sc_netlink_post_doit,
};

/* */
static int sc_netlink_handler(uint32_t ifindex, struct sk_buff* skb, int sig_dbm, unsigned char rate, void* data) {
	int ret = 0;
	struct sc_netlink_device* nldev = (struct sc_netlink_device*)data;
	struct ieee80211_hdr* hdr = (struct ieee80211_hdr*)skb->data;

	TRACEKMOD("### sc_netlink_handler\n");

	/* IEEE802.11 Data Packet */
	if (ieee80211_is_data(hdr->frame_control)) {
		int err;
		struct sc_capwap_session* session;
		uint8_t radioaddrbuffer[CAPWAP_RADIO_EUI48_LENGTH_PADDED];
		uint8_t winfobuffer[CAPWAP_WINFO_FRAMEINFO_LENGTH_PADDED];
		struct sc_capwap_radio_addr* radioaddr = NULL;
		struct sc_capwap_wireless_information* winfo = NULL;

		printk("*** receive packet\n");

		/* Drop packet */
		ret = -1;

		/* */
		session = sc_capwap_getsession(NULL);
		if (!session) {
			goto error;
		}

		/* IEEE 802.11 into IEEE 802.3 */
		if (nldev->flags & NLSMARTCAPWAP_FLAGS_TUNNEL_8023) {
			if (ieee80211_data_to_8023(skb, nldev->dev->dev_addr, NL80211_IFTYPE_AP)) {
				printk("*** convertion error\n");
				goto error;
			}

			/* Create Radio Mac Address */
			radioaddr = sc_capwap_setradiomacaddress(radioaddrbuffer, CAPWAP_RADIO_EUI48_LENGTH_PADDED, nldev->dev->dev_addr);
		}

		/* Create Wireless Information */
		if (sig_dbm || rate) {
			winfo = sc_capwap_setwinfo_frameinfo(winfobuffer, CAPWAP_WINFO_FRAMEINFO_LENGTH_PADDED, (uint8_t)sig_dbm, 0, ((uint16_t)rate) * 5);
		}

		/* */
		CAPWAP_SKB_CB(skb)->flags = SKB_CAPWAP_FLAG_FROM_IEEE80211;

		/* Forward to AC */
		err = sc_capwap_forwarddata(session, nldev->radioid, nldev->binding, skb, nldev->flags, radioaddr, (radioaddr ? CAPWAP_RADIO_EUI48_LENGTH_PADDED : 0), winfo, (winfo ? CAPWAP_WINFO_FRAMEINFO_LENGTH_PADDED : 0));
		printk("*** send: %d\n", err);
	}

error:
	return ret;
}

/* */
static struct sc_netlink_device* sc_netlink_new_device(uint32_t ifindex, uint8_t radioid, u8 wlanid, uint8_t binding) {
	struct net_device* dev;
	struct sc_netlink_device* nldev;

	TRACEKMOD("### sc_netlink_new_device\n");

	/* Retrieve device from ifindex */
	dev = dev_get_by_index(&init_net, ifindex);
	if (!dev) {
		return NULL;
	}

	/* Check if wireless device */
	if (!dev->ieee80211_ptr || !dev->ieee80211_ptr->wiphy) {
		dev_put(dev);
		return NULL;
	}

	/* Create device */
	nldev = (struct sc_netlink_device*)kzalloc(sizeof(struct sc_netlink_device), GFP_KERNEL);
	if (!nldev) {
		dev_put(dev);
		return NULL;
	}

	/* Initialize device */
	nldev->pcktunnel_handler.handler = sc_netlink_handler;
	nldev->pcktunnel_handler.data = (void*)nldev;
	nldev->ifindex = ifindex;
	nldev->radioid = radioid;
	nldev->wlanid = wlanid;
	nldev->binding = binding;
	nldev->dev = dev;

	return nldev;
}

/* */
static void sc_netlink_free_device(struct sc_netlink_device* nldev) {
	TRACEKMOD("### sc_netlink_free_device\n");

	/* Disconnect device from mac80211 */
	ieee80211_pcktunnel_deregister(nldev->dev, &nldev->pcktunnel_handler);

	/* */
	dev_put(nldev->dev);

	/* Free memory */
	kfree(nldev);
}

/* */
static struct sc_netlink_device* sc_netlink_register_device(uint32_t ifindex, uint8_t radioid, uint16_t wlanid, uint8_t binding) {
	struct sc_netlink_device* nldev;

	TRACEKMOD("### sc_netlink_register_device\n");

	ASSERT_RTNL();

	/* */
	if (!IS_VALID_RADIOID(radioid) || !IS_VALID_WLANID(wlanid)) {
		return NULL;
	}

	/* Search device */
	list_for_each_entry(nldev, &sc_netlink_dev_list, list) {
		if (nldev->ifindex == ifindex) {
			return NULL;
		}
	}

	/* Create device */
	nldev = sc_netlink_new_device(ifindex, radioid, wlanid, binding);
	if (nldev) {
		list_add_rcu(&nldev->list, &sc_netlink_dev_list);
	}

	return nldev;
}

/* */
static int sc_netlink_unregister_device(uint32_t ifindex) {
	int ret = -ENODEV;
	struct sc_netlink_device* nldev;

	TRACEKMOD("### sc_netlink_unregister_device\n");

	ASSERT_RTNL();

	/* Search device */
	list_for_each_entry(nldev, &sc_netlink_dev_list, list) {
		if (nldev->ifindex == ifindex) {
			/* Remove from list */
			list_del_rcu(&nldev->list);
			synchronize_net();

			/* Free device */
			ret = 0;
			sc_netlink_free_device(nldev);
			break;
		}
	}

	return ret;
}

/* */
static void sc_netlink_unregister_alldevice(void) {
	struct sc_netlink_device* tmp;
	struct sc_netlink_device* nldev;

	TRACEKMOD("### sc_netlink_unregister_alldevice\n");

	ASSERT_RTNL();

	/* Close all devices */
	list_for_each_entry_safe(nldev, tmp, &sc_netlink_dev_list, list) {
		/* Remove from list */
		list_del_rcu(&nldev->list);
		synchronize_net();

		/* Free device */
		sc_netlink_free_device(nldev);
	}
}


/* */
static int sc_netlink_link(struct sk_buff* skb, struct genl_info* info) {
	int ret;
	uint32_t portid = genl_info_snd_portid(info);

	TRACEKMOD("### sc_netlink_link\n");

	if (!sc_netlink_usermodeid) {
		/* Initialize library */
		ret = sc_capwap_init(1);
		if (!ret) {
			sc_netlink_usermodeid = portid;

			/* Deny unload module */
			try_module_get(THIS_MODULE);
		}
	} else if (sc_netlink_usermodeid == portid) {
		ret = -EALREADY;
	} else {
		ret = -EBUSY;
	}

	return ret;
}

/* */
static int sc_netlink_reset(struct sk_buff* skb, struct genl_info* info) {
	/* Check Link */
	if (sc_netlink_usermodeid != genl_info_snd_portid(info)) {
		return -ENOLINK;
	}

	/* Close all devices */
	sc_netlink_unregister_alldevice();

	/* Reset session */
	sc_capwap_resetsession();

	return 0;
}

/* */
static int sc_netlink_notify(struct notifier_block* nb, unsigned long state, void* _notify) {
	struct netlink_notify* notify = (struct netlink_notify*)_notify;

	if (state == NETLINK_URELEASE) {
		rtnl_lock();

		if (sc_netlink_usermodeid == netlink_notify_portid(notify)) {
			sc_netlink_usermodeid = 0;

			/* Close all devices */
			sc_netlink_unregister_alldevice();

			/* Close capwap engine */
			sc_capwap_close();

			/* Allow unload module */
			module_put(THIS_MODULE);
		}

		rtnl_unlock();
	}

	return NOTIFY_DONE;
}

/* */
static int sc_netlink_bind(struct sk_buff* skb, struct genl_info* info) {
	union capwap_addr sockaddr;

	TRACEKMOD("### sc_netlink_bind\n");

	/* Check Link */
	if (sc_netlink_usermodeid != genl_info_snd_portid(info)) {
		return -ENOLINK;
	}

	/* Get bind address */
	if (!info->attrs[NLSMARTCAPWAP_ATTR_ADDRESS] || (nla_len(info->attrs[NLSMARTCAPWAP_ATTR_ADDRESS]) != sizeof(struct sockaddr_storage))) {
		return -EINVAL;
	}

	memcpy(&sockaddr.ss, nla_data(info->attrs[NLSMARTCAPWAP_ATTR_ADDRESS]), sizeof(struct sockaddr_storage));
	if ((sockaddr.ss.ss_family != AF_INET) && (sockaddr.ss.ss_family != AF_INET6)) {
		return -EINVAL;
	}

	/* Bind socket */
	return sc_capwap_bind(&sockaddr);
}

/* */
static int sc_netlink_connect(struct sk_buff* skb, struct genl_info* info) {
	int ret;
	union capwap_addr sockaddr;
	struct sc_capwap_sessionid_element sessionid;
	uint16_t mtu = DEFAULT_MTU;

	TRACEKMOD("### sc_netlink_connect\n");

	/* Check Link */
	if (sc_netlink_usermodeid != genl_info_snd_portid(info)) {
		return -ENOLINK;
	}

	/* Get AC address */
	if (!info->attrs[NLSMARTCAPWAP_ATTR_ADDRESS] || (nla_len(info->attrs[NLSMARTCAPWAP_ATTR_ADDRESS]) != sizeof(struct sockaddr_storage))) {
		return -EINVAL;
	}

	memcpy(&sockaddr.ss, nla_data(info->attrs[NLSMARTCAPWAP_ATTR_ADDRESS]), sizeof(struct sockaddr_storage));
	if ((sockaddr.ss.ss_family != AF_INET) && (sockaddr.ss.ss_family != AF_INET6)) {
		return -EINVAL;
	}

	/* Get MTU */
	if (info->attrs[NLSMARTCAPWAP_ATTR_MTU]) {
		mtu = nla_get_u16(info->attrs[NLSMARTCAPWAP_ATTR_MTU]);
		if ((mtu < MIN_MTU) || (mtu > MAX_MTU)) {
			return -EINVAL;
		}
	}

	/* Get Session ID */
	if (info->attrs[NLSMARTCAPWAP_ATTR_SESSION_ID] && (nla_len(info->attrs[NLSMARTCAPWAP_ATTR_SESSION_ID]) == sizeof(struct sc_capwap_sessionid_element))) {
		memcpy(sessionid.id, nla_data(info->attrs[NLSMARTCAPWAP_ATTR_SESSION_ID]), sizeof(struct sc_capwap_sessionid_element));
	} else {
		return -EINVAL;
	}

	/* Send packet */
	ret = sc_capwap_connect(&sockaddr, &sessionid, mtu);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

/* */
static int sc_netlink_send_keepalive(struct sk_buff* skb, struct genl_info* info) {
	int ret;

	TRACEKMOD("### sc_netlink_send_keepalive\n");

	/* Check Link */
	if (sc_netlink_usermodeid != genl_info_snd_portid(info)) {
		return -ENOLINK;
	}

	/* Send packet */
	ret = sc_capwap_sendkeepalive();
	if (ret < 0) {
		return ret;
	}

	return 0;
}

/* */
static int sc_netlink_send_data(struct sk_buff* skb, struct genl_info* info) {
	int ret;
	uint8_t radioid;
	uint8_t binding;
	uint8_t rssi = 0;
	uint8_t snr = 0;
	uint16_t rate = 0;
	int length;
	struct sk_buff* skbdata;
	struct sc_capwap_session* session;
	unsigned char winfobuffer[CAPWAP_WINFO_FRAMEINFO_LENGTH_PADDED];
	struct sc_capwap_wireless_information* winfo = NULL;

	TRACEKMOD("### sc_netlink_send_data\n");

	/* Check Link */
	if (sc_netlink_usermodeid != genl_info_snd_portid(info)) {
		return -ENOLINK;
	} else if (!info->attrs[NLSMARTCAPWAP_ATTR_RADIOID] || !info->attrs[NLSMARTCAPWAP_ATTR_DATA_FRAME]) {
		return -EINVAL;
	}

	/* */
	session = sc_capwap_getsession(NULL);
	if (!session) {
		return -ENOLINK;
	}

	/* Get radioid */
	radioid = nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_RADIOID]);
	if (!IS_VALID_RADIOID(radioid) || !info->attrs[NLSMARTCAPWAP_ATTR_BINDING]) {
		return -EINVAL;
	}

	/* Get binding */
	binding = nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_BINDING]);

	/* Get RSSI */
	if (info->attrs[NLSMARTCAPWAP_ATTR_RSSI]) {
		rssi = nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_RSSI]);
	}

	/* Get SNR */
	if (info->attrs[NLSMARTCAPWAP_ATTR_SNR]) {
		snr = nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_SNR]);
	}

	/* Get RATE */
	if (info->attrs[NLSMARTCAPWAP_ATTR_RATE]) {
		rate = nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_RATE]);
	}

	/* Create Wireless Information */
	if (rssi || snr || rate) {
		winfo = sc_capwap_setwinfo_frameinfo(winfobuffer, CAPWAP_WINFO_FRAMEINFO_LENGTH_PADDED, rssi, snr, rate);
	}

	/* Create socket buffer */
	length = nla_len(info->attrs[NLSMARTCAPWAP_ATTR_DATA_FRAME]);
	skbdata = alloc_skb(length + CAPWAP_HEADER_MAX_LENGTH, GFP_KERNEL);
	if (!skbdata) {
		return -ENOMEM;
	}

	/* Reserve space for Capwap Header */
	skb_reserve(skbdata, CAPWAP_HEADER_MAX_LENGTH);

	/* Copy data into socket buffer */
	memcpy(skb_put(skbdata, length), nla_data(info->attrs[NLSMARTCAPWAP_ATTR_DATA_FRAME]), length);

	/* */
	CAPWAP_SKB_CB(skb)->flags = SKB_CAPWAP_FLAG_FROM_USER_SPACE;

	/* Send packet */
	ret = sc_capwap_forwarddata(session, radioid, binding, skbdata, 0, NULL, 0, winfo, (winfo ? CAPWAP_WINFO_FRAMEINFO_LENGTH_PADDED : 0));
	if (ret) {
		TRACEKMOD("*** Unable send packet from sc_netlink_send_data function\n");
	}

	kfree_skb(skbdata);
	return ret;
}

/* */
static int sc_netlink_join_mac80211_device(struct sk_buff* skb, struct genl_info* info) {
	int ret;
	uint32_t ifindex;
	struct sc_netlink_device* nldev;

	TRACEKMOD("### sc_netlink_join_mac80211_device\n");

	/* Check Link */
	if (sc_netlink_usermodeid != genl_info_snd_portid(info)) {
		return -ENOLINK;
	}

	/* Get interface index */
	if (!info->attrs[NLSMARTCAPWAP_ATTR_IFINDEX]) {
		return -EINVAL;
	}

	ifindex = nla_get_u32(info->attrs[NLSMARTCAPWAP_ATTR_IFINDEX]);
	if (!ifindex) {
		return -EINVAL;
	}

	/* Check */
	if (!info->attrs[NLSMARTCAPWAP_ATTR_RADIOID] || !info->attrs[NLSMARTCAPWAP_ATTR_WLANID] || !info->attrs[NLSMARTCAPWAP_ATTR_BINDING]) {
		return -EINVAL;
	}

	/* Register device */
	nldev = sc_netlink_register_device(ifindex, nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_RADIOID]), nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_WLANID]), nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_BINDING]));
	if (!nldev) {
		return -EINVAL;
	}

	/* */
	if (info->attrs[NLSMARTCAPWAP_ATTR_FLAGS]) {
		nldev->flags = nla_get_u32(info->attrs[NLSMARTCAPWAP_ATTR_FLAGS]);
	}

	/* Set subtype masking */
	if (info->attrs[NLSMARTCAPWAP_ATTR_MGMT_SUBTYPE_MASK]) {
		nldev->pcktunnel_handler.subtype_mask[0] = nla_get_u16(info->attrs[NLSMARTCAPWAP_ATTR_MGMT_SUBTYPE_MASK]);
	}

	if (info->attrs[NLSMARTCAPWAP_ATTR_CTRL_SUBTYPE_MASK]) {
		nldev->pcktunnel_handler.subtype_mask[1] = nla_get_u16(info->attrs[NLSMARTCAPWAP_ATTR_CTRL_SUBTYPE_MASK]);
	}

	if (info->attrs[NLSMARTCAPWAP_ATTR_DATA_SUBTYPE_MASK]) {
		nldev->pcktunnel_handler.subtype_mask[2] = nla_get_u16(info->attrs[NLSMARTCAPWAP_ATTR_DATA_SUBTYPE_MASK]);
	}

	/* Connect device to mac80211 */
	ret = ieee80211_pcktunnel_register(nldev->dev, &nldev->pcktunnel_handler);
	if (ret) {
		sc_netlink_unregister_device(ifindex);
	}

	return ret;
}

/* */
static int sc_netlink_leave_mac80211_device(struct sk_buff* skb, struct genl_info* info) {
	TRACEKMOD("### sc_netlink_leave_mac80211_device\n");

	/* Check Link */
	if (sc_netlink_usermodeid != genl_info_snd_portid(info)) {
		return -ENOLINK;
	}

	/* Get interface index */
	if (!info->attrs[NLSMARTCAPWAP_ATTR_IFINDEX]) {
		return -EINVAL;
	}

	/* Unregister device */
	return sc_netlink_unregister_device(nla_get_u32(info->attrs[NLSMARTCAPWAP_ATTR_IFINDEX]));
}

/* */
static int sc_device_event(struct notifier_block* unused, unsigned long event, void* ptr) {
	struct net_device* dev = netdev_notifier_info_to_dev(ptr);

	/* Check event only if connect with WTP userspace */
	if (!sc_netlink_usermodeid) {
		return NOTIFY_DONE;
	}

	/* */
	switch (event) {
		case NETDEV_UNREGISTER: {
			/* Try to unregister device */
			sc_netlink_unregister_device(dev->ifindex);
			break;
		}
	}

	return NOTIFY_DONE;
}

/* */
static const struct nla_policy sc_netlink_policy[NLSMARTCAPWAP_ATTR_MAX + 1] = {
	[NLSMARTCAPWAP_ATTR_IFINDEX] = { .type = NLA_U32 },
	[NLSMARTCAPWAP_ATTR_RADIOID] = { .type = NLA_U8 },
	[NLSMARTCAPWAP_ATTR_WLANID] = { .type = NLA_U8 },
	[NLSMARTCAPWAP_ATTR_BINDING] = { .type = NLA_U8 },
	[NLSMARTCAPWAP_ATTR_FLAGS] = { .type = NLA_U32 },
	[NLSMARTCAPWAP_ATTR_MGMT_SUBTYPE_MASK] = { .type = NLA_U16 },
	[NLSMARTCAPWAP_ATTR_CTRL_SUBTYPE_MASK] = { .type = NLA_U16 },
	[NLSMARTCAPWAP_ATTR_DATA_SUBTYPE_MASK] = { .type = NLA_U16 },
	[NLSMARTCAPWAP_ATTR_ADDRESS] = { .type = NLA_BINARY, .len = sizeof(struct sockaddr_storage) },
	[NLSMARTCAPWAP_ATTR_MTU] = { .type = NLA_U16 },
	[NLSMARTCAPWAP_ATTR_SESSION_ID] = { .type = NLA_BINARY, .len = sizeof(struct sc_capwap_sessionid_element) },
	[NLSMARTCAPWAP_ATTR_DTLS] = { .type = NLA_U16 },
	[NLSMARTCAPWAP_ATTR_DATA_FRAME] = { .type = NLA_BINARY, .len = IEEE80211_MTU },
	[NLSMARTCAPWAP_ATTR_RSSI] = { .type = NLA_U8 },
	[NLSMARTCAPWAP_ATTR_SNR] = { .type = NLA_U8 },
	[NLSMARTCAPWAP_ATTR_RATE] = { .type = NLA_U16 },

};

/* Netlink Ops */
static __genl_const struct genl_ops sc_netlink_ops[] = {
	{
		.cmd = NLSMARTCAPWAP_CMD_LINK,
		.doit = sc_netlink_link,
		.policy = sc_netlink_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NLSMARTCAPWAP_CMD_BIND,
		.doit = sc_netlink_bind,
		.policy = sc_netlink_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NLSMARTCAPWAP_CMD_CONNECT,
		.doit = sc_netlink_connect,
		.policy = sc_netlink_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NLSMARTCAPWAP_CMD_RESET,
		.doit = sc_netlink_reset,
		.policy = sc_netlink_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NLSMARTCAPWAP_CMD_SEND_KEEPALIVE,
		.doit = sc_netlink_send_keepalive,
		.policy = sc_netlink_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NLSMARTCAPWAP_CMD_SEND_DATA,
		.doit = sc_netlink_send_data,
		.policy = sc_netlink_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NLSMARTCAPWAP_CMD_JOIN_MAC80211_DEVICE,
		.doit = sc_netlink_join_mac80211_device,
		.policy = sc_netlink_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NLSMARTCAPWAP_CMD_LEAVE_MAC80211_DEVICE,
		.doit = sc_netlink_leave_mac80211_device,
		.policy = sc_netlink_policy,
		.flags = GENL_ADMIN_PERM,
	},
};

/* Netlink notify */
static struct notifier_block sc_netlink_notifier = {
	.notifier_call = sc_netlink_notify,
};

/* Interface notify */
struct notifier_block sc_device_notifier = {
	.notifier_call = sc_device_event
};

/* */
int sc_netlink_notify_recv_keepalive(const union capwap_addr* sockaddr, struct sc_capwap_sessionid_element* sessionid) {
	void* msg;
	struct sk_buff* sk_msg;

	TRACEKMOD("### sc_netlink_notify_recv_keepalive\n");

	/* Alloc message */
	sk_msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!sk_msg) {
		return -ENOMEM;
	}

	/* Set command */
	msg = genlmsg_put(sk_msg, 0, 0, &sc_netlink_family, 0, NLSMARTCAPWAP_CMD_RECV_KEEPALIVE);
	if (!msg) {
		nlmsg_free(sk_msg);
		return -ENOMEM;
	}

	/* Send message */
	genlmsg_end(sk_msg, msg);
	return genlmsg_unicast(&init_net, sk_msg, sc_netlink_usermodeid);
}

/* */
int sc_netlink_notify_recv_data(uint8_t* packet, int length) {
	void* msg;
	struct sk_buff* sk_msg;

	TRACEKMOD("### sc_netlink_notify_recv_data\n");

	/* Alloc message */
	sk_msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!sk_msg) {
		return -ENOMEM;
	}

	/* Set command */
	msg = genlmsg_put(sk_msg, 0, 0, &sc_netlink_family, 0, NLSMARTCAPWAP_CMD_RECV_DATA);
	if (!msg) {
		goto error;
	}

	/* */
	if (nla_put(sk_msg, NLSMARTCAPWAP_ATTR_DATA_FRAME, length, packet)) {
		goto error2;
	}

	/* Send message */
	genlmsg_end(sk_msg, msg);
	return genlmsg_unicast(&init_net, sk_msg, sc_netlink_usermodeid);

error2:
	genlmsg_cancel(sk_msg, msg);

error:
	nlmsg_free(sk_msg);
	return -ENOMEM;
}

/* */
struct net_device* sc_netlink_getdev_from_wlanid(uint8_t radioid, uint8_t wlanid) {
	struct sc_netlink_device* nldev;

	TRACEKMOD("### sc_netlink_getdev_from_wlanid\n");

	/* Search */
	list_for_each_entry(nldev, &sc_netlink_dev_list, list) {
		if ((nldev->radioid == radioid) && (nldev->wlanid == wlanid)) {
			return nldev->dev;
		}
	}

	return NULL;
}

/* */
struct net_device* sc_netlink_getdev_from_bssid(uint8_t radioid, const uint8_t* addr) {
	struct sc_netlink_device* nldev;

	TRACEKMOD("### sc_netlink_getdev_from_bssid\n");

	/* Search */
	list_for_each_entry(nldev, &sc_netlink_dev_list, list) {
		if ((nldev->radioid == radioid) && !memcmp(nldev->dev->dev_addr, addr, MACADDRESS_EUI48_LENGTH)) {
			return nldev->dev;
		}
	}

	return NULL;
}

/* */
int sc_netlink_init(void) {
	int ret;

	TRACEKMOD("### sc_netlink_init\n");

	/* */
	sc_netlink_usermodeid = 0;

	/* Register interface event */
	ret = register_netdevice_notifier(&sc_device_notifier);
	if (ret) {
		goto error;
	}

	/* Register netlink family */
	ret = genl_register_family_with_ops(&sc_netlink_family, sc_netlink_ops);
	if (ret) {
		goto error2;
	}

	/* Register netlink notifier */
	ret = netlink_register_notifier(&sc_netlink_notifier);
	if (ret) {
		goto error3;
	}

	return 0;

error3:
	genl_unregister_family(&sc_netlink_family);
error2:
	unregister_netdevice_notifier(&sc_device_notifier);
error:
	return ret;
}

/* */
void sc_netlink_exit(void) {
	TRACEKMOD("### sc_netlink_exit\n");

	netlink_unregister_notifier(&sc_netlink_notifier);
	genl_unregister_family(&sc_netlink_family);
	unregister_netdevice_notifier(&sc_device_notifier);
}
