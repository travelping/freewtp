#include "config.h"

#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/rcupdate.h>
#include <linux/err.h>
#include <linux/ieee80211.h>
#include <linux/jhash.h>

#include <net/net_namespace.h>
#include <net/genetlink.h>
#include <net/mac80211.h>
#include <net/netns/generic.h>

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
	struct net *net;
	uint32_t flags;
};

/* */
static int sc_net_id __read_mostly;

struct sc_net {
	uint32_t sc_netlink_usermodeid;

	struct sc_capwap_session sc_acsession;
	struct list_head sc_netlink_dev_list;
};

/* */
static int sc_netlink_pre_doit(const struct genl_ops* ops, struct sk_buff* skb, struct genl_info* info) {
	TRACEKMOD("### sc_netlink_pre_doit\n");

	rtnl_lock();
	return 0;
}

/* */
static void sc_netlink_post_doit(const struct genl_ops* ops, struct sk_buff* skb, struct genl_info* info) {
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
static int sc_netlink_handler(uint32_t ifindex, struct sk_buff* skb,
			      int sig_dbm, unsigned char rate, void* data)
{
	int ret = 0;
	struct sc_netlink_device* nldev = (struct sc_netlink_device*)data;
        struct sc_net *sn = net_generic(nldev->net, sc_net_id);
	struct ieee80211_hdr* hdr = (struct ieee80211_hdr*)skb->data;

	TRACEKMOD("### sc_netlink_handler\n");

	/* IEEE802.11 Data Packet */
	if (ieee80211_is_data(hdr->frame_control)) {
		int err;
		uint8_t radioaddrbuffer[CAPWAP_RADIO_EUI48_LENGTH_PADDED];
		uint8_t winfobuffer[CAPWAP_WINFO_FRAMEINFO_LENGTH_PADDED];
		struct sc_capwap_radio_addr* radioaddr = NULL;
		struct sc_capwap_wireless_information* winfo = NULL;

		/* Drop packet */
		ret = -1;

		/* IEEE 802.11 into IEEE 802.3 */
		if (nldev->flags & NLSMARTCAPWAP_FLAGS_TUNNEL_8023) {
			if (ieee80211_data_to_8023(skb, nldev->dev->dev_addr, NL80211_IFTYPE_AP)) {
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
		err = sc_capwap_forwarddata(&sn->sc_acsession, nldev->radioid, nldev->binding, skb, nldev->flags, radioaddr, (radioaddr ? CAPWAP_RADIO_EUI48_LENGTH_PADDED : 0), winfo, (winfo ? CAPWAP_WINFO_FRAMEINFO_LENGTH_PADDED : 0));
	}

error:
	return ret;
}

/* */
static struct sc_netlink_device* sc_netlink_new_device(struct net *net, uint32_t ifindex,
						       uint8_t radioid, u8 wlanid, uint8_t binding)
{
	struct net_device* dev;
	struct sc_netlink_device* nldev;

	TRACEKMOD("### sc_netlink_new_device\n");

	/* Retrieve device from ifindex */
	dev = dev_get_by_index(net, ifindex);
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
	nldev->net = net;

	return nldev;
}

/* */
static void sc_netlink_free_device(struct sc_netlink_device* nldev)
{
	TRACEKMOD("### sc_netlink_free_device\n");

	/* Disconnect device from mac80211 */
	ieee80211_pcktunnel_deregister(nldev->dev, &nldev->pcktunnel_handler);

	/* */
	dev_put(nldev->dev);

	/* Free memory */
	kfree(nldev);
}

/* */
static struct sc_netlink_device *
sc_netlink_register_device(struct net *net, uint32_t ifindex, uint8_t radioid,
			   uint16_t wlanid, uint8_t binding)
{
        struct sc_net *sn = net_generic(net, sc_net_id);
	struct sc_netlink_device* nldev;

	TRACEKMOD("### sc_netlink_register_device\n");

	ASSERT_RTNL();

	/* */
	if (!IS_VALID_RADIOID(radioid) || !IS_VALID_WLANID(wlanid)) {
		return NULL;
	}

	/* Search device */
	list_for_each_entry(nldev, &sn->sc_netlink_dev_list, list) {
		if (nldev->ifindex == ifindex) {
			return NULL;
		}
	}

	/* Create device */
	nldev = sc_netlink_new_device(net, ifindex, radioid, wlanid, binding);
	if (nldev) {
		list_add_rcu(&nldev->list, &sn->sc_netlink_dev_list);
	}

	return nldev;
}

/* */
static int sc_netlink_unregister_device(struct sc_net *sn, uint32_t ifindex)
{
	int ret = -ENODEV;
	struct sc_netlink_device* nldev;

	TRACEKMOD("### sc_netlink_unregister_device\n");

	ASSERT_RTNL();

	/* Search device */
	list_for_each_entry(nldev, &sn->sc_netlink_dev_list, list) {
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
static void sc_netlink_unregister_alldevice(struct sc_net *sn) {
	struct sc_netlink_device* tmp;
	struct sc_netlink_device* nldev;

	TRACEKMOD("### sc_netlink_unregister_alldevice\n");

	ASSERT_RTNL();

	/* Close all devices */
	list_for_each_entry_safe(nldev, tmp, &sn->sc_netlink_dev_list, list) {
		/* Remove from list */
		list_del_rcu(&nldev->list);
		synchronize_net();

		/* Free device */
		sc_netlink_free_device(nldev);
	}
}

/* */
static int sc_netlink_link(struct sk_buff* skb, struct genl_info* info)
{
	struct net *net = genl_info_net(info);
	struct sc_net *sn = net_generic(net, sc_net_id);
	int ret;

	TRACEKMOD("### sc_netlink_link\n");

	/* */
	if (sn->sc_netlink_usermodeid) {
		TRACEKMOD("*** Busy kernel link\n");
		return -EBUSY;
	}

	/* Initialize library */
	ret = sc_capwap_init(&sn->sc_acsession, net);
	if (ret) {
		return ret;
	}

	/* Deny unload module */
	sn->sc_netlink_usermodeid = info->snd_portid;
	try_module_get(THIS_MODULE);

	return 0;
}

/* */
static int sc_netlink_reset(struct sk_buff* skb, struct genl_info* info)
{
	struct net *net = genl_info_net(info);
	struct sc_net *sn = net_generic(net, sc_net_id);

	TRACEKMOD("### sc_netlink_reset\n");

	/* Check Link */
	if (!sn->sc_netlink_usermodeid) {
		return -ENOLINK;
	}

	/* Close all devices */
	sc_netlink_unregister_alldevice(sn);

	/* Reset session */
	sc_capwap_resetsession(&sn->sc_acsession);

	return 0;
}

/* */
static int sc_netlink_notify(struct notifier_block* nb,
			     unsigned long state,
			     void* _notify)
{
	struct netlink_notify* notify = (struct netlink_notify*)_notify;
	struct sc_net *sn = net_generic(notify->net, sc_net_id);

	if ((state == NETLINK_URELEASE) && (sn->sc_netlink_usermodeid == notify->portid)) {
		rtnl_lock();

		sn->sc_netlink_usermodeid = 0;

		/* Close all devices */
		sc_netlink_unregister_alldevice(sn);

		/* Close capwap engine */
		sc_capwap_close(&sn->sc_acsession);

		/* Allow unload module */
		module_put(THIS_MODULE);

		rtnl_unlock();
	}

	return NOTIFY_DONE;
}

static void cfg_assign_ip(void *ip, __be16 *port, struct sockaddr_storage *addr)
{
	if (addr->ss_family == AF_INET) {
		memcpy(ip, &((struct sockaddr_in *)addr)->sin_addr, sizeof(struct in_addr));
		*port = ((struct sockaddr_in *)addr)->sin_port;
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (addr->ss_family == AF_INET6) {
		memcpy(ip, &((struct sockaddr_in6 *)addr)->sin6_addr, sizeof(struct in6_addr));
		*port = ((struct sockaddr_in6 *)addr)->sin6_port;
	}
#endif

}

/* */
static int sc_netlink_create(struct sk_buff* skb, struct genl_info* info)
{
	struct net *net = genl_info_net(info);
	struct sc_net *sn = net_generic(net, sc_net_id);
	struct sc_capwap_session *session = &sn->sc_acsession;
	struct udp_port_cfg *cfg = &session->udp_config;
	struct sockaddr_storage *local, *peer;
	uint16_t mtu = DEFAULT_MTU;

	TRACEKMOD("### sc_netlink_create\n");

	/* Check Link */
	if (!sn->sc_netlink_usermodeid)
		return -ENOLINK;

	/* Get bind address */
	if (!info->attrs[NLSMARTCAPWAP_ATTR_LOCAL_ADDRESS] ||
	    !info->attrs[NLSMARTCAPWAP_ATTR_PEER_ADDRESS] ||
	    !info->attrs[NLSMARTCAPWAP_ATTR_SESSION_ID])
		return -EINVAL;

	/* Get MTU */
	if (info->attrs[NLSMARTCAPWAP_ATTR_MTU]) {
		mtu = nla_get_u16(info->attrs[NLSMARTCAPWAP_ATTR_MTU]);
		if ((mtu < MIN_MTU) || (mtu > MAX_MTU))
			return -EINVAL;
	}

	memcpy(&session->sessionid, nla_data(info->attrs[NLSMARTCAPWAP_ATTR_SESSION_ID]),
	       sizeof(struct sc_capwap_sessionid_element));
	session->mtu = mtu;

	local = (struct sockaddr_storage *)nla_data(info->attrs[NLSMARTCAPWAP_ATTR_LOCAL_ADDRESS]);
	peer = (struct sockaddr_storage *)nla_data(info->attrs[NLSMARTCAPWAP_ATTR_PEER_ADDRESS]);

	cfg->family = peer->ss_family;
	cfg_assign_ip(&cfg->local_ip, &cfg->local_udp_port, local);
	cfg_assign_ip(&cfg->peer_ip, &cfg->peer_udp_port, peer);
        cfg->use_udp_checksums = 1;
	cfg->use_udp6_tx_checksums = 1;
	cfg->use_udp6_rx_checksums = 1;

	return sc_capwap_create(session);
}

/* */
static int sc_netlink_send_keepalive(struct sk_buff* skb, struct genl_info* info)
{
	struct net *net = genl_info_net(info);
	struct sc_net *sn = net_generic(net, sc_net_id);
	int ret;

	TRACEKMOD("### sc_netlink_send_keepalive\n");

	/* Check Link */
	if (!sn->sc_netlink_usermodeid)
		return -ENOLINK;

	/* Send packet */
	ret = sc_capwap_sendkeepalive(&sn->sc_acsession);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

/* */
static int sc_netlink_send_data(struct sk_buff* skb, struct genl_info* info)
{
	struct net *net = genl_info_net(info);
	struct sc_net *sn = net_generic(net, sc_net_id);
	int ret;
	uint8_t radioid;
	uint8_t binding;
	uint8_t rssi = 0;
	uint8_t snr = 0;
	uint16_t rate = 0;
	int length;
	struct sk_buff* skbdata;
	unsigned char winfobuffer[CAPWAP_WINFO_FRAMEINFO_LENGTH_PADDED];
	struct sc_capwap_wireless_information* winfo = NULL;

	TRACEKMOD("### sc_netlink_send_data\n");

	/* Check Link */
	if (!sn->sc_netlink_usermodeid) {
		return -ENOLINK;
	} else if (!info->attrs[NLSMARTCAPWAP_ATTR_RADIOID] ||
		   !info->attrs[NLSMARTCAPWAP_ATTR_DATA_FRAME]) {
		return -EINVAL;
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
	ret = sc_capwap_forwarddata(&sn->sc_acsession, radioid, binding, skbdata, 0, NULL, 0, winfo, (winfo ? CAPWAP_WINFO_FRAMEINFO_LENGTH_PADDED : 0));
	if (ret) {
		TRACEKMOD("*** Unable send packet from sc_netlink_send_data function\n");
	}

	kfree_skb(skbdata);
	return ret;
}

/* */
static int sc_netlink_join_mac80211_device(struct sk_buff* skb, struct genl_info* info)
{
	struct net *net = genl_info_net(info);
	struct sc_net *sn = net_generic(net, sc_net_id);
	int ret;
	uint32_t ifindex;
	struct sc_netlink_device* nldev;

	TRACEKMOD("### sc_netlink_join_mac80211_device\n");

	/* Check Link */
	if (!sn->sc_netlink_usermodeid) {
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
	if (!info->attrs[NLSMARTCAPWAP_ATTR_RADIOID] ||
	    !info->attrs[NLSMARTCAPWAP_ATTR_WLANID] ||
	    !info->attrs[NLSMARTCAPWAP_ATTR_BINDING]) {
		return -EINVAL;
	}

	/* Register device */
	nldev = sc_netlink_register_device(net, ifindex,
					   nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_RADIOID]),
					   nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_WLANID]),
					   nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_BINDING]));
	if (!nldev) {
		return -EINVAL;
	}

	/* */
	if (info->attrs[NLSMARTCAPWAP_ATTR_FLAGS]) {
		nldev->flags = nla_get_u32(info->attrs[NLSMARTCAPWAP_ATTR_FLAGS]);
	}

	/* Set subtype masking */
	if (info->attrs[NLSMARTCAPWAP_ATTR_MGMT_SUBTYPE_MASK]) {
		nldev->pcktunnel_handler.subtype_mask[0] =
			nla_get_u16(info->attrs[NLSMARTCAPWAP_ATTR_MGMT_SUBTYPE_MASK]);
	}

	if (info->attrs[NLSMARTCAPWAP_ATTR_CTRL_SUBTYPE_MASK]) {
		nldev->pcktunnel_handler.subtype_mask[1] =
			nla_get_u16(info->attrs[NLSMARTCAPWAP_ATTR_CTRL_SUBTYPE_MASK]);
	}

	if (info->attrs[NLSMARTCAPWAP_ATTR_DATA_SUBTYPE_MASK]) {
		nldev->pcktunnel_handler.subtype_mask[2] =
			nla_get_u16(info->attrs[NLSMARTCAPWAP_ATTR_DATA_SUBTYPE_MASK]);
	}

	/* Connect device to mac80211 */
	ret = ieee80211_pcktunnel_register(nldev->dev, &nldev->pcktunnel_handler);
	if (ret) {
		sc_netlink_unregister_device(sn, ifindex);
	}

	return ret;
}

/* */
static int sc_netlink_leave_mac80211_device(struct sk_buff* skb, struct genl_info* info)
{
	struct net *net = genl_info_net(info);
	struct sc_net *sn = net_generic(net, sc_net_id);

	TRACEKMOD("### sc_netlink_leave_mac80211_device\n");

	/* Check Link */
	if (!sn->sc_netlink_usermodeid) {
		return -ENOLINK;
	}

	/* Get interface index */
	if (!info->attrs[NLSMARTCAPWAP_ATTR_IFINDEX]) {
		return -EINVAL;
	}

	/* Unregister device */
	return sc_netlink_unregister_device(sn, nla_get_u32(info->attrs[NLSMARTCAPWAP_ATTR_IFINDEX]));
}

/* */
struct sc_station *sc_find_station(struct hlist_head *sta_head, uint8_t radioid, uint8_t *mac)
{
	struct sc_station *sta;

	hlist_for_each_entry_rcu(sta, sta_head, station_list) {
		if (sta->radioid == radioid &&
		    memcmp(&sta->mac, mac, ETH_ALEN) == 0)
			return sta;
	}

	return NULL;
}

/* */
static int sc_netlink_add_station(struct sk_buff* skb, struct genl_info* info)
{
	struct net *net = genl_info_net(info);
	struct sc_net *sn = net_generic(net, sc_net_id);
	struct sc_capwap_session *session = &sn->sc_acsession;
	struct sc_station *sta;
	uint8_t radioid;
	uint8_t *mac;
	uint32_t hash;
	struct hlist_head *sta_head;

	TRACEKMOD("### sc_netlink_add_station\n");

	/* Check Link */
	if (!sn->sc_netlink_usermodeid)
		return -ENOLINK;

	if (!info->attrs[NLSMARTCAPWAP_ATTR_RADIOID] ||
	    !info->attrs[NLSMARTCAPWAP_ATTR_MAC] ||
	    !info->attrs[NLSMARTCAPWAP_ATTR_WLANID])
		return -EINVAL;

	radioid = nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_RADIOID]);
	mac = nla_data(info->attrs[NLSMARTCAPWAP_ATTR_MAC]);
	hash = jhash(mac, ETH_ALEN, radioid) % STA_HASH_SIZE;
	sta_head = &session->station_list[hash];

	if (sc_find_station(sta_head, radioid, mac) != NULL)
		return -EEXIST;

	if (info->nlhdr->nlmsg_flags & NLM_F_REPLACE)
		return -ENXIO;

	sta = kmalloc(sizeof(struct sc_station), GFP_KERNEL);
	if (sta == NULL)
		return -ENOMEM;

	sta->radioid = radioid;
	memcpy(&sta->mac, mac, ETH_ALEN);
	sta->wlanid = nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_WLANID]);

	hlist_add_head_rcu(&sta->station_list, sta_head);

	return 0;
}

/* */
static int sc_netlink_del_station(struct sk_buff* skb, struct genl_info* info)
{
	struct net *net = genl_info_net(info);
	struct sc_net *sn = net_generic(net, sc_net_id);
	struct sc_capwap_session *session = &sn->sc_acsession;
	uint8_t radioid;
	uint8_t *mac;
	uint32_t hash;
	struct hlist_head *sta_head;
	struct sc_station *sta;

	TRACEKMOD("### sc_netlink_del_station\n");

	/* Check Link */
	if (!sn->sc_netlink_usermodeid)
		return -ENOLINK;

	if (!info->attrs[NLSMARTCAPWAP_ATTR_RADIOID] ||
	    !info->attrs[NLSMARTCAPWAP_ATTR_MAC])
		return -EINVAL;

	radioid = nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_RADIOID]);
	mac = nla_data(info->attrs[NLSMARTCAPWAP_ATTR_MAC]);
	hash = jhash(mac, ETH_ALEN, radioid) % STA_HASH_SIZE;
	sta_head = &session->station_list[hash];

	sta = sc_find_station(sta_head, radioid, mac);
	if (!sta)
		return -ENOENT;

	hlist_del_rcu(&sta->station_list);
	kfree_rcu(sta, rcu_head);

	return 0;
}

/* */
static int sc_device_event(struct notifier_block* unused,
			   unsigned long event,
			   void* ptr)
{
	struct net_device* dev = netdev_notifier_info_to_dev(ptr);
	struct sc_net *sn = net_generic(dev_net(dev), sc_net_id);

	/* Check event only if connect with WTP userspace */
	if (!sn->sc_netlink_usermodeid) {
		return NOTIFY_DONE;
	}

	/* */
	switch (event) {
		case NETDEV_UNREGISTER: {
			/* Try to unregister device */
			sc_netlink_unregister_device(sn, dev->ifindex);
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
	[NLSMARTCAPWAP_ATTR_LOCAL_ADDRESS] = { .len = sizeof(struct sockaddr_storage) },
	[NLSMARTCAPWAP_ATTR_PEER_ADDRESS] = { .len = sizeof(struct sockaddr_storage) },
	[NLSMARTCAPWAP_ATTR_MTU] = { .type = NLA_U16 },
	[NLSMARTCAPWAP_ATTR_SESSION_ID] = { .len = sizeof(struct sc_capwap_sessionid_element) },
	[NLSMARTCAPWAP_ATTR_DTLS] = { .type = NLA_U16 },
	[NLSMARTCAPWAP_ATTR_DATA_FRAME] = { .type = NLA_BINARY, .len = IEEE80211_MTU },
	[NLSMARTCAPWAP_ATTR_RSSI] = { .type = NLA_U8 },
	[NLSMARTCAPWAP_ATTR_SNR] = { .type = NLA_U8 },
	[NLSMARTCAPWAP_ATTR_RATE] = { .type = NLA_U16 },
	[NLSMARTCAPWAP_ATTR_MAC] = { .len = ETH_ALEN },
};

/* Netlink Ops */
static const struct genl_ops sc_netlink_ops[] = {
	{
		.cmd = NLSMARTCAPWAP_CMD_LINK,
		.doit = sc_netlink_link,
		.policy = sc_netlink_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NLSMARTCAPWAP_CMD_CREATE,
		.doit = sc_netlink_create,
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
	{
		.cmd = NLSMARTCAPWAP_CMD_ADD_STATION,
		.doit = sc_netlink_add_station,
		.policy = sc_netlink_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NLSMARTCAPWAP_CMD_DEL_STATION,
		.doit = sc_netlink_del_station,
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
int sc_netlink_notify_recv_keepalive(struct net *net,
				     struct sc_capwap_sessionid_element* sessionid)
{
	struct sc_net *sn = net_generic(net, sc_net_id);
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
	return genlmsg_unicast(net, sk_msg, sn->sc_netlink_usermodeid);
}

/* */
int sc_netlink_notify_recv_data(struct net *net, uint8_t* packet, int length)
{
	struct sc_net *sn = net_generic(net, sc_net_id);
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
	return genlmsg_unicast(net, sk_msg, sn->sc_netlink_usermodeid);

error2:
	genlmsg_cancel(sk_msg, msg);

error:
	nlmsg_free(sk_msg);
	return -ENOMEM;
}

/* */
struct net_device* sc_netlink_getdev_from_wlanid(struct net *net,
						 uint8_t radioid,
						 uint8_t wlanid)
{
	struct sc_net *sn = net_generic(net, sc_net_id);
	struct sc_netlink_device *nldev;

	TRACEKMOD("### sc_netlink_getdev_from_wlanid\n");

	/* Search */
	rcu_read_lock();
	list_for_each_entry_rcu(nldev, &sn->sc_netlink_dev_list, list) {
		if ((nldev->radioid == radioid) && (nldev->wlanid == wlanid)) {
			rcu_read_unlock();
			return nldev->dev;
		}
	}
	rcu_read_unlock();

	return NULL;
}

static int __net_init sc_net_init(struct net *net)
{
        struct sc_net *sn = net_generic(net, sc_net_id);

	sn->sc_netlink_usermodeid = 0;
        INIT_LIST_HEAD_RCU(&sn->sc_netlink_dev_list);

        return 0;
}

static void __net_exit sc_net_exit(struct net *net)
{
        struct sc_net *sn = net_generic(net, sc_net_id);

        rtnl_lock();
	sc_netlink_unregister_alldevice(sn);
        rtnl_unlock();
}

static struct pernet_operations sc_net_ops = {
        .init = sc_net_init,
        .exit = sc_net_exit,
        .id   = &sc_net_id,
        .size = sizeof(struct sc_net),
};

/* */
int __init sc_netlink_init(void) {
	int ret;

	TRACEKMOD("### sc_netlink_init\n");

	/* register pernet */
        ret = register_pernet_subsys(&sc_net_ops);
        if (ret < 0)
		goto error_out;

	/* Register interface event */
	ret = register_netdevice_notifier(&sc_device_notifier);
	if (ret < 0)
                goto unreg_pernet;

	/* Register netlink family */
	ret = genl_register_family_with_ops(&sc_netlink_family, sc_netlink_ops);
	if (ret < 0)
		goto unreg_netdev_notifier;

	/* Register netlink notifier */
	ret = netlink_register_notifier(&sc_netlink_notifier);
	if (ret)
		goto unreg_genl_family;

	pr_info("smartCAPWAP module loaded");
 	return 0;

unreg_genl_family:
	genl_unregister_family(&sc_netlink_family);
unreg_netdev_notifier:
	unregister_netdevice_notifier(&sc_device_notifier);
unreg_pernet:
	unregister_pernet_subsys(&sc_net_ops);
error_out:
        pr_err("error loading smartCAPWAP module\n");
	return ret;
}

/* */
void __exit sc_netlink_exit(void) {
	TRACEKMOD("### sc_netlink_exit\n");

	netlink_unregister_notifier(&sc_netlink_notifier);
	genl_unregister_family(&sc_netlink_family);
	unregister_netdevice_notifier(&sc_device_notifier);
	unregister_pernet_subsys(&sc_net_ops);

	pr_info("smartCAWAP module unloaded\n");
}
