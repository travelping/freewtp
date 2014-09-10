#include "config.h"
#include <linux/module.h>
#include <linux/version.h>
#include <linux/version.h>
#include <linux/socket.h>
#include <linux/rtnetlink.h>
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
static u32 sc_netlink_usermodeid;

/* */
static int sc_netlink_pre_doit(struct genl_ops* ops, struct sk_buff* skb, struct genl_info* info) {
	TRACEKMOD("### sc_netlink_pre_doit\n");

	rtnl_lock();
	return 0;
}

/* */
static void sc_netlink_post_doit(struct genl_ops* ops, struct sk_buff* skb, struct genl_info* info) {
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
static int sc_netlink_bind(struct sk_buff* skb, struct genl_info* info) {
	union capwap_addr sockaddr;

	TRACEKMOD("### sc_netlink_bind\n");

	/* Check Link */
	if (sc_netlink_usermodeid != info->snd_portid) {
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
static int sc_netlink_send_keepalive(struct sk_buff* skb, struct genl_info* info) {
	int ret;
	union capwap_addr sockaddr;

	TRACEKMOD("### sc_netlink_send_keepalive\n");

	/* Check Link */
	if (sc_netlink_usermodeid != info->snd_portid) {
		return -ENOLINK;
	}

	/* Check Session address */
	if (!info->attrs[NLSMARTCAPWAP_ATTR_ADDRESS]) {
		return -EINVAL;
	}

	/* */
	memcpy(&sockaddr.ss, nla_data(info->attrs[NLSMARTCAPWAP_ATTR_ADDRESS]), sizeof(struct sockaddr_storage));
	if ((sockaddr.ss.ss_family != AF_INET) && (sockaddr.ss.ss_family != AF_INET6)) {
		return -EINVAL;
	}

	/* Send keep-alive packet */
	ret = sc_capwap_sendkeepalive(&sockaddr);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

/* */
static int sc_netlink_send_data(struct sk_buff* skb, struct genl_info* info) {
	int length;
	struct sk_buff* skbdata;
	union capwap_addr sockaddr;
	struct sc_skb_capwap_cb* cb;

	TRACEKMOD("### sc_netlink_send_data\n");

	/* Check Link */
	if (sc_netlink_usermodeid != info->snd_portid) {
		return -ENOLINK;
	} else if (!info->attrs[NLSMARTCAPWAP_ATTR_ADDRESS] || !info->attrs[NLSMARTCAPWAP_ATTR_RADIOID] || !info->attrs[NLSMARTCAPWAP_ATTR_BINDING] || !info->attrs[NLSMARTCAPWAP_ATTR_DATA_FRAME]) {
		return -EINVAL;
	}

	/* */
	memcpy(&sockaddr.ss, nla_data(info->attrs[NLSMARTCAPWAP_ATTR_ADDRESS]), sizeof(struct sockaddr_storage));
	if ((sockaddr.ss.ss_family != AF_INET) && (sockaddr.ss.ss_family != AF_INET6)) {
		return -EINVAL;
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
	cb = CAPWAP_SKB_CB(skbdata);
	cb->flags = SKB_CAPWAP_FLAG_FROM_USER_SPACE | SKB_CAPWAP_FLAG_PEERADDRESS | SKB_CAPWAP_FLAG_RADIOID | SKB_CAPWAP_FLAG_BINDING;
	sc_addr_tolittle(&sockaddr, &cb->peeraddr);
	cb->radioid = nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_RADIOID]);
	cb->binding = nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_BINDING]);

	/* */
	sc_capwap_recvpacket(skbdata);
	return 0;
}

/* */
static int sc_netlink_new_session(struct sk_buff* skb, struct genl_info* info) {
	uint16_t mtu = DEFAULT_MTU;

	TRACEKMOD("### sc_netlink_new_session\n");

	/* Check Link */
	if (sc_netlink_usermodeid != info->snd_portid) {
		return -ENOLINK;
	}

	/* Check Session ID */
	if (!info->attrs[NLSMARTCAPWAP_ATTR_SESSION_ID] || (nla_len(info->attrs[NLSMARTCAPWAP_ATTR_SESSION_ID]) != sizeof(struct sc_capwap_sessionid_element))) {
		return -EINVAL;
	}

	/* Get MTU */
	if (info->attrs[NLSMARTCAPWAP_ATTR_MTU]) {
		mtu = nla_get_u16(info->attrs[NLSMARTCAPWAP_ATTR_MTU]);
		if ((mtu < MIN_MTU) || (mtu > MAX_MTU)) {
			return -EINVAL;
		}
	}

	/* New session */
	return sc_capwap_newsession((struct sc_capwap_sessionid_element*)nla_data(info->attrs[NLSMARTCAPWAP_ATTR_SESSION_ID]), mtu);
}

/* */
static int sc_netlink_delete_session(struct sk_buff* skb, struct genl_info* info) {
	union capwap_addr sockaddr;

	TRACEKMOD("### sc_netlink_delete_session\n");

	/* Check Link */
	if (sc_netlink_usermodeid != info->snd_portid) {
		return -ENOLINK;
	}

	/* Check Session ID */
	if (!info->attrs[NLSMARTCAPWAP_ATTR_SESSION_ID] || (nla_len(info->attrs[NLSMARTCAPWAP_ATTR_SESSION_ID]) != sizeof(struct sc_capwap_sessionid_element))) {
		return -EINVAL;
	}

	/* Check Address */
	if (info->attrs[NLSMARTCAPWAP_ATTR_ADDRESS] && (nla_len(info->attrs[NLSMARTCAPWAP_ATTR_ADDRESS]) == sizeof(struct sockaddr_storage))) {
		memcpy(&sockaddr.ss, nla_data(info->attrs[NLSMARTCAPWAP_ATTR_ADDRESS]), sizeof(struct sockaddr_storage));
	} else {
		sockaddr.ss.ss_family = AF_UNSPEC;
	}

	/* Delete session */
	return sc_capwap_deletesession(((sockaddr.ss.ss_family == AF_UNSPEC) ? NULL : &sockaddr), (struct sc_capwap_sessionid_element*)nla_data(info->attrs[NLSMARTCAPWAP_ATTR_SESSION_ID]));
}

/* */
static int sc_netlink_link(struct sk_buff* skb, struct genl_info* info) {
	int ret = 0;

	TRACEKMOD("### sc_netlink_link\n");

	if (!info->attrs[NLSMARTCAPWAP_ATTR_HASH_SESSION_BITFIELD] || !info->attrs[NLSMARTCAPWAP_ATTR_SESSION_THREADS_COUNT]) {
		TRACEKMOD("*** Invalid link argument\n");
		return -EINVAL;
	}

	if (!sc_netlink_usermodeid) {
		uint32_t hash = nla_get_u32(info->attrs[NLSMARTCAPWAP_ATTR_HASH_SESSION_BITFIELD]);
		uint32_t threads = nla_get_u32(info->attrs[NLSMARTCAPWAP_ATTR_SESSION_THREADS_COUNT]);

		if (!hash || !threads) {
			TRACEKMOD("*** Invalid link argument: %u %u\n", hash, threads);
			return -EINVAL;
		}

		/* Initialize library */
		ret = sc_capwap_init(hash, threads);
		if (!ret) {
			sc_netlink_usermodeid = info->snd_portid;

			/* Deny unload module */
			try_module_get(THIS_MODULE);
		}
	} else if (sc_netlink_usermodeid == info->snd_portid) {
		TRACEKMOD("*** Already link\n");
		ret = -EALREADY;
	} else {
		TRACEKMOD("*** Busy kernel link\n");
		ret = -EBUSY;
	}

	return ret;
}

/* */
static int sc_netlink_notify(struct notifier_block* nb, unsigned long state, void* _notify) {
	struct netlink_notify* notify = (struct netlink_notify*)_notify;

	/* */
	if (state == NETLINK_URELEASE) {
		rtnl_lock();

		if (sc_netlink_usermodeid == notify->portid) {
			/* Close capwap engine */
			sc_capwap_close();

			/* Allow unload module */
			module_put(THIS_MODULE);
			sc_netlink_usermodeid = 0;
		}

		rtnl_unlock();
	}

	return NOTIFY_DONE;
}

/* */
static const struct nla_policy sc_netlink_policy[NLSMARTCAPWAP_ATTR_MAX + 1] = {
	[NLSMARTCAPWAP_ATTR_FLAGS] = { .type = NLA_U32 },
	[NLSMARTCAPWAP_ATTR_SESSION_ID] = { .type = NLA_BINARY, .len = sizeof(struct sc_capwap_sessionid_element) },
	[NLSMARTCAPWAP_ATTR_RADIOID] = { .type = NLA_U8 },
	[NLSMARTCAPWAP_ATTR_BINDING] = { .type = NLA_U8 },
	[NLSMARTCAPWAP_ATTR_ADDRESS] = { .type = NLA_BINARY, .len = sizeof(struct sockaddr_storage) },
	[NLSMARTCAPWAP_ATTR_DATA_FRAME] = { .type = NLA_BINARY, .len = IEEE80211_MAX_DATA_LEN + CAPWAP_HEADER_MAX_LENGTH },
	[NLSMARTCAPWAP_ATTR_MTU] = { .type = NLA_U16 },
	[NLSMARTCAPWAP_ATTR_HASH_SESSION_BITFIELD] = { .type = NLA_U32 },
	[NLSMARTCAPWAP_ATTR_SESSION_THREADS_COUNT] = { .type = NLA_U32 },
};

/* Netlink Ops */
static struct genl_ops sc_netlink_ops[] = {
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
		.cmd = NLSMARTCAPWAP_CMD_NEW_SESSION,
		.doit = sc_netlink_new_session,
		.policy = sc_netlink_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NLSMARTCAPWAP_CMD_DELETE_SESSION,
		.doit = sc_netlink_delete_session,
		.policy = sc_netlink_policy,
		.flags = GENL_ADMIN_PERM,
	},
};

/* Netlink notify */
static struct notifier_block sc_netlink_notifier = {
	.notifier_call = sc_netlink_notify,
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
		goto error;
	}

	/* */
	if (nla_put(sk_msg, NLSMARTCAPWAP_ATTR_ADDRESS, sizeof(struct sockaddr_storage), &sockaddr->ss) || 
		nla_put(sk_msg, NLSMARTCAPWAP_ATTR_SESSION_ID, sizeof(struct sc_capwap_sessionid_element), sessionid)) {
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
int sc_netlink_notify_recv_data(struct sc_capwap_sessionid_element* sessionid, uint8_t* packet, int length) {
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
	if (nla_put(sk_msg, NLSMARTCAPWAP_ATTR_SESSION_ID, sizeof(struct sc_capwap_sessionid_element), sessionid) || 
		nla_put(sk_msg, NLSMARTCAPWAP_ATTR_DATA_FRAME, length, packet)) {
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
int sc_netlink_init(void) {
	int ret;

	TRACEKMOD("### sc_netlink_init\n");

	/* */
	sc_netlink_usermodeid = 0;

	/* Register netlink family */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
	ret = genl_register_family_with_ops(&sc_netlink_family, sc_netlink_ops, sizeof(sc_netlink_ops) / sizeof(sc_netlink_ops[0]));
#else
	ret = genl_register_family_with_ops(&sc_netlink_family, sc_netlink_ops);
#endif
	if (ret) {
		goto error;
	}

	/* Register netlink notifier */
	ret = netlink_register_notifier(&sc_netlink_notifier);
	if (ret) {
		goto error2;
	}

	return 0;

error2:
	genl_unregister_family(&sc_netlink_family);
error:
	return ret;
}

/* */
void sc_netlink_exit(void) {
	TRACEKMOD("### sc_netlink_exit\n");

	netlink_unregister_notifier(&sc_netlink_notifier);
	genl_unregister_family(&sc_netlink_family);
}
