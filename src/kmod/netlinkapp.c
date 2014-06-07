#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/rcupdate.h>
#include <linux/err.h>
#include <net/mac80211.h>
#include "nlsmartcapwap.h"
#include "netlinkapp.h"

/* */
struct nlsmartcapwap_device {
	struct list_head list;
	struct ieee80211_pcktunnel pcktunnel_handler;

	u32 ifindex;
	u32 flags;
};

/* */
static u32 nlsmartcapwap_usermodeid = 0;
static LIST_HEAD(nlsmartcapwap_dev_list);

/* */
static int nlsmartcapwap_pre_doit(__genl_const struct genl_ops* ops, struct sk_buff* skb, struct genl_info* info) {
	rtnl_lock();
	return 0;
}

/* */
static void nlsmartcapwap_post_doit(__genl_const struct genl_ops* ops, struct sk_buff* skb, struct genl_info* info) {
	rtnl_unlock();
}

/* Netlink Family */
static struct genl_family nlsmartcapwap_family = {
	.id = GENL_ID_GENERATE,
	.name = SMARTCAPWAP_GENL_NAME,
	.hdrsize = 0,
	.version = 1,
	.maxattr = NLSMARTCAPWAP_ATTR_MAX,
	.netnsok = true,
	.pre_doit = nlsmartcapwap_pre_doit,
	.post_doit = nlsmartcapwap_post_doit,
};

/* */
static int nlsmartcapwap_handler(u32 ifindex, struct sk_buff* skb, int sig_dbm, unsigned char rate, void* data) {
	struct nlsmartcapwap_device* nldev = (struct nlsmartcapwap_device*)data;
	struct ieee80211_hdr* hdr = (struct ieee80211_hdr*)skb->data;

	/* Check source network */
	if (ifindex == nldev->ifindex) {
		if (nldev->flags & SMARTCAPWAP_FLAGS_SEND_USERSPACE) {
			void* msg;
			struct sk_buff* sk_msg;

			/* Alloc message */
			sk_msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
			if (sk_msg) {
				/* Set command */
				msg = genlmsg_put(sk_msg, 0, 0, &nlsmartcapwap_family, 0, NLSMARTCAPWAP_CMD_FRAME);
				if (msg) {
					/* Set params */
					if (nla_put_u32(sk_msg, NLSMARTCAPWAP_ATTR_IFINDEX, nldev->ifindex) ||
						nla_put(sk_msg, NLSMARTCAPWAP_ATTR_FRAME, skb->len, skb->data) ||
						(sig_dbm && nla_put_u32(sk_msg, NLSMARTCAPWAP_ATTR_RX_SIGNAL_DBM, (u32)sig_dbm)) ||
						(rate && nla_put_u8(sk_msg, NLSMARTCAPWAP_ATTR_RX_RATE, (u8)rate))) {

						/* Abort message */
						genlmsg_cancel(sk_msg, msg);
						nlmsg_free(sk_msg);
					} else {
						/* Send message */
						genlmsg_end(sk_msg, msg);
						genlmsg_unicast(&init_net, sk_msg, nlsmartcapwap_usermodeid);
					}
				} else {
					nlmsg_free(sk_msg);
				}
			}
		}
	}

	/* Check if block all IEEE802.11 Data Packet */
	if ((nldev->flags & SMARTCAPWAP_FLAGS_BLOCK_DATA_FRAME) && 
		((le16_to_cpu(hdr->frame_control) & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA)) {
		return -1;
	}

	return 0;
}

/* */
static struct nlsmartcapwap_device* nlsmartcapwap_new_device(u32 ifindex) {
	struct nlsmartcapwap_device* nldev;

	/* Create device */
	nldev = (struct nlsmartcapwap_device*)kzalloc(sizeof(struct nlsmartcapwap_device), GFP_KERNEL);
	if (nldev) {
		/* Initialize device */
		nldev->pcktunnel_handler.handler = nlsmartcapwap_handler;
		nldev->pcktunnel_handler.data = (void*)nldev;
		nldev->ifindex = ifindex;
	}

	return nldev;
}

/* */
static void nlsmartcapwap_free_device(struct nlsmartcapwap_device* nldev) {
	/* Disconnect device from mac80211 */
	ieee80211_pcktunnel_deregister(nldev->ifindex, &nldev->pcktunnel_handler);

	/* Free memory */
	kfree(nldev);
}

/* */
static struct nlsmartcapwap_device* nlsmartcapwap_register_device(u32 ifindex) {
	struct nlsmartcapwap_device* nldev;

	ASSERT_RTNL();

	/* Search device */
	list_for_each_entry(nldev, &nlsmartcapwap_dev_list, list) {
		if (nldev->ifindex == ifindex) {
			return nldev;
		}
	}

	/* Create device */
	nldev = nlsmartcapwap_new_device(ifindex);
	if (nldev) {
		list_add_rcu(&nldev->list, &nlsmartcapwap_dev_list);
	}

	return nldev;
}

/* */
static int nlsmartcapwap_unregister_device(u32 ifindex) {
	int ret = -ENODEV;
	struct nlsmartcapwap_device* nldev;

	ASSERT_RTNL();

	/* Search device */
	list_for_each_entry(nldev, &nlsmartcapwap_dev_list, list) {
		if (nldev->ifindex == ifindex) {
			/* Remove from list */
			list_del_rcu(&nldev->list);
			synchronize_net();

			/* Free device */
			ret = 0;
			nlsmartcapwap_free_device(nldev);
			break;
		}
	}

	return ret;
}

/* */
static void nlsmartcapwap_close(void) {
	struct nlsmartcapwap_device* nldev;
	struct nlsmartcapwap_device* tmp;

	list_for_each_entry_safe(nldev, tmp, &nlsmartcapwap_dev_list, list) {
		list_del(&nldev->list);

		/* Free device */
		nlsmartcapwap_free_device(nldev);
	}
}


/* */
static int nlsmartcapwap_link(struct sk_buff* skb, struct genl_info* info) {
	int ret = 0;
	u32 portid = genl_info_snd_portid(info);

	if (!nlsmartcapwap_usermodeid) {
		nlsmartcapwap_usermodeid = portid;
	} else if (nlsmartcapwap_usermodeid == portid) {
		ret = -EALREADY;
	} else {
		ret = -EBUSY;
	}

	return ret;
}

/* */
static int nlsmartcapwap_netlink_notify(struct notifier_block* nb, unsigned long state, void* _notify) {
	struct netlink_notify* notify = (struct netlink_notify*)_notify;
	u32 portid = netlink_notify_portid(notify);

	/* */
	if (state == NETLINK_URELEASE) {
		rtnl_lock();

		if (nlsmartcapwap_usermodeid == portid) {
			nlsmartcapwap_usermodeid = 0;

			/* Close all devices */
			nlsmartcapwap_close();
		}

		rtnl_unlock();
	}

	return NOTIFY_DONE;
}

/* */
static int nlsmartcapwap_join_mac80211_device(struct sk_buff* skb, struct genl_info* info) {
	u32 ifindex;
	struct nlsmartcapwap_device* nldev;
	int ret = -EINVAL;

	/* Get interface index */
	if (!info->attrs[NLSMARTCAPWAP_ATTR_IFINDEX]) {
		return -EINVAL;
	}

	ifindex = nla_get_u32(info->attrs[NLSMARTCAPWAP_ATTR_IFINDEX]);
	if (!ifindex) {
		return -EINVAL;
	}

	/* Register device */
	nldev = nlsmartcapwap_register_device(ifindex);
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
	ret = ieee80211_pcktunnel_register(ifindex, &nldev->pcktunnel_handler);
	if (ret) {
		nlsmartcapwap_unregister_device(ifindex);
	}

	return ret;
}

/* */
static int nlsmartcapwap_leave_mac80211_device(struct sk_buff* skb, struct genl_info* info) {
	u32 ifindex;

	/* Get interface index */
	if (!info->attrs[NLSMARTCAPWAP_ATTR_IFINDEX]) {
		return -EINVAL;
	}

	ifindex = nla_get_u32(info->attrs[NLSMARTCAPWAP_ATTR_IFINDEX]);
	if (!ifindex) {
		return -EINVAL;
	}

	/* Unregister device */
	return nlsmartcapwap_unregister_device(ifindex);
}

/* */
static const struct nla_policy nlsmartcapwap_policy[NLSMARTCAPWAP_ATTR_MAX + 1] = {
	[NLSMARTCAPWAP_ATTR_IFINDEX] = { .type = NLA_U32 },
	[NLSMARTCAPWAP_ATTR_FLAGS] = { .type = NLA_U32 },
	[NLSMARTCAPWAP_ATTR_MGMT_SUBTYPE_MASK] = { .type = NLA_U16 },
	[NLSMARTCAPWAP_ATTR_CTRL_SUBTYPE_MASK] = { .type = NLA_U16 },
	[NLSMARTCAPWAP_ATTR_DATA_SUBTYPE_MASK] = { .type = NLA_U16 },
	[NLSMARTCAPWAP_ATTR_FRAME] = { .type = NLA_BINARY, .len = IEEE80211_MAX_DATA_LEN },
	[NLSMARTCAPWAP_ATTR_RX_SIGNAL_DBM] = { .type = NLA_U32 },
	[NLSMARTCAPWAP_ATTR_RX_RATE] = { .type = NLA_U8 },
};

/* Netlink Ops */
static __genl_const struct genl_ops nlsmartcapwap_ops[] = {
	{
		.cmd = NLSMARTCAPWAP_CMD_LINK,
		.doit = nlsmartcapwap_link,
		.policy = nlsmartcapwap_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NLSMARTCAPWAP_CMD_JOIN_MAC80211_DEVICE,
		.doit = nlsmartcapwap_join_mac80211_device,
		.policy = nlsmartcapwap_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NLSMARTCAPWAP_CMD_LEAVE_MAC80211_DEVICE,
		.doit = nlsmartcapwap_leave_mac80211_device,
		.policy = nlsmartcapwap_policy,
		.flags = GENL_ADMIN_PERM,
	},
};

/* Netlink notify */
static struct notifier_block nlsmartcapwap_netlink_notifier = {
	.notifier_call = nlsmartcapwap_netlink_notify,
};

/* */
int nlsmartcapwap_init(void) {
	int ret;

	/* Register netlink family */
	ret = genl_register_family_with_ops(&nlsmartcapwap_family, nlsmartcapwap_ops);
	if (ret) {
		return ret;
	}

	/* Register netlink notifier */
	ret = netlink_register_notifier(&nlsmartcapwap_netlink_notifier);
	if (ret) {
		genl_unregister_family(&nlsmartcapwap_family);
		return ret;
	}

	return ret;
}

/* */
void nlsmartcapwap_exit(void) {
	/* */
	rtnl_lock();
	nlsmartcapwap_close();
	rtnl_unlock();

	/* */
	netlink_unregister_notifier(&nlsmartcapwap_netlink_notifier);
	genl_unregister_family(&nlsmartcapwap_family);
}
