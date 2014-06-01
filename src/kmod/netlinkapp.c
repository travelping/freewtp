#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/rcupdate.h>
#include "nlsmartcapwap.h"
#include "netlinkapp.h"

/* */
#define NLSMARTCAPWAP_FLAG_NEED_RTNL			0x01

/* */
static u32 g_nlusermodeid = 0;

/* */
static int nlsmartcapwap_pre_doit(__genl_const struct genl_ops* ops, struct sk_buff* skb, struct genl_info* info) {
	int rtnl = ((ops->internal_flags & NLSMARTCAPWAP_FLAG_NEED_RTNL) ? 1 : 0);

	/* */
	if (rtnl) {
		rtnl_lock();
	}

	return 0;
}

/* */
static void nlsmartcapwap_post_doit(__genl_const struct genl_ops* ops, struct sk_buff* skb, struct genl_info* info) {
	if (ops->internal_flags & NLSMARTCAPWAP_FLAG_NEED_RTNL) {
		rtnl_unlock();
	}
}

/* */
static int nlsmartcapwap_connect(struct sk_buff *skb, struct genl_info *info) {
	int result = 0;
	u32 portid = genl_info_snd_portid(info);

	if (!g_nlusermodeid) {
		g_nlusermodeid = portid;
	} else if (g_nlusermodeid == portid) {
		result = -EALREADY;
	} else {
		result = -EBUSY;
	}

	return result;
}

/* */
static int nlsmartcapwap_netlink_notify(struct notifier_block* nb, unsigned long state, void* _notify) {
	struct netlink_notify* notify = (struct netlink_notify*)_notify;
	u32 portid = netlink_notify_portid(notify);

	/* */
	if (state = NETLINK_URELEASE) {
		rtnl_lock();

		if (g_nlusermodeid == portid) {
			g_nlusermodeid = 0;
		}

		rtnl_unlock();
	}

	return NOTIFY_DONE;
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

static const struct nla_policy nlsmartcapwap_policy[NLSMARTCAPWAP_ATTR_MAX + 1] = {
	[NLSMARTCAPWAP_ATTR_IFINDEX] = { .type = NLA_U32 },
};

/* Netlink Ops */
static __genl_const struct genl_ops nlsmartcapwap_ops[] = {
	{
		.cmd = NLSMARTCAPWAP_CMD_CONNECT,
		.doit = nlsmartcapwap_connect,
		.policy = nlsmartcapwap_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NLSMARTCAPWAP_FLAG_NEED_RTNL,
	},
};

/* Netlink notify */
static struct notifier_block nlsmartcapwap_netlink_notifier = {
	.notifier_call = nlsmartcapwap_netlink_notify,
};

/* */
int nlsmartcapwap_init(void) {
	int result;

	/* Register netlink family */
	result = genl_register_family_with_ops(&nlsmartcapwap_family, nlsmartcapwap_ops);
	if (result) {
		return result;
	}

	/* Register netlink notifier */
	result = netlink_register_notifier(&nlsmartcapwap_netlink_notifier);
	if (result) {
		genl_unregister_family(&nlsmartcapwap_family);
		return result;
	}

	return result;
}

/* */
void nlsmartcapwap_exit(void) {
	netlink_unregister_notifier(&nlsmartcapwap_netlink_notifier);
	genl_unregister_family(&nlsmartcapwap_family);
}
