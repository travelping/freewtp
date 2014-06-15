#include <linux/module.h>
#include <linux/version.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/rcupdate.h>
#include <linux/err.h>
#include <net/mac80211.h>
#include <linux/ieee80211.h>
#include "nlsmartcapwap.h"
#include "netlinkapp.h"

/* */
struct nlsmartcapwap_ac_device {
	struct list_head list;

	u32 usermodeid;
};

/* */
static u32 nlsmartcapwap_ac_usermodeid = 0;
static LIST_HEAD(nlsmartcapwap_ac_dev_list);

/* Netlink Family */
static struct genl_family nlsmartcapwap_ac_family = {
	.id = GENL_ID_GENERATE,
	.name = SMARTCAPWAP_AC_GENL_NAME,
	.hdrsize = 0,
	.version = 1,
	.maxattr = NLSMARTCAPWAP_AC_ATTR_MAX,
	.netnsok = true,
};

/* */
static void nlsmartcapwap_ac_free_device(struct nlsmartcapwap_ac_device* nldev) {
	/* Free memory */
	kfree(nldev);
}

/* */
static void nlsmartcapwap_ac_close(void) {
	struct nlsmartcapwap_ac_device* nldev;
	struct nlsmartcapwap_ac_device* tmp;

	list_for_each_entry_safe(nldev, tmp, &nlsmartcapwap_ac_dev_list, list) {
		list_del(&nldev->list);

		/* Free device */
		nlsmartcapwap_ac_free_device(nldev);
	}
}


/* */
static int nlsmartcapwap_ac_link(struct sk_buff* skb, struct genl_info* info) {
	int ret = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	u32 portid = info->snd_pid;
#else
	u32 portid = info->snd_portid;
#endif

	rtnl_lock();

	if (!nlsmartcapwap_ac_usermodeid) {
		nlsmartcapwap_ac_usermodeid = portid;
	} else if (nlsmartcapwap_ac_usermodeid == portid) {
		ret = -EALREADY;
	} else {
		ret = -EBUSY;
	}

	rtnl_unlock();

	return ret;
}

/* */
static int nlsmartcapwap_ac_netlink_notify(struct notifier_block* nb, unsigned long state, void* _notify) {
	struct netlink_notify* notify = (struct netlink_notify*)_notify;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	u32 portid = notify->pid;
#else
	u32 portid = notify->portid;
#endif

	/* */
	if (state == NETLINK_URELEASE) {
		rtnl_lock();

		if (nlsmartcapwap_ac_usermodeid == portid) {
			nlsmartcapwap_ac_usermodeid = 0;

			/* Close all devices */
			nlsmartcapwap_ac_close();
		}

		rtnl_unlock();
	}

	return NOTIFY_DONE;
}

/* */
static const struct nla_policy nlsmartcapwap_ac_policy[NLSMARTCAPWAP_AC_ATTR_MAX + 1] = {
	[NLSMARTCAPWAP_AC_ATTR_FLAGS] = { .type = NLA_U32 },
};

/* Netlink Ops */
static struct genl_ops nlsmartcapwap_ac_ops[] = {
	{
		.cmd = NLSMARTCAPWAP_AC_CMD_LINK,
		.doit = nlsmartcapwap_ac_link,
		.policy = nlsmartcapwap_ac_policy,
		.flags = GENL_ADMIN_PERM,
	},
};

/* Netlink notify */
static struct notifier_block nlsmartcapwap_ac_netlink_notifier = {
	.notifier_call = nlsmartcapwap_ac_netlink_notify,
};

/* */
int nlsmartcapwap_ac_init(void) {
	int ret;

	/* Register netlink family */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
	ret = genl_register_family_with_ops(&nlsmartcapwap_ac_family, nlsmartcapwap_ac_ops, sizeof(nlsmartcapwap_ac_ops) / sizeof(nlsmartcapwap_ac_ops[0]));
#else
	ret = genl_register_family_with_ops(&nlsmartcapwap_ac_family, nlsmartcapwap_ac_ops);
#endif
	if (ret) {
		return ret;
	}

	/* Register netlink notifier */
	ret = netlink_register_notifier(&nlsmartcapwap_ac_netlink_notifier);
	if (ret) {
		genl_unregister_family(&nlsmartcapwap_ac_family);
		return ret;
	}

	return ret;
}

/* */
void nlsmartcapwap_ac_exit(void) {
	/* */
	rtnl_lock();
	nlsmartcapwap_ac_close();
	rtnl_unlock();

	/* */
	netlink_unregister_notifier(&nlsmartcapwap_ac_netlink_notifier);
	genl_unregister_family(&nlsmartcapwap_ac_family);
}
