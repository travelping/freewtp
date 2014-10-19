#include "config.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include "iface.h"

/* */
struct sc_netdev_priv {
	struct net_device* dev;
	struct sc_netdev_priv* next;
};

/* */
#define CAPWAP_IFACE_COUNT				8
#define CAPWAP_IFACE_HASH(x)			((x) % CAPWAP_IFACE_COUNT)

static uint32_t sc_iface_count;
static DEFINE_SPINLOCK(sc_iface_lock);
static struct sc_netdev_priv* sc_iface_hash[CAPWAP_IFACE_COUNT];

/* */
static void sc_iface_netdev_uninit(struct net_device* dev) {
	unsigned long flags;
	struct sc_netdev_priv* search;
	int hash = CAPWAP_IFACE_HASH(dev->ifindex);
	struct sc_netdev_priv* priv = (struct sc_netdev_priv*)netdev_priv(dev);

	TRACEKMOD("### sc_iface_netdev_uninit\n");

	/* Remove interface from hash */
	spin_lock_irqsave(&sc_iface_lock, flags);

	search  = sc_iface_hash[hash];
	if (search) {
		if (priv == search) {
			netif_tx_lock_bh(dev);
			netif_carrier_off(dev);
			netif_tx_unlock_bh(dev);

			sc_iface_hash[hash] = priv->next;

			dev_put(dev);
			sc_iface_count--;
		} else {
			while (search->next && (search->next != priv)) {
				search = search->next;
			}

			if (search->next) {
				netif_tx_lock_bh(dev);
				netif_carrier_off(dev);
				netif_tx_unlock_bh(dev);

				search->next = priv->next;

				dev_put(dev);
				sc_iface_count--;
			}
		}
	}

	spin_unlock_irqrestore(&sc_iface_lock, flags);

	/* Close stations with link to this device */
	/* TODO */
}

/* */
static int sc_iface_netdev_open(struct net_device* dev) {
	TRACEKMOD("### sc_iface_netdev_open\n");

	netif_start_queue(dev);
	return 0;
}

/* */
static int sc_iface_netdev_stop(struct net_device* dev) {
	TRACEKMOD("### sc_iface_netdev_stop\n");

	netif_stop_queue(dev);
	return 0;
}

/* */
static int sc_iface_netdev_tx(struct sk_buff* skb, struct net_device* dev) {
	TRACEKMOD("### sc_iface_netdev_tx\n");

	/* TODO */
	return 0;
}

/* */
static int sc_iface_netdev_change_mtu(struct net_device* dev, int new_mtu) {
	TRACEKMOD("### sc_iface_netdev_change_mtu\n");

	/* TODO */
	return 0;
}

/* */
static void sc_iface_netdev_setup(struct net_device* dev) {
	struct sc_netdev_priv* priv = (struct sc_netdev_priv*)netdev_priv(dev);

	TRACEKMOD("### sc_iface_netdev_setup\n");

	/* */
	memset(priv, 0, sizeof(struct sc_netdev_priv));
	priv->dev = dev;
}

/* */
static const struct net_device_ops capwap_netdev_ops = {
	.ndo_uninit = sc_iface_netdev_uninit,
	.ndo_open = sc_iface_netdev_open,
	.ndo_stop = sc_iface_netdev_stop,
	.ndo_start_xmit = sc_iface_netdev_tx,
	.ndo_change_mtu = sc_iface_netdev_change_mtu,
};

/* */
int sc_iface_create(const char* ifname, uint16_t mtu) {
	int err;
	int hash;
	unsigned long flags;
	struct net_device* dev;
	struct sc_netdev_priv* priv;

	TRACEKMOD("### sc_iface_create\n");

	/* Create interface */
	dev = alloc_netdev(sizeof(struct sc_netdev_priv), ifname, sc_iface_netdev_setup);
	if (!dev) {
		return -ENOMEM;
	}

	/* */
	priv = (struct sc_netdev_priv*)netdev_priv(dev);
	dev->netdev_ops = &capwap_netdev_ops;
	ether_setup(dev);

	eth_hw_addr_random(dev);

	dev->mtu = mtu;

	dev->hw_features = NETIF_F_HW_CSUM;
	dev->features = dev->hw_features;

	/* */
	err = register_netdev(dev);
	if (err) {
		free_netdev(dev);
		return err;
	}

	/* */
	hash = CAPWAP_IFACE_HASH(dev->ifindex);

	spin_lock_irqsave(&sc_iface_lock, flags);

	sc_iface_count++;
	priv->next = sc_iface_hash[hash];
	sc_iface_hash[hash] = priv;
	dev_hold(dev);

	spin_unlock_irqrestore(&sc_iface_lock, flags);

	/* Enable carrier */
	netif_tx_lock_bh(dev);
	netif_carrier_on(dev);
	netif_tx_unlock_bh(dev);

	return dev->ifindex;
}

/* */
int sc_iface_delete(uint32_t ifindex) {
	unsigned long flags;
	struct sc_netdev_priv* priv;

	TRACEKMOD("### sc_iface_delete\n");

	/* */
	spin_lock_irqsave(&sc_iface_lock, flags);

	priv  = sc_iface_hash[CAPWAP_IFACE_HASH(ifindex)];
	while (priv) {
		if (priv->dev->ifindex == ifindex) {
			break;
		}

		priv = priv->next;
	}

	spin_unlock_irqrestore(&sc_iface_lock, flags);

	/* */
	if (!priv) {
		return -ENOENT;
	}

	/* */
	unregister_netdev(priv->dev);
	free_netdev(priv->dev);

	return 0;
}

/* */
void sc_iface_closeall(void) {
	int i;
	unsigned long flags;

	TRACEKMOD("### sc_iface_closeall\n");

	while (sc_iface_count) {
		struct net_device* dev = NULL;

		spin_lock_irqsave(&sc_iface_lock, flags);

		for (i = 0; i < CAPWAP_IFACE_COUNT; i++) {
			if (sc_iface_hash[i]) {
				dev = sc_iface_hash[i]->dev;
				break;
			}
		}

		spin_unlock_irqrestore(&sc_iface_lock, flags);

		/* */
		BUG_ON(!dev);
		unregister_netdev(dev);
		free_netdev(dev);
	}
}
