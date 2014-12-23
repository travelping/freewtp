#include "config.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/smp.h>
#include "iface.h"
#include "station.h"
#include "capwap.h"

/* */
#define CAPWAP_IFACE_COUNT				8
#define CAPWAP_IFACE_HASH(x)			((x) % CAPWAP_IFACE_COUNT)

static LIST_HEAD(sc_iface_list);
static struct sc_netdev_priv* __rcu sc_iface_hash[CAPWAP_IFACE_COUNT];

/* */
static void sc_iface_netdev_uninit(struct net_device* dev) {
	struct sc_netdev_priv* search;
	struct sc_capwap_station* temp;
	struct sc_capwap_station* station;
	int hash = CAPWAP_IFACE_HASH(dev->ifindex);
	struct sc_netdev_priv* priv = (struct sc_netdev_priv*)netdev_priv(dev);

	TRACEKMOD("### sc_iface_netdev_uninit\n");

	sc_capwap_update_lock();

	/* Close stations */
	list_for_each_entry_safe(station, temp, &priv->list_stations, list_dev) {
		sc_stations_releaseconnection(station);
		sc_stations_free(station);
	}

	/* */
	if (!list_empty(&priv->list_stations)) {
		TRACEKMOD("*** Bug: the list stations of interface is not empty\n");
	}

	if (!list_empty(&priv->list_connections)) {
		TRACEKMOD("*** Bug: the list connections of interface is not empty\n");
	}

	/* Remove interface from hash */
	search  = rcu_dereference_protected(sc_iface_hash[hash], sc_capwap_update_lock_is_locked());
	if (search) {
		if (priv == search) {
			netif_tx_lock_bh(dev);
			netif_carrier_off(dev);
			netif_tx_unlock_bh(dev);

			rcu_assign_pointer(sc_iface_hash[hash], priv->next);

			list_del_rcu(&priv->list);
			synchronize_net();

			dev_put(dev);
		} else {
			while (rcu_access_pointer(search->next) && (rcu_access_pointer(search->next) != priv)) {
				search = rcu_dereference_protected(search->next, sc_capwap_update_lock_is_locked());
			}

			if (rcu_access_pointer(search->next)) {
				netif_tx_lock_bh(dev);
				netif_carrier_off(dev);
				netif_tx_unlock_bh(dev);

				rcu_assign_pointer(search->next, priv->next);

				list_del_rcu(&priv->list);
				synchronize_net();

				dev_put(dev);
			}
		}
	}

	sc_capwap_update_unlock();
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
	struct sc_netdev_priv* priv = (struct sc_netdev_priv*)netdev_priv(dev);

	TRACEKMOD("### sc_iface_netdev_tx %d\n", smp_processor_id());

	if (dev->flags & IFF_UP) {
		/* Ignore 802.1ad */
		if (skb->vlan_proto == htons(ETH_P_8021AD) || (eth_hdr(skb)->h_proto == htons(ETH_P_8021AD))) {
			goto drop;
		}

		/* */
		spin_lock(&priv->lock);
		dev->stats.tx_packets++;
		dev->stats.tx_bytes += skb->len;
		spin_unlock(&priv->lock);

		/* */
		CAPWAP_SKB_CB(skb)->flags = SKB_CAPWAP_FLAG_FROM_AC_TAP;
		sc_capwap_recvpacket(skb);
	} else {
		goto drop;
	}

	return 0;

drop:
	/* Drop packet */
	kfree_skb(skb);

	/* */
	spin_lock(&priv->lock);
	dev->stats.rx_dropped++;
	spin_unlock(&priv->lock);

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
	struct sc_netdev_priv* devpriv = (struct sc_netdev_priv*)netdev_priv(dev);

	TRACEKMOD("### sc_iface_netdev_setup\n");

	/* */
	memset(devpriv, 0, sizeof(struct sc_netdev_priv));
	devpriv->dev = dev;
	spin_lock_init(&devpriv->lock);
	INIT_LIST_HEAD(&devpriv->list_stations);
	INIT_LIST_HEAD(&devpriv->list_connections);
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

	/* */
	sc_capwap_update_lock();

	list_add_rcu(&priv->list, &sc_iface_list);

	priv->next = rcu_dereference_protected(sc_iface_hash[hash], sc_capwap_update_lock_is_locked());
	rcu_assign_pointer(sc_iface_hash[hash], priv);
	dev_hold(dev);

	sc_capwap_update_unlock();

	/* Enable carrier */
	netif_tx_lock_bh(dev);
	netif_carrier_on(dev);
	netif_tx_unlock_bh(dev);

	return dev->ifindex;
}

/* */
int sc_iface_delete(uint32_t ifindex) {
	struct sc_netdev_priv* priv;
	struct net_device* dev = NULL;

	TRACEKMOD("### sc_iface_delete\n");

	rcu_read_lock();

	/* Search device */
	priv = sc_iface_search(ifindex);
	if (priv) {
		dev = priv->dev;
	}

	rcu_read_unlock();

	/* */
	if (!dev) {
		return -ENOENT;
	}

	/* Unregister device */
	unregister_netdev(dev);
	free_netdev(dev);

	return 0;
}

/* */
struct sc_netdev_priv* sc_iface_search(uint32_t ifindex) {
	struct sc_netdev_priv* priv;

	TRACEKMOD("### sc_iface_search\n");

	priv = rcu_dereference_check(sc_iface_hash[CAPWAP_IFACE_HASH(ifindex)], lockdep_is_held(&sc_iface_mutex));
	while (priv) {
		if (priv->dev->ifindex == ifindex) {
			break;
		}

		/* */
		priv = rcu_dereference_check(priv->next, lockdep_is_held(&sc_iface_mutex));
	}

	return priv;
}

/* */
void sc_iface_closeall(void) {
	struct sc_netdev_priv* priv;

	TRACEKMOD("### sc_iface_closeall\n");

	for (;;) {
		struct net_device* dev = NULL;

		rcu_read_lock();

		/* Get device */
		priv = list_first_or_null_rcu(&sc_iface_list, struct sc_netdev_priv, list);
		if (priv) {
			dev = priv->dev;
		}

		rcu_read_unlock();

		/* */
		if (!dev) {
			break;
		}

		/* Unregister device */
		unregister_netdev(dev);
		free_netdev(dev);
	}
}
