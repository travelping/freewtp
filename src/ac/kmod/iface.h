#ifndef __KMOD_AC_IFACE_HEADER__
#define __KMOD_AC_IFACE_HEADER__

/* */
struct sc_netdev_priv {
	struct list_head list;
	struct net_device* dev;

	spinlock_t lock;

	struct list_head list_stations;
	struct list_head list_connections;

	struct sc_netdev_priv* __rcu next;
};

/* */
int sc_iface_create(const char* ifname, uint16_t mtu);
int sc_iface_delete(uint32_t ifindex);

/* */
struct sc_netdev_priv* sc_iface_search(uint32_t ifindex);

/* */
void sc_iface_closeall(void);

#endif /* __KMOD_AC_IFACE_HEADER__ */
