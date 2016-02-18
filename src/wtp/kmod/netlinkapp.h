#ifndef __KMOD_WTP_NETLINKAPP_HEADER__
#define __KMOD_WTP_NETLINKAPP_HEADER__

#include "capwap_rfc.h"
#include "capwap.h"

/* */
int sc_netlink_init(void);
void sc_netlink_exit(void);

/* */
struct net_device* sc_netlink_getdev_from_wlanid(struct net *net, uint8_t radioid, uint8_t wlanid);
struct net_device* sc_netlink_getdev_from_bssid(struct net *net, uint8_t radioid, const uint8_t* addr);

/* */
int sc_netlink_notify_recv_keepalive(struct net *net,
				     struct sc_capwap_sessionid_element* sessionid);
int sc_netlink_notify_recv_data(struct net *net, uint8_t* packet, int length);

#endif /* __KMOD_WTP_NETLINKAPP_HEADER__ */
