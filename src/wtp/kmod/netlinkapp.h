#ifndef __KMOD_WTP_NETLINKAPP_HEADER__
#define __KMOD_WTP_NETLINKAPP_HEADER__

#include "capwap_rfc.h"
#include "socket.h"

/* */
int sc_netlink_init(void);
void sc_netlink_exit(void);

/* */
struct net_device* sc_netlink_getdev_from_wlanid(uint8_t radioid, uint8_t wlanid);
struct net_device* sc_netlink_getdev_from_bssid(uint8_t radioid, const uint8_t* addr);

/* */
int sc_netlink_notify_recv_keepalive(const union capwap_addr* sockaddr, struct sc_capwap_sessionid_element* sessionid);
int sc_netlink_notify_recv_data(uint8_t* packet, int length);

#endif /* __KMOD_WTP_NETLINKAPP_HEADER__ */
