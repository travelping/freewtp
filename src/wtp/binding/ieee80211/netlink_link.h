#ifndef __NETLINK_LINK_HEADER__
#define __NETLINK_LINK_HEADER__

#include <linux/rtnetlink.h>
#include <linux/netlink.h>

/* */
#ifndef IFLA_IFNAME
#define IFLA_IFNAME					3
#endif

#ifndef IFLA_WIRELESS
#define IFLA_WIRELESS				11
#endif

#ifndef IFLA_OPERSTATE
#define IFLA_OPERSTATE				16
#endif

#ifndef IFLA_LINKMODE
#define IFLA_LINKMODE				17
#endif

#ifndef IF_OPER_DORMANT
#define IF_OPER_DORMANT				5
#endif

#ifndef IF_OPER_UP
#define IF_OPER_UP					6
#endif

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP				0x10000
#endif

#ifndef IFF_DORMANT
#define IFF_DORMANT					0x20000
#endif

/* */
struct netlink {
	int sock;
	void (*newlink_event)(wifi_global_handle handle, struct ifinfomsg* infomsg, uint8_t* data, int length);
	void (*dellink_event)(wifi_global_handle handle, struct ifinfomsg* infomsg, uint8_t* data, int length);

	int nl_sequence;
};

/* */
struct netlink* netlink_init(void);
void netlink_free(struct netlink* netlinkhandle);

/* */
int netlink_set_link_status(struct netlink* netlinkhandle, int ifindex, int linkmode, int operstate);

/* */
void netlink_event_receive(int fd, void** params, int paramscount);

#endif /* __NETLINK_LINK_HEADER__ */
