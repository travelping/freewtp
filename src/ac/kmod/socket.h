#ifndef __KMOD_SOCKET_HEADER__
#define __KMOD_SOCKET_HEADER__

#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/skbuff.h>

/* */
#define SOCKET_UDP					0
#define SOCKET_UDPLITE				1

/* Little socket address */
struct capwap_addr_little {
	uint8_t family;
	union {
		struct in_addr addr4;
		struct in6_addr addr6;
	};
	uint16_t port;
};

/* Universal socket address */
union capwap_addr {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr_storage ss;
};

/* */
int sc_socket_init(void);
void sc_socket_close(void);

/* */
int sc_socket_bind(union capwap_addr* sockaddr);
int sc_socket_send(int type, uint8_t* buffer, int length, union capwap_addr* sockaddr);
int sc_socket_getpeeraddr(struct sk_buff* skb, union capwap_addr* peeraddr);

/* */
int sc_addr_compare(const union capwap_addr* addr1, const union capwap_addr* addr2);
void sc_addr_tolittle(const union capwap_addr* addr, struct capwap_addr_little* little);
void sc_addr_fromlittle(const struct capwap_addr_little* little, union capwap_addr* addr);

#endif /* __KMOD_SOCKET_HEADER__ */
