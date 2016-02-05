#ifndef __KMOD_SOCKET_HEADER__
#define __KMOD_SOCKET_HEADER__

#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/skbuff.h>

/* */
#define SOCKET_UDP					0
#define SOCKET_UDPLITE				1

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

/* */
int sc_socket_getpeeraddr(struct sk_buff* skb, union capwap_addr* peeraddr);

/* */
int sc_addr_compare(const union capwap_addr* addr1, const union capwap_addr* addr2);

#endif /* __KMOD_SOCKET_HEADER__ */
