#include "config.h"
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <net/udp.h>
#include "socket.h"
#include "capwap.h"

/* Socket */
#define SOCKET_COUNT				2
static struct socket* sc_sockets[SOCKET_COUNT];

/* */
int sc_socket_recvpacket(struct sock* sk, struct sk_buff* skb) {
	TRACEKMOD("### sc_socket_recvpacket\n");

	/* */
	CAPWAP_SKB_CB(skb)->flags = SKB_CAPWAP_FLAG_FROM_DATA_CHANNEL;

	/* */
	sc_capwap_recvpacket(skb);
	return 0;
}

/* */
static int sc_socket_create(int type, union capwap_addr* sockaddr, uint16_t protocol) {
	int ret;

	TRACEKMOD("### sc_socket_create\n");

	/* Create socket */
	ret = sock_create_kern(sockaddr->ss.ss_family, SOCK_DGRAM, protocol, &sc_sockets[type]);
	if (ret) {
		return ret;
	}

	/* Bind to interface */
	ret = kernel_bind(sc_sockets[type], &sockaddr->sa, sizeof(union capwap_addr));
	if (ret) {
		goto failure;
	}

	/* Set callback */
	udp_sk(sc_sockets[type]->sk)->encap_type = 1;
	udp_sk(sc_sockets[type]->sk)->encap_rcv = sc_socket_recvpacket;

	/* */
	if (!((sockaddr->ss.ss_family == AF_INET) ? sockaddr->sin.sin_port : sockaddr->sin6.sin6_port)) {
		union capwap_addr localaddr;
		int localaddrsize = sizeof(union capwap_addr);

		/* Retrieve port */
		ret = kernel_getsockname(sc_sockets[type], &localaddr.sa, &localaddrsize);
		if (ret) {
			goto failure;
		}

		/* */
		if ((sockaddr->ss.ss_family == AF_INET) && (localaddr.ss.ss_family == AF_INET)) {
			sockaddr->sin.sin_port = localaddr.sin.sin_port;
		} else if ((sockaddr->ss.ss_family == AF_INET6) && (localaddr.ss.ss_family == AF_INET6)) {
			sockaddr->sin6.sin6_port = localaddr.sin6.sin6_port;
		} else {
			ret = -EFAULT;
			goto failure;
		}
	}

	return 0;

failure:
	sock_release(sc_sockets[type]);
	sc_sockets[type] = 0;
	return ret;
}

/* */
int sc_socket_getpeeraddr(struct sk_buff* skb, union capwap_addr* peeraddr) {
	unsigned char* nethdr;

	TRACEKMOD("### sc_socket_getpeeraddr\n");

	/* */
	nethdr = skb_network_header(skb);
	if (!nethdr) {
		return -EINVAL;
	}

	/* */
	switch (ntohs(skb->protocol)) {
		case ETH_P_IP: {
			/* Validate IPv4 header */
			if ((nethdr[0] & 0xf0) != 0x40) {
				return -EINVAL;
			}

			/* Retrieve address */
			peeraddr->sin.sin_family = AF_INET;
			peeraddr->sin.sin_addr.s_addr = ((struct iphdr*)nethdr)->saddr;
			peeraddr->sin.sin_port = udp_hdr(skb)->source;
			break;
		}

		case ETH_P_IPV6: {
			/* Validate IPv6 header */
			if ((nethdr[0] & 0xf0) != 0x60) {
				return -EINVAL;
			}

			/* Retrieve address */
			peeraddr->sin6.sin6_family = AF_INET6;
			memcpy(&peeraddr->sin6.sin6_addr, &((struct ipv6hdr*)nethdr)->saddr, sizeof(struct  in6_addr));
			peeraddr->sin6.sin6_port = udp_hdr(skb)->source;
			break;
		}

		default: {
			return -EINVAL;
		}
	}

	return 0;
}

/* */
int sc_socket_send(int type, uint8_t* buffer, int length, union capwap_addr* sockaddr) {
	struct kvec vec;
	struct msghdr msg;

	TRACEKMOD("### sc_socket_send\n");

	/* */
	vec.iov_base = buffer;
	vec.iov_len = length;

	/* */
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = sockaddr;
	msg.msg_namelen = sizeof(union capwap_addr);
	msg.msg_flags = MSG_NOSIGNAL | MSG_DONTWAIT;

	/* */
	return kernel_sendmsg(sc_sockets[type], &msg, &vec, 1, length);
}

/* */
int sc_socket_init(void) {
	TRACEKMOD("### sc_socket_init\n");

	memset(sc_sockets, 0, sizeof(sc_sockets));
	return 0;
}

/* */
int sc_socket_bind(union capwap_addr* sockaddr) {
	int ret;

	TRACEKMOD("### sc_socket_bind\n");

	/* */
	if (sc_sockets[SOCKET_UDP] || sc_sockets[SOCKET_UDPLITE]) {
		return -EBUSY;
	}

	/* UDP socket */
	ret = sc_socket_create(SOCKET_UDP, sockaddr, IPPROTO_UDP);
	if (ret) {
		goto failure;
	}

	/* UDPLite socket */
	ret = sc_socket_create(SOCKET_UDPLITE, sockaddr, IPPROTO_UDPLITE);
	if (ret) {
		goto failure;
	}

	/* */
	udp_encap_enable();
	if (sockaddr->ss.ss_family == AF_INET6) {
		udpv6_encap_enable();
	}

	return 0;

failure:
	sc_socket_close();
	return ret;
}

/* */
void sc_socket_close(void) {
	TRACEKMOD("### sc_socket_close\n");

	/* Close sockets */
	if (sc_sockets[SOCKET_UDP]) {
		kernel_sock_shutdown(sc_sockets[SOCKET_UDP], SHUT_RDWR);
		sock_release(sc_sockets[SOCKET_UDP]);
	}

	if (sc_sockets[SOCKET_UDPLITE]) {
		kernel_sock_shutdown(sc_sockets[SOCKET_UDPLITE], SHUT_RDWR);
		sock_release(sc_sockets[SOCKET_UDPLITE]);
	}

	memset(sc_sockets, 0, sizeof(sc_sockets));
}

/* */
int sc_addr_compare(const union capwap_addr* addr1, const union capwap_addr* addr2) {
	TRACEKMOD("### sc_addr_compare\n");

	if (addr1->ss.ss_family == addr2->ss.ss_family) {
		if (addr1->ss.ss_family == AF_INET) {
			return (((addr1->sin.sin_addr.s_addr == addr2->sin.sin_addr.s_addr) && (addr1->sin.sin_port == addr2->sin.sin_port)) ? 0 : -1);
		} else if (addr1->ss.ss_family == AF_INET6) {
			return ((!memcmp(&addr1->sin6.sin6_addr, &addr2->sin6.sin6_addr, sizeof(struct in6_addr)) && (addr1->sin6.sin6_port == addr2->sin6.sin6_port)) ? 0 : -1);
		}
	}

	return -1;
}
