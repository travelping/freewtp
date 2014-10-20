#include "config.h"
#include <linux/module.h>
#include <linux/kthread.h>
#include <net/ipv6.h>
#include "capwap.h"
#include "nlsmartcapwap.h"
#include "netlinkapp.h"

/* */
static struct sc_capwap_session sc_acsession;

/* */
int sc_capwap_init(uint32_t threads) {
	TRACEKMOD("### sc_capwap_init\n");

	/* Init session */
	memset(&sc_localaddr, 0, sizeof(union capwap_addr));
	memset(&sc_acsession, 0, sizeof(struct sc_capwap_session));
	sc_capwap_initsession(&sc_acsession);

	/* Init sockect */
	return sc_socket_init();
}

/* */
void sc_capwap_close(void) {
	TRACEKMOD("### sc_capwap_close\n");

	/* */
	sc_socket_close();
	sc_capwap_freesession(&sc_acsession);
}

/* */
int sc_capwap_connect(const union capwap_addr* sockaddr, struct sc_capwap_sessionid_element* sessionid, uint16_t mtu) {
	TRACEKMOD("### sc_capwap_connect\n");

	if ((sc_localaddr.ss.ss_family != AF_INET) && (sc_localaddr.ss.ss_family != AF_INET6)) {
		return -ENONET;
	}

	/* AC address */
	if ((sockaddr->ss.ss_family == AF_INET6) && ipv6_addr_v4mapped(&sockaddr->sin6.sin6_addr)) {
		return -EINVAL;
	} else if ((sc_localaddr.ss.ss_family == AF_INET) && (sockaddr->ss.ss_family == AF_INET6)) {
		return -EINVAL;
	}

	/* */
	memcpy(&sc_acsession.peeraddr, sockaddr, sizeof(union capwap_addr));
	memcpy(&sc_acsession.sessionid, sessionid, sizeof(struct sc_capwap_sessionid_element));
	sc_acsession.mtu = mtu;

	return sc_capwap_sendkeepalive();
}

/* */
void sc_capwap_resetsession(void) {
	sc_capwap_freesession(&sc_acsession);

	/* Reinit session */
	memset(&sc_localaddr, 0, sizeof(union capwap_addr));
	memset(&sc_acsession, 0, sizeof(struct sc_capwap_session));
	sc_capwap_initsession(&sc_acsession);
}

/* */
int sc_capwap_sendkeepalive(void) {
	int ret;
	int length;
	uint8_t buffer[CAPWAP_KEEP_ALIVE_MAX_SIZE];

	TRACEKMOD("### sc_capwap_sendkeepalive\n");

	/* Build keepalive */
	length = sc_capwap_createkeepalive(&sc_acsession.sessionid, buffer, CAPWAP_KEEP_ALIVE_MAX_SIZE);

	/* Send packet */
	ret = sc_socket_send(SOCKET_UDP, buffer, length, &sc_acsession.peeraddr);
	if (ret > 0) {
		ret = 0;
	}

	return ret;
}

/* */
struct sc_capwap_session* sc_capwap_getsession(const union capwap_addr* sockaddr) {
	TRACEKMOD("### sc_capwap_getsession\n");

	if (!sockaddr) {
		return &sc_acsession;
	} else if (sc_acsession.peeraddr.ss.ss_family == sockaddr->ss.ss_family) {
		if (sc_acsession.peeraddr.ss.ss_family == AF_INET) {
			if ((sc_acsession.peeraddr.sin.sin_port == sockaddr->sin.sin_port) && (sc_acsession.peeraddr.sin.sin_addr.s_addr == sockaddr->sin.sin_addr.s_addr)) {
				return &sc_acsession;
			}
		} else if (sc_acsession.peeraddr.ss.ss_family == AF_INET6) {
			if ((sc_acsession.peeraddr.sin6.sin6_port == sockaddr->sin6.sin6_port) && !ipv6_addr_cmp(&sc_acsession.peeraddr.sin6.sin6_addr, &sockaddr->sin6.sin6_addr)) {
				return &sc_acsession;
			}
		}
	}

	return NULL;
}

/* */
void sc_capwap_recvpacket(struct sk_buff* skb) {
	union capwap_addr peeraddr;
	struct sc_capwap_session* session;

	TRACEKMOD("### sc_capwap_recvpacket\n");

	/* Get peer address */
	if (sc_socket_getpeeraddr(skb, &peeraddr)) {
		goto drop;
	}

	/* Get session */
	session = sc_capwap_getsession(&peeraddr);
	if (!session) {
		TRACEKMOD("*** Session not found\n");
		goto drop;
	}

	/* Remove UDP header */
	if (!skb_pull(skb, sizeof(struct udphdr))) {
		TRACEKMOD("*** Invalid packet\n");
		goto drop;
	}

	/* Parsing packet */
	if (sc_capwap_parsingpacket(session, &peeraddr, skb)) {
		TRACEKMOD("*** Parsing error\n");
		goto drop;
	}

	return;

drop:
	kfree_skb(skb);
}

/* */
struct sc_capwap_session* sc_capwap_recvunknownkeepalive(const union capwap_addr* sockaddr, const struct sc_capwap_sessionid_element* sessionid) {
	TRACEKMOD("### sc_capwap_recvunknownkeepalive\n");

	return NULL;
}

/* */
void sc_capwap_parsingdatapacket(struct sc_capwap_session* session, struct sk_buff* skb) {
	TRACEKMOD("### sc_capwap_parsingdatapacket\n");

}

/* */
void sc_capwap_parsingmgmtpacket(struct sc_capwap_session* session, struct sk_buff* skb) {
	TRACEKMOD("### sc_capwap_parsingmgmtpacket\n");

	/* Send packet with capwap header into userspace */
	sc_netlink_notify_recv_data(skb->data, skb->len);
}
