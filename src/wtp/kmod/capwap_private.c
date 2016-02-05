#include "config.h"

#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/etherdevice.h>
#include <linux/ieee80211.h>

#include <net/net_namespace.h>
#include <net/mac80211.h>
#include <net/ipv6.h>

#include "capwap.h"
#include "nlsmartcapwap.h"
#include "netlinkapp.h"

/* */
static struct sc_capwap_session sc_acsession;

/* */
int sc_capwap_init(struct net *net) {
	TRACEKMOD("### sc_capwap_init\n");

	/* Init session */
	memset(&sc_acsession, 0, sizeof(struct sc_capwap_session));
	sc_capwap_initsession(&sc_acsession);

	sc_acsession.net = net;

	/* Init sockect */
	memset(&sc_localaddr, 0, sizeof(union capwap_addr));
	return sc_socket_init();
}

/* */
void sc_capwap_close(void) {
	TRACEKMOD("### sc_capwap_close\n");

	/* */
	sc_socket_close();
	memset(&sc_localaddr, 0, sizeof(union capwap_addr));
	sc_capwap_freesession(&sc_acsession);
}

/* */
int sc_capwap_connect(struct net *net, const union capwap_addr* sockaddr,
		      struct sc_capwap_sessionid_element* sessionid, uint16_t mtu) {
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
	TRACEKMOD("### sc_capwap_resetsession\n");

	/* */
	sc_capwap_freesession(&sc_acsession);

	/* Reinit session */
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
	TRACEKMOD("*** Send keep-alive result: %d\n", ret);
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
	uint8_t* pos;
	uint8_t* dstaddress;
	struct net_device* dev;
	struct sc_capwap_header* header = (struct sc_capwap_header*)skb->data;
	int is80211 = (IS_FLAG_T_HEADER(header) ? 1 : 0);
	struct sc_capwap_radio_addr* radioaddr = NULL;
	int radioaddrsize = 0;
	struct sc_capwap_wireless_information* winfo = NULL;
	struct sc_capwap_destination_wlans* destwlan = NULL;
	int winfosize = 0;

	TRACEKMOD("### sc_capwap_parsingdatapacket\n");

	/* Retrieve optional attribute */
	pos = skb->data + sizeof(struct sc_capwap_header);
	if (IS_FLAG_M_HEADER(header)) {
		radioaddr = (struct sc_capwap_radio_addr*)pos;
		radioaddrsize = (sizeof(struct sc_capwap_radio_addr) + radioaddr->length + 3) & ~3;
		pos += radioaddrsize;
	}

	if (IS_FLAG_W_HEADER(header)) {
		winfo = (struct sc_capwap_wireless_information*)pos;
		destwlan = (struct sc_capwap_destination_wlans*)(pos + sizeof(struct sc_capwap_wireless_information));
		winfosize = (sizeof(struct sc_capwap_wireless_information) + winfo->length + 3) & ~3;
		pos += winfosize;
	}

	/* Body packet */
	skb_pull(skb, GET_HLEN_HEADER(header) * 4);

	dstaddress = (is80211 ? ieee80211_get_DA((struct ieee80211_hdr*)skb->data) : (uint8_t*)((struct ethhdr*)skb->data)->h_dest);
	if (is_multicast_ether_addr(dstaddress)) {
		/* Accept only broadcast packet with wireless information */
		if (winfo) {
			uint8_t wlanid = 1;
			uint16_t bitmask = be16_to_cpu(destwlan->wlanidbitmap);
			while (bitmask) {
				if (bitmask & 0x01) {
					dev = sc_netlink_getdev_from_wlanid(session->net, GET_RID_HEADER(header), wlanid);
					if (dev) {
						struct sk_buff* clone = skb_copy_expand(skb, skb_headroom(skb), skb_tailroom(skb), GFP_KERNEL);
						if (!clone) {
							goto error;
						}

						/* */
						if (!is80211) { 
							if (sc_capwap_8023_to_80211(clone, dev->dev_addr)) {
								kfree_skb(clone);
								goto error;
							}
						}

						TRACEKMOD("*** Send broadcast packet to interface: %d\n", dev->ifindex);

						/* Send packet */
						local_bh_disable();
						ieee80211_inject_xmit(clone, dev);
						local_bh_enable();
					} else {
						TRACEKMOD("*** Unknown wlanid: %d\n", (int)wlanid);
					}
				}

				/* Next */
				wlanid++;
				bitmask >>= 1;
			}
		} else {
			TRACEKMOD("*** Invalid broadcast packet\n");
		}

		/* Free broadcast packet */
		kfree_skb(skb);
	} else {
		/* Accept only 802.11 frame or 802.3 frame with radio address */
		if (is80211 || (radioaddr && (radioaddr->length == MACADDRESS_EUI48_LENGTH))){
			if (!is80211) { 
				if (sc_capwap_8023_to_80211(skb, radioaddr->addr)) {
					goto error;
				}
			}

			/* */
			dev = sc_netlink_getdev_from_bssid(session->net, GET_RID_HEADER(header), ((struct ieee80211_hdr*)skb->data)->addr2);
			if (!dev) {
				goto error;
			}

			TRACEKMOD("** Send packet to interface: %d\n", dev->ifindex);

			/* Send packet */
			local_bh_disable();
			ieee80211_inject_xmit(skb, dev);
			local_bh_enable();
		} else {
			goto error;
		}
	}

	return;

error:
	TRACEKMOD("*** Invalid packet\n");
	kfree_skb(skb);
}

/* */
void sc_capwap_parsingmgmtpacket(struct sc_capwap_session* session, struct sk_buff* skb) {
	TRACEKMOD("### sc_capwap_parsingmgmtpacket\n");

	/* Send packet with capwap header into userspace */
	sc_netlink_notify_recv_data(session->net, skb->data, skb->len);
}
