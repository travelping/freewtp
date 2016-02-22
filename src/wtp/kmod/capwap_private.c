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
int sc_capwap_init(struct sc_capwap_session *session, struct net *net)
{
	int i;

	TRACEKMOD("### sc_capwap_init\n");

	ASSERT_RTNL();

	/* Init session */
	memset(session, 0, sizeof(struct sc_capwap_session));

	session->net = net;

	/* Defragment packets */
	memset(&session->fragments, 0, sizeof(struct sc_capwap_fragment_queue));
	INIT_LIST_HEAD(&session->fragments.lru_list);
	spin_lock_init(&session->fragments.lock);

	for (i = 0; i < STA_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&session->station_list[i]);

	return 0;
}

/* */
void sc_capwap_resetsession(struct sc_capwap_session *session)
{
	TRACEKMOD("### sc_capwap_resetsession\n");

	sc_capwap_close(session);
	sc_capwap_init(session, session->net);
}

/* */
int sc_capwap_sendkeepalive(struct sc_capwap_session *session)
{
	int ret;
	int length;
	uint8_t buffer[CAPWAP_KEEP_ALIVE_MAX_SIZE];

	TRACEKMOD("### sc_capwap_sendkeepalive\n");

	/* Build keepalive */
	length = sc_capwap_createkeepalive(&session->sessionid, buffer, CAPWAP_KEEP_ALIVE_MAX_SIZE);

	/* Send packet */
	ret = sc_capwap_send(session, buffer, length);
	TRACEKMOD("*** Send keep-alive result: %d\n", ret);
	if (ret > 0) {
		ret = 0;
	}

	return ret;
}

int sc_capwap_send(struct sc_capwap_session *session, uint8_t* buffer, int length)
{
	struct kvec vec = {
		.iov_base = buffer,
		.iov_len = length,
	};
        struct msghdr msg = {
		.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL,
        };

	TRACEKMOD("### sc_capwap_send\n");

	return kernel_sendmsg(session->socket, &msg, &vec, 1, vec.iov_len);
}

int sc_capwap_recvpacket(struct sock *sk, struct sk_buff* skb)
{
	struct sc_capwap_session* session;

	TRACEKMOD("### sc_capwap_recvpacket\n");

	CAPWAP_SKB_CB(skb)->flags = SKB_CAPWAP_FLAG_FROM_DATA_CHANNEL;

	sock_hold(sk);

	/* Get session */
	session = (struct sc_capwap_session *)sk->sk_user_data;
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
	if (sc_capwap_parsingpacket(session, skb)) {
		TRACEKMOD("*** Parsing error\n");
		goto drop;
	}

	sock_put(sk);
	return 0;

drop:
	sock_put(sk);
	kfree_skb(skb);

	return 0;
}

/* */
struct sc_capwap_session* sc_capwap_recvunknownkeepalive(struct sc_capwap_session* session,
							 const struct sc_capwap_sessionid_element* sessionid)
{
	TRACEKMOD("### sc_capwap_recvunknownkeepalive\n");

	return NULL;
}

/* */
void sc_capwap_parsingdatapacket(struct sc_capwap_session* session, struct sk_buff* skb)
{
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
		uint32_t hash;
		struct hlist_head *sta_head;
		struct sc_station *sta;

		hash = jhash(dstaddress, ETH_ALEN, GET_RID_HEADER(header)) % STA_HASH_SIZE;
		sta_head = &session->station_list[hash];

		rcu_read_lock();

		sta = sc_find_station(sta_head, GET_RID_HEADER(header), dstaddress);
		if (!sta) {
			rcu_read_unlock();
			TRACEKMOD("*** Radio Id for STA invalid: %d, %pM\n",
				  GET_RID_HEADER(header), dstaddress);
			goto error;
		}

		dev = sc_netlink_getdev_from_wlanid(session->net, GET_RID_HEADER(header), sta->wlanid);
		if (!dev) {
			TRACEKMOD("*** no interface for Radio Id/WLAN Id: %d, %d\n",
				  GET_RID_HEADER(header), sta->wlanid);
				rcu_read_unlock();
				goto error;
		}

		rcu_read_unlock();

		if (!is80211) {
			if (sc_capwap_8023_to_80211(skb, dev->dev_addr)) {
				goto error;
			}
		} else {
			if (memcmp(dev->dev_addr, ((struct ieee80211_hdr*)skb->data)->addr2, ETH_ALEN) != 0) {
				TRACEKMOD("*** Invalid BSSID in 802.11 packet\n");
				goto error;
			}
		}

		TRACEKMOD("** Send packet to interface: %d\n", dev->ifindex);

		/* Send packet */
		local_bh_disable();
		ieee80211_inject_xmit(skb, dev);
		local_bh_enable();
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
