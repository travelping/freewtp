#ifndef __KMOD_CAPWAP_HEADER__
#define __KMOD_CAPWAP_HEADER__

#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/skbuff.h>

#include <net/protocol.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>

#include "capwap_rfc.h"

/* */
#define STA_HASH_SIZE       16

/* */
#define MAX_MTU						9000
#define DEFAULT_MTU 				1450
#define MIN_MTU						500
#define IEEE80211_MTU				7981

/* */
#define CAPWAP_FRAGMENT_QUEUE		16

/* */
#define CAPWAP_FRAGMENT_ENABLE		0x0001
#define CAPWAP_FRAGMENT_LRUQUEUE	0x0002
#define CAPWAP_FRAGMENT_LAST		0x0004

/* */
#define SKB_CAPWAP_FLAG_FROM_DATA_CHANNEL			0x0001
#define SKB_CAPWAP_FLAG_FROM_USER_SPACE				0x0002
#define SKB_CAPWAP_FLAG_FROM_AC_TAP					0x0004
#define SKB_CAPWAP_FLAG_FROM_IEEE80211				0x0008

#define SKB_CAPWAP_FLAG_SESSIONID					0x0100
#define SKB_CAPWAP_FLAG_RADIOID						0x0200
#define SKB_CAPWAP_FLAG_BINDING						0x0400
#define SKB_CAPWAP_FLAG_WIRELESSINFORMATION			0x0800
#define SKB_CAPWAP_FLAG_FRAGMENT					0x1000

/* Universal socket address */
union capwap_addr {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr_storage ss;
};

struct sc_station {
	struct hlist_node station_list;

	uint8_t radioid;
	uint8_t mac[ETH_ALEN];
	uint8_t wlanid;

	struct rcu_head rcu_head;
};

struct sc_skb_capwap_cb {
	uint16_t flags;

	/* Session ID */
	struct sc_capwap_sessionid_element sessionid;

	/* Capwap information */
	uint8_t radioid;
	uint8_t binding;

	/* Wireless Information */
	uint8_t winfo_rssi;
	uint8_t winfo_snr;
	uint16_t winfo_rate;

	/* Fragment */
	uint16_t frag_offset;
	uint16_t frag_length;
};

#define CAPWAP_SKB_CB(skb)					((struct sc_skb_capwap_cb*)((skb)->cb))

/* */
struct sc_capwap_fragment {
	struct list_head lru_list;

	uint8_t flags;
	ktime_t tstamp;

	uint16_t fragmentid;

	struct sk_buff* fragments;
	struct sk_buff* lastfragment;
	int recvlength;
	int totallength;
};

/* */
struct sc_capwap_fragment_queue {
	spinlock_t lock;

	struct list_head lru_list;
	struct sc_capwap_fragment queues[CAPWAP_FRAGMENT_QUEUE];
};

/* */
struct sc_capwap_session {
	struct net *net;

	struct socket *socket;
	struct udp_port_cfg udp_config;
	uint16_t mtu;
	struct sc_capwap_sessionid_element sessionid;

	atomic_t fragmentid;
	struct sc_capwap_fragment_queue fragments;

	struct hlist_head station_list[STA_HASH_SIZE];
};

/* Dipendent implementation function */
int sc_capwap_recvpacket(struct sock *sk, struct sk_buff* skb);
struct sc_capwap_session* sc_capwap_recvunknownkeepalive(struct sc_capwap_session* session,
							 const struct sc_capwap_sessionid_element* sessionid);

void sc_capwap_parsingdatapacket(struct sc_capwap_session* session, struct sk_buff* skb);
void sc_capwap_parsingmgmtpacket(struct sc_capwap_session* session, struct sk_buff* skb);

/* Indipendent implementation function */
int sc_capwap_create(struct sc_capwap_session *session);
int sc_capwap_send(struct sc_capwap_session *session, uint8_t* buffer, int length);
void sc_capwap_close(struct sc_capwap_session *session);

int sc_capwap_8023_to_80211(struct sk_buff* skb, const uint8_t* bssid);
int sc_capwap_80211_to_8023(struct sk_buff* skb);

void sc_capwap_sessionid_printf(const struct sc_capwap_sessionid_element* sessionid, char* string);

int sc_capwap_createkeepalive(struct sc_capwap_sessionid_element* sessionid, uint8_t* buffer, int size);
int sc_capwap_parsingpacket(struct sc_capwap_session* session, struct sk_buff* skb);

struct sc_capwap_radio_addr* sc_capwap_setradiomacaddress(uint8_t* buffer, int size, uint8_t* bssid);
struct sc_capwap_wireless_information* sc_capwap_setwinfo_frameinfo(uint8_t* buffer, int size, uint8_t rssi, uint8_t snr, uint16_t rate);
struct sc_capwap_wireless_information* sc_capwap_setwinfo_destwlans(uint8_t* buffer, int size, uint16_t wlanidbitmap);

int sc_capwap_forwarddata(struct sc_capwap_session* session, uint8_t radioid, uint8_t binding, struct sk_buff* skb, uint32_t flags, struct sc_capwap_radio_addr* radioaddr, int radioaddrlength, struct sc_capwap_wireless_information* winfo, int winfolength);

/* Private funciotn */
#include "capwap_private.h"

#endif /* __KMOD_CAPWAP_HEADER__ */
