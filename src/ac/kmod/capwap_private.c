#include "config.h"
#include <linux/module.h>
#include <linux/hash.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/etherdevice.h>
#include <linux/smp.h>
#include <linux/lockdep.h>
#include <net/ipv6.h>
#include <net/cfg80211.h>
#include "socket.h"
#include "capwap.h"
#include "nlsmartcapwap.h"
#include "netlinkapp.h"
#include "iface.h"
#include "station.h"

/* */
#define SESSION_HASH_SIZE_SHIFT				16
#define SESSION_HASH_SIZE					(1 << SESSION_HASH_SIZE_SHIFT)
#define MAX_WORKER_THREAD					32

/* */
static DEFINE_MUTEX(sc_session_update_mutex);

/* Sessions */
static struct list_head sc_session_setup_list;
static struct list_head sc_session_running_list;

static struct sc_capwap_session_priv* __rcu sc_session_hash_ipaddr[SESSION_HASH_SIZE];
static struct sc_capwap_session_priv* __rcu sc_session_hash_sessionid[SESSION_HASH_SIZE];

/* Threads */
static DEFINE_SPINLOCK(sc_session_threads_lock);
static uint32_t sc_session_threads_pos;
static uint32_t sc_session_threads_count;
static struct sc_capwap_workthread sc_session_threads[MAX_WORKER_THREAD];

/* */
static uint32_t sc_capwap_hash_ipaddr(const union capwap_addr* peeraddr) {
	TRACEKMOD("### sc_capwap_hash_ipaddr\n");

	return hash_32(((peeraddr->ss.ss_family == AF_INET) ? peeraddr->sin.sin_addr.s_addr : ipv6_addr_hash(&peeraddr->sin6.sin6_addr)), SESSION_HASH_SIZE_SHIFT);
}

/* */
static uint32_t sc_capwap_hash_sessionid(const struct sc_capwap_sessionid_element* sessionid) {
	TRACEKMOD("### sc_capwap_hash_sessionid\n");

	return ((sessionid->id32[0] ^ sessionid->id32[1] ^ sessionid->id32[2] ^ sessionid->id32[3]) % SESSION_HASH_SIZE);
}

/* */
static void sc_capwap_closesession(struct sc_capwap_session_priv* sessionpriv) {
	uint32_t hash;
	struct sc_capwap_session_priv* search;
	struct sc_capwap_station* temp;
	struct sc_capwap_station* station;

	TRACEKMOD("### sc_capwap_closesession\n");

	/* Close stations */
	list_for_each_entry_safe(station, temp, &sessionpriv->list_stations, list_session) {
		sc_stations_releaseconnection(station);
		sc_stations_free(station);
	}

	/* */
	if (!list_empty(&sessionpriv->list_stations)) {
		TRACEKMOD("*** Bug: the list stations of session is not empty\n");
	}

	if (!list_empty(&sessionpriv->list_connections)) {
		TRACEKMOD("*** Bug: the list connections of session is not empty\n");
	}

	/* Remove session from list reference */
	if (sessionpriv->session.peeraddr.ss.ss_family != AF_UNSPEC) {
		/* IP Address */
		hash = sc_capwap_hash_ipaddr(&sessionpriv->session.peeraddr);
		search = rcu_dereference_protected(sc_session_hash_ipaddr[hash], sc_capwap_update_lock_is_locked());

		if (search) {
			if (search == sessionpriv) {
				rcu_assign_pointer(sc_session_hash_ipaddr[hash], sessionpriv->next_ipaddr);
			} else {
				while (rcu_access_pointer(search->next_ipaddr) && (rcu_access_pointer(search->next_ipaddr) != sessionpriv)) {
					search = rcu_dereference_protected(search->next_ipaddr, sc_capwap_update_lock_is_locked());
				}

				if (rcu_access_pointer(search->next_ipaddr)) {
					rcu_assign_pointer(search->next_ipaddr, sessionpriv->next_ipaddr);
				}
			}
		}

		/* Session ID */
		hash = sc_capwap_hash_sessionid(&sessionpriv->session.sessionid);
		search = rcu_dereference_protected(sc_session_hash_sessionid[hash], sc_capwap_update_lock_is_locked());

		if (search) {
			if (search == sessionpriv) {
				rcu_assign_pointer(sc_session_hash_sessionid[hash], sessionpriv->next_sessionid);
			} else {
				while (rcu_access_pointer(search->next_sessionid) && (rcu_access_pointer(search->next_sessionid) != sessionpriv)) {
					search = rcu_dereference_protected(search->next_sessionid, sc_capwap_update_lock_is_locked());
				}

				if (rcu_access_pointer(search->next_sessionid)) {
					rcu_assign_pointer(search->next_sessionid, sessionpriv->next_sessionid);
				}
			}
		}
	}

	/* */
	list_del_rcu(&sessionpriv->list);
	synchronize_net();

	/* Free memory */
	sc_capwap_freesession(&sessionpriv->session);
	kfree(sessionpriv);
}

/* */
static void sc_capwap_closesessions(void) {
	struct sc_capwap_session_priv* sessionpriv;
	struct sc_capwap_session_priv* temp;

	TRACEKMOD("### sc_capwap_closesessions\n");

	/* */
	sc_capwap_update_lock();

	/* */
	list_for_each_entry_safe(sessionpriv, temp, &sc_session_setup_list, list) {
		sc_capwap_closesession(sessionpriv);
	}

	/* */
	list_for_each_entry_safe(sessionpriv, temp, &sc_session_running_list, list) {
		sc_capwap_closesession(sessionpriv);
	}

	/* */
	sc_capwap_update_unlock();
}

/* */
static struct sc_capwap_session_priv* sc_capwap_getsession_ipaddr(const union capwap_addr* sockaddr) {
	struct sc_capwap_session_priv* sessionpriv;

	TRACEKMOD("### sc_capwap_getsession_ipaddr\n");

	/* */
	sessionpriv = rcu_dereference_check(sc_session_hash_ipaddr[sc_capwap_hash_ipaddr(sockaddr)], sc_capwap_update_lock_is_locked());
	while (sessionpriv) {
		if (!sc_addr_compare(sockaddr, &sessionpriv->session.peeraddr)) {
			break;
		}

		/* */
		sessionpriv = rcu_dereference_check(sessionpriv->next_ipaddr, sc_capwap_update_lock_is_locked());
	}

	return sessionpriv;
}

/* */
static struct sc_capwap_session_priv* sc_capwap_getsession_sessionid(const struct sc_capwap_sessionid_element* sessionid) {
	struct sc_capwap_session_priv* sessionpriv;

	TRACEKMOD("### sc_capwap_getsession_sessionid\n");

	/* */
	sessionpriv = rcu_dereference_check(sc_session_hash_sessionid[sc_capwap_hash_sessionid(sessionid)], sc_capwap_update_lock_is_locked());
	while (sessionpriv) {
		if (!memcmp(&sessionpriv->session.sessionid, sessionid, sizeof(struct sc_capwap_sessionid_element))) {
			break;
		}

		/* */
		sessionpriv = rcu_dereference_check(sessionpriv->next_sessionid, sc_capwap_update_lock_is_locked());
	}

	return sessionpriv;
}

/* */
static int sc_capwap_deletesetupsession(const struct sc_capwap_sessionid_element* sessionid) {
	int ret = -ENOENT;
	struct sc_capwap_session_priv* sessionpriv;

	TRACEKMOD("### sc_capwap_deletesetupsession\n");

	/* */
	sc_capwap_update_lock();

	list_for_each_entry(sessionpriv, &sc_session_setup_list, list) {
		if (!memcmp(&sessionpriv->session.sessionid, sessionid, sizeof(struct sc_capwap_sessionid_element))) {
#ifdef DEBUGKMOD
			do {
				char sessionname[33];
				sc_capwap_sessionid_printf(&sessionpriv->session.sessionid, sessionname);
				TRACEKMOD("*** Delete setup session: %s\n", sessionname);
			} while(0);
#endif
			sc_capwap_closesession(sessionpriv);
			ret = 0;
			break;
		}
	}

	/* */
	sc_capwap_update_unlock();
	return ret;
}

/* */
static int sc_capwap_deleterunningsession(const struct sc_capwap_sessionid_element* sessionid) {
	int ret = -ENOENT;
	struct sc_capwap_session_priv* sessionpriv;

	TRACEKMOD("### sc_capwap_deleterunningsession\n");

	/* */
	sc_capwap_update_lock();

	/* Search session with address hash */
	sessionpriv = sc_capwap_getsession_sessionid(sessionid);
	if (sessionpriv) {
#ifdef DEBUGKMOD
		do {
			char sessionname[33];
			sc_capwap_sessionid_printf(&sessionpriv->session.sessionid, sessionname);
			TRACEKMOD("*** Delete running session: %s\n", sessionname);
		} while(0);
#endif
		sc_capwap_closesession(sessionpriv);
		ret = 0;
	}

	/* */
	sc_capwap_update_unlock();
	return ret;
}

/* */
static int sc_capwap_restrictbroadcastpacket(struct sk_buff* skb, int is80211) {
	TRACEKMOD("### sc_capwap_restrictbroadcastpacket\n");

	/* TODO: limit some broadcast packet (DHCP) */

	return 0;
}

/* */
static int sc_capwap_sendpacket_wtp(struct sc_capwap_session_priv* sessionpriv, uint8_t radioid, uint8_t wlanid, struct sk_buff* skb, int is80211) {
	uint32_t flags = 0;
	struct sc_capwap_radio_addr* radioaddr = NULL;
	uint8_t radioaddrbuffer[CAPWAP_RADIO_EUI48_LENGTH_PADDED];
	struct sc_capwap_wlan* wlan = &sessionpriv->wlans[radioid - 1][wlanid - 1];

	TRACEKMOD("### sc_capwap_sendpacket_wtp\n");

	/* */
	if (!wlan->used) {
		return -EINVAL;
	}

	/* Datalink header convertion */
	if (is80211 && (wlan->tunnelmode == CAPWAP_ADD_WLAN_TUNNELMODE_8023)) {
		sc_capwap_80211_to_8023(skb);
		flags |= NLSMARTCAPWAP_FLAGS_TUNNEL_8023;
		radioaddr = sc_capwap_setradiomacaddress(radioaddrbuffer, CAPWAP_RADIO_EUI48_LENGTH_PADDED, wlan->bssid);
	} else if (!is80211 && (wlan->tunnelmode == CAPWAP_ADD_WLAN_TUNNELMODE_80211)) {
		sc_capwap_8023_to_80211(skb, wlan->bssid);
	}

	/* Forward packet */
	return sc_capwap_forwarddata(&sessionpriv->session, radioid, sessionpriv->binding, skb, flags, radioaddr, (radioaddr ? CAPWAP_RADIO_EUI48_LENGTH_PADDED : 0), NULL, 0);
}

/* */
static void sc_capwap_sendbroadcastpacket_wtp(struct sc_netdev_priv* netpriv, uint16_t vlan, struct sk_buff* skb, struct sc_capwap_session_priv* ignore) {
	struct sk_buff* clone;
	struct sc_capwap_connection* connection;
	struct sc_capwap_wireless_information* winfo;
	uint8_t buffer[CAPWAP_WINFO_DESTWLAN_LENGTH_PADDED];
	int headroom = sizeof(struct sc_capwap_header) + CAPWAP_WINFO_DESTWLAN_LENGTH_PADDED;

	TRACEKMOD("### sc_capwap_sendbroadcastpacket_wtp\n");

	/* */
	if (headroom < skb_headroom(skb)) {
		headroom = skb_headroom(skb);
	}

	/* Send packet for every connection */
	list_for_each_entry_rcu(connection, &netpriv->list_connections, list_dev) {
		if ((connection->vlan == vlan) && (connection->sessionpriv != ignore)) {
			clone = skb_copy_expand(skb, headroom, skb_tailroom(skb), GFP_KERNEL);
			if (!clone) {
				break;
			}

			/* Forward packet */
			winfo = sc_capwap_setwinfo_destwlans(buffer, CAPWAP_WINFO_DESTWLAN_LENGTH_PADDED, connection->wlanidmask);
			sc_capwap_forwarddata(&connection->sessionpriv->session, connection->radioid, connection->sessionpriv->binding, clone, NLSMARTCAPWAP_FLAGS_TUNNEL_8023, NULL, 0, winfo, CAPWAP_WINFO_DESTWLAN_LENGTH_PADDED);
			kfree_skb(clone);
		}
	}
}

/* */
static void sc_capwap_sendpacket_iface(struct sc_capwap_station* station, struct sk_buff* skb) {
	struct sc_netdev_priv* devpriv = rcu_dereference(station->devpriv);

	TRACEKMOD("### sc_capwap_sendpacket_iface\n");

	/* */
	if (devpriv->dev->flags & IFF_UP) {
		if (station->vlan) {
			skb = vlan_insert_tag(skb, htons(ETH_P_8021Q), station->vlan & VLAN_VID_MASK);
			if (!skb) {
				/* Unable add VLAN id */
				spin_lock(&devpriv->lock);
				devpriv->dev->stats.rx_dropped++;
				spin_unlock(&devpriv->lock);
				return;
			}
		}

		/* Prepare to send packet */
		skb_reset_mac_header(skb);
		skb->protocol = eth_type_trans(skb, devpriv->dev);

		/* Send packet */
		netif_rx_ni(skb);
		TRACEKMOD("*** Send packet with size %d to interface %s\n", skb->len, devpriv->dev->name);

		/* Update stats */
		spin_lock(&devpriv->lock);
		devpriv->dev->stats.rx_packets++;
		devpriv->dev->stats.rx_bytes += skb->len;
		spin_unlock(&devpriv->lock);
	} else {
		/* Drop packet */
		kfree_skb(skb);

		spin_lock(&devpriv->lock);
		devpriv->dev->stats.rx_dropped++;
		spin_unlock(&devpriv->lock);
	}
}

/* */
static int sc_capwap_thread_recvpacket(struct sk_buff* skb) {
	int ret = 1;
	struct sc_capwap_session_priv* sessionpriv;
	struct sc_skb_capwap_cb* cb = CAPWAP_SKB_CB(skb);

	TRACEKMOD("### sc_capwap_thread_recvpacket\n");

	/* */
	if (cb->flags & SKB_CAPWAP_FLAG_FROM_USER_SPACE) {
		TRACEKMOD("*** Receive SKB_CAPWAP_FLAG_FROM_USER_SPACE\n");

		/* Send packet*/
		rcu_read_lock();

		sessionpriv = sc_capwap_getsession_sessionid(&cb->sessionid);
		if (sessionpriv) {
			if (sc_capwap_forwarddata(&sessionpriv->session, cb->radioid, cb->binding, skb, 0, NULL, 0, NULL, 0)) {
				TRACEKMOD("*** Unable send packet from sc_netlink_send_data function\n");
			}
		} else {
			TRACEKMOD("*** Unable to find session\n");
		}

		rcu_read_unlock();
	} else if (cb->flags & SKB_CAPWAP_FLAG_FROM_DATA_CHANNEL) {
		union capwap_addr peeraddr;

		TRACEKMOD("*** Receive SKB_CAPWAP_FLAG_FROM_DATA_CHANNEL\n");

		/* Get peer address */
		if (!sc_socket_getpeeraddr(skb, &peeraddr)) {
			if (skb_pull(skb, sizeof(struct udphdr))) {
				rcu_read_lock();

				sessionpriv = sc_capwap_getsession_ipaddr(&peeraddr);
				ret = sc_capwap_parsingpacket((sessionpriv ? &sessionpriv->session : NULL), &peeraddr, skb);

				rcu_read_unlock();
			} else {
				TRACEKMOD("*** Invalid packet\n");
				ret = -EOVERFLOW;
			}
		} else {
			TRACEKMOD("*** Unable get address from packet\n");
			ret = -EINVAL;
		}
	} else if (cb->flags & SKB_CAPWAP_FLAG_FROM_AC_TAP) {
		uint16_t vlan = 0;
		struct ethhdr* eh = eth_hdr(skb);
		struct sc_capwap_station* station;

		TRACEKMOD("*** Receive SKB_CAPWAP_FLAG_FROM_AC_TAP\n");

		/* Retrieve VLAN */
		if (vlan_tx_tag_present(skb)) {
			vlan = vlan_tx_tag_get_id(skb);
		} else if (eh->h_proto == htons(ETH_P_8021Q)) {
			vlan = ntohs(vlan_eth_hdr(skb)->h_vlan_TCI) & VLAN_VID_MASK;

			/* Remove 802.1q from packet */
			memmove(skb->data + VLAN_HLEN, skb->data, 2 * ETH_ALEN);
			skb_pull(skb, VLAN_HLEN);
			skb_reset_mac_header(skb);
		}

		rcu_read_lock();

		if (is_multicast_ether_addr(eh->h_dest)) {
			TRACEKMOD("*** Receive broadcast/multicast packet\n");

			if (!sc_capwap_restrictbroadcastpacket(skb, 0)) {
				sc_capwap_sendbroadcastpacket_wtp((struct sc_netdev_priv*)netdev_priv(skb->dev), vlan, skb, NULL);
			}
		} else {
			station = sc_stations_search(eh->h_dest);
			if (station && (station->vlan == vlan)) {
				sc_capwap_sendpacket_wtp(rcu_dereference(station->sessionpriv), station->radioid, station->wlanid, skb, 0);
			} else {
				TRACEKMOD("*** Unable to found station from macaddress\n");
				ret = -EINVAL;
			}
		}

		rcu_read_unlock();
	}

	return ret;
}

/* */
static int sc_capwap_thread(void* data) {
	struct sk_buff* skb;
	struct sc_capwap_workthread* thread = (struct sc_capwap_workthread*)data;

	TRACEKMOD("### sc_capwap_thread\n");
	TRACEKMOD("*** Thread start: %d\n", smp_processor_id());

	for (;;) {
		wait_event_interruptible(thread->waitevent, (skb_queue_len(&thread->queue) > 0) || kthread_should_stop());
		if (kthread_should_stop()) {
			break;
		}

		/* Get packet */
		skb = skb_dequeue(&thread->queue);
		if (!skb) {
			TRACEKMOD("*** Nothing from thread %d\n", smp_processor_id());
			continue;
		}

		/* */
		TRACEKMOD("*** Thread receive packet %d\n", smp_processor_id());
		if (sc_capwap_thread_recvpacket(skb)) {
			TRACEKMOD("*** Free packet\n");
			kfree_skb(skb);
		}
	}

	/* Purge queue */
	skb_queue_purge(&thread->queue);

	TRACEKMOD("*** Thread end: %d\n", smp_processor_id());
	return 0;
}

/* */
void sc_capwap_update_lock(void) {
	mutex_lock(&sc_session_update_mutex);
}

/* */
void sc_capwap_update_unlock(void) {
	mutex_unlock(&sc_session_update_mutex);
}

/* */
#ifdef CONFIG_PROVE_LOCKING
int sc_capwap_update_lock_is_locked(void) {
	return lockdep_is_held(&sc_session_update_mutex);
}
#endif

/* */
int sc_capwap_sendkeepalive(const struct sc_capwap_sessionid_element* sessionid) {
	int ret;
	int length;
	struct sc_capwap_session_priv* sessionpriv;
	uint8_t buffer[CAPWAP_KEEP_ALIVE_MAX_SIZE];

	TRACEKMOD("### sc_capwap_sendkeepalive\n");

	/* */
	rcu_read_lock();

	/* Get session */
	sessionpriv = sc_capwap_getsession_sessionid(sessionid);
	if (!sessionpriv) {
		TRACEKMOD("*** Unknown keep-alive session\n");
		ret = -ENOENT;
		goto done;
	}

#ifdef DEBUGKMOD
	do {
		char sessionname[33];
		sc_capwap_sessionid_printf(&sessionpriv->session.sessionid, sessionname);
		TRACEKMOD("*** Send keep-alive session: %s\n", sessionname);
	} while(0);
#endif

	/* Build keepalive */
	length = sc_capwap_createkeepalive(&sessionpriv->session.sessionid, buffer, CAPWAP_KEEP_ALIVE_MAX_SIZE);

	/* Send packet */
	ret = sc_socket_send(SOCKET_UDP, buffer, length, &sessionpriv->session.peeraddr);
	TRACEKMOD("*** Send keep-alive result: %d\n", ret);
	if (ret > 0) {
		ret = 0;
	}

done:
	rcu_read_unlock();
	return ret;
}

/* */
int sc_capwap_newsession(const struct sc_capwap_sessionid_element* sessionid, uint8_t binding, uint16_t mtu) {
	struct sc_capwap_session_priv* sessionpriv;

	TRACEKMOD("### sc_capwap_newsession\n");

#ifdef DEBUGKMOD
	do {
		char sessionname[33];
		sc_capwap_sessionid_printf(sessionid, sessionname);
		TRACEKMOD("*** Create session: %s\n", sessionname);
	} while(0);
#endif

	/* */
	sessionpriv = (struct sc_capwap_session_priv*)kzalloc(sizeof(struct sc_capwap_session_priv), GFP_KERNEL);
	if (!sessionpriv) {
		TRACEKMOD("*** Unable to create session\n");
		return -ENOMEM;
	}

	/* Initialize session */
	sc_capwap_initsession(&sessionpriv->session);
	memcpy(&sessionpriv->session.sessionid, sessionid, sizeof(struct sc_capwap_sessionid_element));
	sessionpriv->binding = binding;
	sessionpriv->session.mtu = mtu;
	INIT_LIST_HEAD(&sessionpriv->list_stations);
	INIT_LIST_HEAD(&sessionpriv->list_connections);

	/* Add to setup session list */
	sc_capwap_update_lock();
	list_add_rcu(&sessionpriv->list, &sc_session_setup_list);
	sc_capwap_update_unlock();

	TRACEKMOD("*** Create session\n");
	return 0;
}

/* */
int sc_capwap_init(void) {
	unsigned long i;
	unsigned long cpu;
	int err = -ENOMEM;

	TRACEKMOD("### sc_capwap_init\n");

	/* Init session */
	memset(&sc_localaddr, 0, sizeof(union capwap_addr));
	INIT_LIST_HEAD(&sc_session_setup_list);
	INIT_LIST_HEAD(&sc_session_running_list);

	/* */
	memset(sc_session_hash_ipaddr, 0, sizeof(struct sc_capwap_session_priv*) * SESSION_HASH_SIZE);
	memset(sc_session_hash_sessionid, 0, sizeof(struct sc_capwap_session_priv*) * SESSION_HASH_SIZE);

	/* Create threads */
	sc_session_threads_pos = 0;
	sc_session_threads_count = 0;
	for_each_online_cpu(cpu) {
		memset(&sc_session_threads[sc_session_threads_count], 0, sizeof(struct sc_capwap_workthread));

		/* Create thread and bind to cpu */
		sc_session_threads[sc_session_threads_count].thread = kthread_create(sc_capwap_thread, &sc_session_threads[sc_session_threads_count], "smartcapwap/%u", sc_session_threads_count);
		if (!IS_ERR(sc_session_threads[sc_session_threads_count].thread)) {
			kthread_bind(sc_session_threads[sc_session_threads_count].thread, cpu);

			/* */
			sc_session_threads_count++;
			if (sc_session_threads_count == MAX_WORKER_THREAD) {
				break;
			}
		} else {
			err = PTR_ERR(sc_session_threads[sc_session_threads_count].thread);
			sc_session_threads[sc_session_threads_count].thread = NULL;
			goto error;
		}
	}

	/* Init sockect */
	err = sc_socket_init();
	if (err) {
		goto error;
	}

	/* Start threads */
	for (i = 0; i < sc_session_threads_count; i++) {
		skb_queue_head_init(&sc_session_threads[i].queue);
		init_waitqueue_head(&sc_session_threads[i].waitevent);
		wake_up_process(sc_session_threads[i].thread);
	}

	return 0;

error:
	for (i = 0; i < sc_session_threads_count; i++) {
		if (sc_session_threads[i].thread) {
			kthread_stop(sc_session_threads[i].thread);
		}
	}

	return err;
}

/* */
void sc_capwap_close(void) {
	uint32_t i;

	TRACEKMOD("### sc_capwap_close\n");

	/* Close */
	sc_socket_close();
	sc_capwap_closesessions();
	sc_iface_closeall();

	/* Terminate threads */
	for (i = 0; i < sc_session_threads_count; i++) {
		kthread_stop(sc_session_threads[i].thread);
	}
}

/* */
int sc_capwap_deletesession(const struct sc_capwap_sessionid_element* sessionid) {
	struct sc_capwap_session_priv* sessionpriv;

	TRACEKMOD("### sc_capwap_deletesession\n");

#ifdef DEBUGKMOD
	do {
		char sessionname[33];
		sc_capwap_sessionid_printf(sessionid, sessionname);
		TRACEKMOD("*** Delete session: %s\n", sessionname);
	} while(0);
#endif

	/* Searching item with read lock */
	rcu_read_lock();

	/* Search into running session list */
	if (sc_capwap_getsession_sessionid(sessionid)) {
		rcu_read_unlock();

		/* Remove session */
		return sc_capwap_deleterunningsession(sessionid);
	}

	/* Search into setup session list */
	list_for_each_entry_rcu(sessionpriv, &sc_session_setup_list, list) {
		if (!memcmp(&sessionpriv->session.sessionid, sessionid, sizeof(struct sc_capwap_sessionid_element))) {
			rcu_read_unlock();

			/* Remove session with sessionid */
			return sc_capwap_deletesetupsession(sessionid);
		}
	}

	rcu_read_unlock();

	TRACEKMOD("*** Session not found\n");
	return -ENOENT;
}

/* */
int sc_capwap_addwlan(const struct sc_capwap_sessionid_element* sessionid, uint8_t radioid, uint8_t wlanid, const uint8_t* bssid, uint8_t macmode, uint8_t tunnelmode) {
	int err = -ENOENT;
	struct sc_capwap_session_priv* sessionpriv;

	TRACEKMOD("### sc_capwap_addwlan\n");

	/* */
	sc_capwap_update_lock();

	/* Search session and interface */
	sessionpriv = sc_capwap_getsession_sessionid(sessionid);
	if (sessionpriv) {
		struct sc_capwap_wlan* wlan = &sessionpriv->wlans[radioid - 1][wlanid - 1];

		memcpy(wlan->bssid, bssid, MACADDRESS_EUI48_LENGTH);
		wlan->macmode = macmode;
		wlan->tunnelmode = tunnelmode;
		wlan->used = 1;
		err = 0;
	}

	sc_capwap_update_unlock();

	return err;
}

/* */
int sc_capwap_removewlan(const struct sc_capwap_sessionid_element* sessionid, uint8_t radioid, uint8_t wlanid) {
	int err = -ENOENT;
	struct sc_capwap_session_priv* sessionpriv;

	TRACEKMOD("### sc_capwap_removewlan\n");

	/* */
	sc_capwap_update_lock();

	/* Search session and interface */
	sessionpriv = sc_capwap_getsession_sessionid(sessionid);
	if (sessionpriv) {
		sessionpriv->wlans[radioid - 1][wlanid - 1].used = 0;
	}

	sc_capwap_update_unlock();

	return err;
}

/* */
void sc_capwap_recvpacket(struct sk_buff* skb) {
	uint32_t pos;

	TRACEKMOD("### sc_capwap_recvpacket\n");

	spin_lock(&sc_session_threads_lock);
	sc_session_threads_pos = ((sc_session_threads_pos + 1) % sc_session_threads_count);
	pos = sc_session_threads_pos;
	spin_unlock(&sc_session_threads_lock);

	TRACEKMOD("*** Add packet (flags 0x%04x size %d) to thread: %u\n", (int)CAPWAP_SKB_CB(skb)->flags, (int)skb->len, pos);

	/* Queue packet */
	skb_queue_tail(&sc_session_threads[pos].queue, skb);
	wake_up_interruptible(&sc_session_threads[pos].waitevent);
}

/* */
struct sc_capwap_session* sc_capwap_recvunknownkeepalive(const union capwap_addr* sockaddr, const struct sc_capwap_sessionid_element* sessionid) {
	uint32_t hash;
	struct sc_capwap_session_priv* search;
	struct sc_capwap_session_priv* sessionpriv = NULL;

	TRACEKMOD("### sc_capwap_recvunknownkeepalive\n");

#ifdef DEBUGKMOD
	do {
		char sessionname[33];
		sc_capwap_sessionid_printf(sessionid, sessionname);
		TRACEKMOD("*** Receive unknown keep-alive: %s\n", sessionname);
	} while(0);
#endif

	/* Change read lock to update lock */
	rcu_read_unlock();
	sc_capwap_update_lock();

	/* Search and remove from setup session */
	list_for_each_entry(search, &sc_session_setup_list, list) {
		if (!memcmp(&search->session.sessionid, sessionid, sizeof(struct sc_capwap_sessionid_element))) {
			sessionpriv = search;
			break;
		}
	}

	/* */
	if (!sessionpriv) {
		TRACEKMOD("*** Setup session not found\n");
		goto done;
	}

	/* */
	list_del_rcu(&sessionpriv->list);
	synchronize_net();

	/* */
	memcpy(&sessionpriv->session.peeraddr, sockaddr, sizeof(union capwap_addr));
	list_add_rcu(&sessionpriv->list, &sc_session_running_list);

	/* */
	hash = sc_capwap_hash_ipaddr(sockaddr);
	sessionpriv->next_ipaddr = rcu_dereference_protected(sc_session_hash_ipaddr[hash], sc_capwap_update_lock_is_locked());
	rcu_assign_pointer(sc_session_hash_ipaddr[hash], sessionpriv);

	/* */
	hash = sc_capwap_hash_sessionid(sessionid);
	sessionpriv->next_sessionid = rcu_dereference_protected(sc_session_hash_sessionid[hash], sc_capwap_update_lock_is_locked());
	rcu_assign_pointer(sc_session_hash_sessionid[hash], sessionpriv);

done:
	rcu_read_lock();
	sc_capwap_update_unlock();

	/* */
	return (sessionpriv ? &sessionpriv->session : NULL);
}

/* */
void sc_capwap_parsingdatapacket(struct sc_capwap_session* session, struct sk_buff* skb) {
	uint8_t* pos;
	uint8_t* srcaddress;
	uint8_t* dstaddress;
	struct sc_capwap_station* srcstation;
	struct sc_capwap_station* dststation;
	struct sc_capwap_header* header = (struct sc_capwap_header*)skb->data;
	int is80211 = (IS_FLAG_T_HEADER(header) ? 1 : 0);
	struct sc_capwap_radio_addr* radioaddr = NULL;
	int radioaddrsize = 0;
	struct sc_capwap_wireless_information* winfo = NULL;
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
		winfosize = (sizeof(struct sc_capwap_wireless_information) + winfo->length + 3) & ~3;
		pos += winfosize;
	}

	/* Body packet */
	skb_pull(skb, GET_HLEN_HEADER(header) * 4);
	srcaddress = (is80211 ? ieee80211_get_SA((struct ieee80211_hdr*)skb->data) : (uint8_t*)((struct ethhdr*)skb->data)->h_source);
	dstaddress = (is80211 ? ieee80211_get_DA((struct ieee80211_hdr*)skb->data) : (uint8_t*)((struct ethhdr*)skb->data)->h_dest);

	/* Search source station */
	srcstation = sc_stations_search(srcaddress);
	if (srcstation) {
		struct sc_capwap_session_priv* srcsessionpriv = rcu_dereference(srcstation->sessionpriv);
		struct sc_capwap_wlan* wlan = &srcsessionpriv->wlans[srcstation->radioid - 1][srcstation->wlanid - 1];

		if (wlan->used) {
			/* Check tunnel mode */
			if (wlan->tunnelmode != CAPWAP_ADD_WLAN_TUNNELMODE_LOCAL) {
				if (is_multicast_ether_addr(dstaddress)) {
					if (is80211) {
						sc_capwap_80211_to_8023(skb);
					}

					/* Forward to any session with same connection */
					if (!srcsessionpriv->isolation && !sc_capwap_restrictbroadcastpacket(skb, is80211)) {
						sc_capwap_sendbroadcastpacket_wtp(rcu_dereference(srcstation->devpriv), srcstation->vlan, skb, srcsessionpriv);
					}

					/* Forward to physical interface */
					sc_capwap_sendpacket_iface(srcstation, skb);
				} else {
					/* Search destination station */
					dststation = sc_stations_search(dstaddress);
					if (dststation) {
						/* Forward packet */
						if (!srcsessionpriv->isolation && (srcsessionpriv != rcu_access_pointer(dststation->sessionpriv))) {
							sc_capwap_sendpacket_wtp(rcu_dereference(dststation->sessionpriv), dststation->radioid, dststation->wlanid, skb, is80211);
						}

						kfree_skb(skb);
					} else {
						if (is80211) {
							sc_capwap_80211_to_8023(skb);
						}

						/* Forward to physical interface */
						sc_capwap_sendpacket_iface(srcstation, skb);
					}
				}
			} else {
				TRACEKMOD("*** Receive packet from local tunnel mode wlan session\n");
				kfree_skb(skb);
			}
		} else {
			TRACEKMOD("*** Receive packet from disable wlan\n");
			kfree_skb(skb);
		}
	} else {
		TRACEKMOD("*** Receive packet from unknown station\n");
		kfree_skb(skb);
	}
}

/* */
void sc_capwap_parsingmgmtpacket(struct sc_capwap_session* session, struct sk_buff* skb) {
	TRACEKMOD("### sc_capwap_parsingmgmtpacket\n");

	/* Send packet with capwap header into userspace */
	sc_netlink_notify_recv_data(&session->sessionid, skb->data, skb->len);
	kfree_skb(skb);
}

/* */
int sc_capwap_authstation(const struct sc_capwap_sessionid_element* sessionid, const uint8_t* address, uint32_t ifindex, uint8_t radioid, uint8_t wlanid, uint16_t vlan) {
	int err = 0;
	struct sc_capwap_station* station;
	struct sc_netdev_priv* devpriv;
	struct sc_capwap_session_priv* sessionpriv;

	TRACEKMOD("### sc_capwap_authstation\n");

	if (!IS_VALID_RADIOID(radioid)) {
		return -EINVAL;
	}

	/* */
	sc_capwap_update_lock();

	/* Search session and interface */
	sessionpriv = sc_capwap_getsession_sessionid(sessionid);
	if (sessionpriv) {
		devpriv = sc_iface_search(ifindex);
		if (devpriv) {
			/* Create or Update Station */
			station = sc_stations_search(address);
			if (station) {
				/* Release old connection */
				sc_stations_releaseconnection(station);

				/* */
				station->vlan = vlan;
				station->radioid = radioid;
				station->wlanid = wlanid;

				/* Update interface */
				if (rcu_access_pointer(station->devpriv) != devpriv) {
					rcu_assign_pointer(station->devpriv, devpriv);
					list_replace(&station->list_dev, &devpriv->list_stations);
				}

				/* Update session */
				if (rcu_access_pointer(station->sessionpriv) != sessionpriv) {
					rcu_assign_pointer(station->sessionpriv, sessionpriv);
					list_replace(&station->list_session, &sessionpriv->list_stations);
				}
			} else {
				station = (struct sc_capwap_station*)kzalloc(sizeof(struct sc_capwap_station), GFP_KERNEL);
				if (station) {
					memcpy(station->address, address, MACADDRESS_EUI48_LENGTH);
					station->vlan = vlan;
					station->radioid = radioid;
					station->wlanid = wlanid;

					/* Assign interface */
					rcu_assign_pointer(station->devpriv, devpriv);
					list_add(&station->list_dev, &devpriv->list_stations);

					/* Assign session */
					rcu_assign_pointer(station->sessionpriv, sessionpriv);
					list_add(&station->list_session, &sessionpriv->list_stations);

					/* Add station */
					sc_stations_add(station);
				} else {
					TRACEKMOD("*** Unable to create station\n");
					err = -ENOMEM;
				}
			}

			/* Set new connection */
			if (!err && station) {
				err = sc_stations_setconnection(station);
				if (err) {
					TRACEKMOD("*** Unable to set connection\n");
					sc_stations_free(station);
				}
			}
		} else {
			TRACEKMOD("*** Unable to find interface\n");
			err = -EINVAL;
		}
	} else {
		TRACEKMOD("*** Unable to find session\n");
		err = -EINVAL;
	}

	sc_capwap_update_unlock();

	return err;
}

/* */
int sc_capwap_deauthstation(const struct sc_capwap_sessionid_element* sessionid, const uint8_t* address) {
	int err = -ENOENT;
	struct sc_capwap_station* station;
	struct sc_capwap_session_priv* sessionpriv;

	TRACEKMOD("### sc_capwap_deauthstation\n");

	sc_capwap_update_lock();

	sessionpriv = sc_capwap_getsession_sessionid(sessionid);
	if (sessionpriv) {
		station = sc_stations_search(address);
		if (station && (rcu_access_pointer(station->sessionpriv) == sessionpriv)) {
			sc_stations_releaseconnection(station);
			sc_stations_free(station);
			err = 0;
		}
	}

	sc_capwap_update_unlock();

	return err;
}
