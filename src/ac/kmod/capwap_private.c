#include "config.h"
#include <linux/module.h>
#include <linux/hash.h>
#include <linux/kthread.h>
#include <net/ipv6.h>
#include "socket.h"
#include "capwap.h"
#include "nlsmartcapwap.h"
#include "netlinkapp.h"
#include "iface.h"

/* Sessions */
static DEFINE_MUTEX(sc_session_mutex);
static struct list_head sc_session_setup_list;
static struct list_head sc_session_running_list;

static uint32_t sc_session_hash_size;
static uint32_t sc_session_hash_size_shift;
static struct sc_capwap_session_priv** __rcu sc_session_hash_ipaddr;
static struct sc_capwap_session_priv** __rcu sc_session_hash_sessionid;

/* Threads */
static DEFINE_SPINLOCK(sc_session_threads_lock);
static uint32_t sc_session_threads_pos;
static uint32_t sc_session_threads_count;
static struct sc_capwap_workthread* sc_session_threads;

/* */
static uint32_t sc_capwap_hash_ipaddr(const union capwap_addr* peeraddr) {
	TRACEKMOD("### sc_capwap_hash_ipaddr\n");

	return hash_32(((peeraddr->ss.ss_family == AF_INET) ? peeraddr->sin.sin_addr.s_addr : ipv6_addr_hash(&peeraddr->sin6.sin6_addr)), sc_session_hash_size_shift);
}

/* */
static uint32_t sc_capwap_hash_sessionid(const struct sc_capwap_sessionid_element* sessionid) {
	TRACEKMOD("### sc_capwap_hash_sessionid\n");

	return (sessionid->id32[0] ^ sessionid->id32[1] ^ sessionid->id32[2] ^ sessionid->id32[3]) % sc_session_hash_size;
}

/* */
static void sc_capwap_closesession(struct sc_capwap_session_priv* sessionpriv) {
	uint32_t hash;
	struct sc_capwap_session_priv* search;

	TRACEKMOD("### sc_capwap_closesession\n");

	lockdep_assert_held(&sc_session_mutex);

	/* Remove session from list reference */
	if (sessionpriv->session.peeraddr.ss.ss_family != AF_UNSPEC) {
		/* IP Address */
		hash = sc_capwap_hash_ipaddr(&sessionpriv->session.peeraddr);
		search = rcu_dereference_protected(sc_session_hash_ipaddr[hash], lockdep_is_held(&sc_session_mutex));

		if (search) {
			if (search == sessionpriv) {
				rcu_assign_pointer(sc_session_hash_ipaddr[hash], sessionpriv->next_ipaddr);
			} else {
				while (rcu_access_pointer(search->next_ipaddr) && (rcu_access_pointer(search->next_ipaddr) != sessionpriv)) {
					search = rcu_dereference_protected(search->next_ipaddr, lockdep_is_held(&sc_session_mutex));
				}

				if (rcu_access_pointer(search->next_ipaddr)) {
					rcu_assign_pointer(search->next_ipaddr, sessionpriv->next_ipaddr);
				}
			}
		}

		/* Session ID */
		hash = sc_capwap_hash_sessionid(&sessionpriv->session.sessionid);
		search = rcu_dereference_protected(sc_session_hash_sessionid[hash], lockdep_is_held(&sc_session_mutex));

		if (search) {
			if (search == sessionpriv) {
				rcu_assign_pointer(sc_session_hash_sessionid[hash], sessionpriv->next_sessionid);
			} else {
				while (rcu_access_pointer(search->next_sessionid) && (rcu_access_pointer(search->next_sessionid) != sessionpriv)) {
					search = rcu_dereference_protected(search->next_sessionid, lockdep_is_held(&sc_session_mutex));
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

	TRACEKMOD("*** Free session\n");
}

/* */
static void sc_capwap_closesessions(void) {
	struct sc_capwap_session_priv* sessionpriv;
	struct sc_capwap_session_priv* temp;

	TRACEKMOD("### sc_capwap_closesessions\n");
	TRACEKMOD("*** Delete all sessions\n");

	/* */
	mutex_lock(&sc_session_mutex);

	/* */
	list_for_each_entry_safe(sessionpriv, temp, &sc_session_setup_list, list) {
#ifdef DEBUGKMOD
		do {
			char sessionname[33];
			sc_capwap_sessionid_printf(&sessionpriv->session.sessionid, sessionname);
			TRACEKMOD("*** Delete setup session: %s\n", sessionname);
		} while(0);
#endif
		sc_capwap_closesession(sessionpriv);
	}

	/* */
	list_for_each_entry_safe(sessionpriv, temp, &sc_session_running_list, list) {
#ifdef DEBUGKMOD
		do {
			char sessionname[33];
			sc_capwap_sessionid_printf(&sessionpriv->session.sessionid, sessionname);
			TRACEKMOD("*** Delete running session: %s\n", sessionname);
		} while(0);
#endif
		sc_capwap_closesession(sessionpriv);
	}

	/* */
	synchronize_net();
	mutex_unlock(&sc_session_mutex);
}

/* */
static struct sc_capwap_session_priv* sc_capwap_getsession_ipaddr(const union capwap_addr* sockaddr) {
	struct sc_capwap_session_priv* sessionpriv;

	TRACEKMOD("### sc_capwap_getsession_ipaddr\n");

	/* */
	sessionpriv = rcu_dereference_check(sc_session_hash_ipaddr[sc_capwap_hash_ipaddr(sockaddr)], lockdep_is_held(&sc_session_mutex));
	while (sessionpriv) {
		if (!sc_addr_compare(sockaddr, &sessionpriv->session.peeraddr)) {
			break;
		}

		/* */
		sessionpriv = rcu_dereference_check(sessionpriv->next_ipaddr, lockdep_is_held(&sc_session_mutex));
	}

	return sessionpriv;
}

/* */
static struct sc_capwap_session_priv* sc_capwap_getsession_sessionid(const struct sc_capwap_sessionid_element* sessionid) {
	struct sc_capwap_session_priv* sessionpriv;

	TRACEKMOD("### sc_capwap_getsession_sessionid\n");

	/* */
	sessionpriv = rcu_dereference_check(sc_session_hash_ipaddr[sc_capwap_hash_sessionid(sessionid)], lockdep_is_held(&sc_session_mutex));
	while (sessionpriv) {
		if (!memcmp(&sessionpriv->session.sessionid, sessionid, sizeof(struct sc_capwap_sessionid_element))) {
			break;
		}

		/* */
		sessionpriv = rcu_dereference_check(sessionpriv->next_sessionid, lockdep_is_held(&sc_session_mutex));
	}

	return sessionpriv;
}

/* */
static int sc_capwap_deletesetupsession(const struct sc_capwap_sessionid_element* sessionid) {
	int ret = -ENOENT;
	struct sc_capwap_session_priv* sessionpriv;

	TRACEKMOD("### sc_capwap_deletesetupsession\n");

	/* */
	mutex_lock(&sc_session_mutex);

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
	mutex_unlock(&sc_session_mutex);
	return ret;
}

/* */
static int sc_capwap_deleterunningsession(const struct sc_capwap_sessionid_element* sessionid) {
	int ret = -ENOENT;
	struct sc_capwap_session_priv* sessionpriv;

	TRACEKMOD("### sc_capwap_deleterunningsession\n");

	/* */
	mutex_lock(&sc_session_mutex);

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
	mutex_unlock(&sc_session_mutex);
	return ret;
}

/* */
static int sc_capwap_thread_recvpacket(struct sk_buff* skb) {
	int ret = 1;
	union capwap_addr peeraddr;
	struct sc_capwap_session_priv* sessionpriv;
	struct sc_skb_capwap_cb* cb = CAPWAP_SKB_CB(skb);

	TRACEKMOD("### sc_capwap_thread_recvpacket\n");

	/* */
	if (cb->flags & SKB_CAPWAP_FLAG_FROM_USER_SPACE) {
		TRACEKMOD("*** Receive SKB_CAPWAP_FLAG_FROM_USER_SPACE\n");

		/* Get peer address */
		sc_addr_fromlittle(&cb->peeraddr, &peeraddr);
		TRACEKMOD("*** Address %d %x %x\n", peeraddr.ss.ss_family, (int)peeraddr.sin.sin_addr.s_addr, (int)peeraddr.sin.sin_port);

		/* Send packet*/
		rcu_read_lock();

		sessionpriv = sc_capwap_getsession_ipaddr(&peeraddr);
		if (sessionpriv) {
			if (sc_capwap_forwarddata(&sessionpriv->session, cb->radioid, cb->binding, skb, 0, NULL, 0, NULL, 0)) {
				TRACEKMOD("*** Unable send packet from sc_netlink_send_data function\n");
			}
		} else {
			TRACEKMOD("*** Unable to find session\n");
		}

		rcu_read_unlock();
	} else if (cb->flags & SKB_CAPWAP_FLAG_FROM_DATA_CHANNEL) {
		TRACEKMOD("*** Receive SKB_CAPWAP_FLAG_FROM_DATA_CHANNEL\n");

		/* Get peer address */
		if (sc_socket_getpeeraddr(skb, &peeraddr)) {
			TRACEKMOD("*** Unable get address from packet\n");
			return -EINVAL;
		}

		/* Remove UDP header */
		if (!skb_pull(skb, sizeof(struct udphdr))) {
			TRACEKMOD("*** Invalid packet\n");
			return -EOVERFLOW;
		}

		/* */
		rcu_read_lock();

		sessionpriv = sc_capwap_getsession_ipaddr(&peeraddr);
		ret = sc_capwap_parsingpacket(&sessionpriv->session, &peeraddr, skb);

		rcu_read_unlock();
	}

	return ret;
}

/* */
static int sc_capwap_thread(void* data) {
	struct sk_buff* skb;
	struct sc_capwap_workthread* thread = (struct sc_capwap_workthread*)data;

	TRACEKMOD("### sc_capwap_thread\n");
	TRACEKMOD("*** Thread start\n");

	for (;;) {
		wait_event_interruptible(thread->waitevent, (skb_queue_len(&thread->queue) > 0) || kthread_should_stop());
		if (kthread_should_stop()) {
			break;
		}

		/* Get packet */
		skb = skb_dequeue(&thread->queue);
		if (!skb) {
			continue;
		}

		/* */
		TRACEKMOD("*** Thread receive packet\n");
		if (sc_capwap_thread_recvpacket(skb)) {
			TRACEKMOD("*** Free packet\n");
			kfree_skb(skb);
		}
	}

	TRACEKMOD("*** Thread end\n");
	return 0;
}

/* */
int sc_capwap_sendkeepalive(const union capwap_addr* peeraddr) {
	int ret;
	int length;
	struct sc_capwap_session_priv* sessionpriv;
	uint8_t buffer[CAPWAP_KEEP_ALIVE_MAX_SIZE];

	TRACEKMOD("### sc_capwap_sendkeepalive\n");

	/* */
	rcu_read_lock();

	/* Get session */
	sessionpriv = sc_capwap_getsession_ipaddr(peeraddr);
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
	if (ret > 0) {
		ret = 0;
	}

done:
	rcu_read_unlock();
	return ret;
}

/* */
int sc_capwap_newsession(const struct sc_capwap_sessionid_element* sessionid, uint16_t mtu) {
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
	sessionpriv = kzalloc(sizeof(struct sc_capwap_session_priv), GFP_KERNEL);
	if (!sessionpriv) {
		TRACEKMOD("*** Unable to create session\n");
		return -ENOMEM;
	}

	/* Initialize session */
	sc_capwap_initsession(&sessionpriv->session);
	memcpy(&sessionpriv->session.sessionid, sessionid, sizeof(struct sc_capwap_sessionid_element));
	sessionpriv->session.mtu = mtu;
	INIT_LIST_HEAD(&sessionpriv->list);

	/* Add to setup session list */
	mutex_lock(&sc_session_mutex);
	list_add_rcu(&sessionpriv->list, &sc_session_setup_list);
	mutex_unlock(&sc_session_mutex);

	TRACEKMOD("*** Create session\n");
	return 0;
}

/* */
int sc_capwap_init(uint32_t hash, uint32_t threads) {
	uint32_t i;
	int err = -ENOMEM;

	TRACEKMOD("### sc_capwap_init\n");
	TRACEKMOD("*** Init capwap module - hash bitfield: %u - threads: %u\n", hash, threads);

	/* */
	if (!hash || !threads) {
		return -EINVAL;
	}

	/* Init session */
	memset(&sc_localaddr, 0, sizeof(union capwap_addr));
	INIT_LIST_HEAD(&sc_session_running_list);
	INIT_LIST_HEAD(&sc_session_setup_list);

	/* */
	sc_session_hash_size_shift = hash;
	sc_session_hash_size = 1 << hash;

	sc_session_hash_ipaddr = (struct sc_capwap_session_priv**)kzalloc(sizeof(struct sc_capwap_session_priv*) * sc_session_hash_size, GFP_KERNEL);
	if (!sc_session_hash_ipaddr) {
		goto error;
	}

	sc_session_hash_sessionid = (struct sc_capwap_session_priv**)kzalloc(sizeof(struct sc_capwap_session_priv*) * sc_session_hash_size, GFP_KERNEL);
	if (!sc_session_hash_sessionid) {
		goto error1;
	}

	/* Create threads */
	sc_session_threads_pos = 0;
	sc_session_threads_count = threads;
	sc_session_threads = (struct sc_capwap_workthread*)kzalloc(sizeof(struct sc_capwap_workthread) * threads, GFP_KERNEL);
	if (!sc_session_threads) {
		goto error2;
	}

	for (i = 0; i < threads; i++) {
		sc_session_threads[i].thread = kthread_create(sc_capwap_thread, &sc_session_threads[i], "smartcapwap/%u", i);
		if (IS_ERR(sc_session_threads[i].thread)) {
			err = PTR_ERR(sc_session_threads[i].thread);
			sc_session_threads[i].thread = NULL;
			goto error3;
		}
	}

	/* Init sockect */
	err = sc_socket_init();
	if (err) {
		goto error3;
	}

	/* Start threads */
	for (i = 0; i < threads; i++) {
		skb_queue_head_init(&sc_session_threads[i].queue);
		init_waitqueue_head(&sc_session_threads[i].waitevent);
		wake_up_process(sc_session_threads[i].thread);
	}

	return 0;

error3:
	for (i = 0; i < threads; i++) {
		if (sc_session_threads[i].thread) {
			kthread_stop(sc_session_threads[i].thread);
		}
	}

	kfree(sc_session_threads);

error2:
	kfree(sc_session_hash_sessionid);

error1:
	kfree(sc_session_hash_ipaddr);

error:
	return err;
}

/* */
void sc_capwap_close(void) {
	uint32_t i;

	TRACEKMOD("### sc_capwap_close\n");
	TRACEKMOD("*** Closing capwap module\n");

	/* */
	sc_socket_close();

	/* */
	for (i = 0; i < sc_session_threads_count; i++) {
		kthread_stop(sc_session_threads[i].thread);
	}

	kfree(sc_session_threads);

	/* */
	sc_capwap_closesessions();
	kfree(sc_session_hash_ipaddr);
	kfree(sc_session_hash_sessionid);

	/* */
	sc_iface_closeall();

	TRACEKMOD("*** Close capwap module\n");
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
void sc_capwap_recvpacket(struct sk_buff* skb) {
	uint32_t pos;
	unsigned long flags;

	TRACEKMOD("### sc_capwap_recvpacket\n");

	spin_lock_irqsave(&sc_session_threads_lock, flags);
	sc_session_threads_pos = ((sc_session_threads_pos + 1) % sc_session_threads_count);
	pos = sc_session_threads_pos;
	spin_unlock_irqrestore(&sc_session_threads_lock, flags);

	TRACEKMOD("*** Add packet to thread: %u\n", pos);

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

	/* Must be called under rcu_read_lock() */
	 rcu_lockdep_assert(rcu_read_lock_held(), "sc_capwap_recvunknownkeepalive() needs rcu_read_lock() protection");

#ifdef DEBUGKMOD
	do {
		char sessionname[33];
		sc_capwap_sessionid_printf(sessionid, sessionname);
		TRACEKMOD("*** Receive unknown keep-alive: %s\n", sessionname);
	} while(0);
#endif

	/* Change read lock to update lock */
	rcu_read_unlock();
	mutex_lock(&sc_session_mutex);

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
	sessionpriv->next_ipaddr = sc_session_hash_ipaddr[hash];
	rcu_assign_pointer(sc_session_hash_ipaddr[hash], sessionpriv);

	/* */
	hash = sc_capwap_hash_sessionid(sessionid);
	sessionpriv->next_sessionid = sc_session_hash_sessionid[hash];
	rcu_assign_pointer(sc_session_hash_sessionid[hash], sessionpriv);

done:
	rcu_read_lock();
	mutex_unlock(&sc_session_mutex);

	/* */
	return (sessionpriv ? &sessionpriv->session : NULL);
}


/* */
void sc_capwap_parsingdatapacket(struct sc_capwap_session* session, struct sk_buff* skb) {
	uint8_t* pos;
	struct sc_capwap_header* header = (struct sc_capwap_header*)skb->data;
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
		radioaddrsize = (sizeof(struct sc_capwap_wireless_information) + winfo->length + 3) & ~3;
		pos += winfosize;
	}

	/* TODO */
}

/* */
void sc_capwap_parsingmgmtpacket(struct sc_capwap_session* session, struct sk_buff* skb) {
	TRACEKMOD("### sc_capwap_parsingmgmtpacket\n");

	/* Send packet with capwap header into userspace */
	sc_netlink_notify_recv_data(&session->sessionid, skb->data, skb->len);
}
