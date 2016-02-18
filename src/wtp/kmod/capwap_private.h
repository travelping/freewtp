#ifndef __KMOD_CAPWAP_PRIVATE_HEADER__
#define __KMOD_CAPWAP_PRIVATE_HEADER__

/* */
struct sc_capwap_workthread {
	struct task_struct* thread;

	struct sk_buff_head queue;
	wait_queue_head_t waitevent;
};

/* */
int sc_capwap_init(struct sc_capwap_session *sc_acsession, struct net *net);

/* */
int sc_capwap_connect(struct sc_capwap_session *session,
		      struct sockaddr_storage *peeraddr,
		      struct sc_capwap_sessionid_element* sessionid, uint16_t mtu);
void sc_capwap_resetsession(struct sc_capwap_session *sc_acsession);

/* */
int sc_capwap_sendkeepalive(struct sc_capwap_session *sc_acsession);

#endif /* __KMOD_CAPWAP_PRIVATE_HEADER__ */

