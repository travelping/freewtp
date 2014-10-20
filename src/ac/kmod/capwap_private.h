#ifndef __KMOD_CAPWAP_PRIVATE_HEADER__
#define __KMOD_CAPWAP_PRIVATE_HEADER__

/* */
struct sc_capwap_session_priv {
	struct sc_capwap_session session;

	struct list_head list;
	struct sc_capwap_session_priv* __rcu next_ipaddr;
	struct sc_capwap_session_priv* __rcu next_sessionid;
};

/* */
struct sc_capwap_workthread {
	struct task_struct* thread;

	struct sk_buff_head queue;
	wait_queue_head_t waitevent;
};

/* */
int sc_capwap_init(uint32_t hash, uint32_t threads);
void sc_capwap_close(void);

/* */
int sc_capwap_sendkeepalive(const union capwap_addr* peeraddr);

/* */
int sc_capwap_newsession(const struct sc_capwap_sessionid_element* sessionid, uint16_t mtu);
int sc_capwap_deletesession(const struct sc_capwap_sessionid_element* sessionid);

#endif /* __KMOD_CAPWAP_PRIVATE_HEADER__ */
