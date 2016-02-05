#ifndef __KMOD_CAPWAP_PRIVATE_HEADER__
#define __KMOD_CAPWAP_PRIVATE_HEADER__

/* */
struct sc_capwap_workthread {
	struct task_struct* thread;

	struct sk_buff_head queue;
	wait_queue_head_t waitevent;
};

/* */
int sc_capwap_init(void);
void sc_capwap_close(void);

/* */
int sc_capwap_connect(const union capwap_addr* sockaddr, struct sc_capwap_sessionid_element* sessionid, uint16_t mtu);
void sc_capwap_resetsession(void);

/* */
struct sc_capwap_session* sc_capwap_getsession(const union capwap_addr* sockaddr);

/* */
int sc_capwap_sendkeepalive(void);

#endif /* __KMOD_CAPWAP_PRIVATE_HEADER__ */

