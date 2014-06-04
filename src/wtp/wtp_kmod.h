#ifndef __WTP_KMOD_HEADER__
#define __WTP_KMOD_HEADER__

/* */
int wtp_kmod_init(void);
void wtp_kmod_free(void);

/* */
int wtp_kmod_join_mac80211_device(uint32_t ifindex);

#endif /* __WTP_KMOD_HEADER__ */
