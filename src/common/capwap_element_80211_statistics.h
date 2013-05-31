#ifndef __CAPWAP_ELEMENT_80211_STATISTICS_HEADER__
#define __CAPWAP_ELEMENT_80211_STATISTICS_HEADER__

#define CAPWAP_ELEMENT_80211_STATISTICS				1039

struct capwap_80211_statistics_element {
	uint8_t radioid;
	uint32_t txfragment;
	uint32_t multicasttx;
	uint32_t failed;
	uint32_t retry;
	uint32_t multipleretry;
	uint32_t frameduplicate;
	uint32_t rtssuccess;
	uint32_t rtsfailure;
	uint32_t ackfailure;
	uint32_t rxfragment;
	uint32_t multicastrx;
	uint32_t fcserror;
	uint32_t txframe;
	uint32_t decryptionerror;
	uint32_t discardedqosfragment;
	uint32_t associatedstation;
	uint32_t qoscfpollsreceived;
	uint32_t qoscfpollsunused;
	uint32_t qoscfpollsunusable;
};

extern struct capwap_message_elements_ops capwap_element_80211_statistics_ops;

#endif /* __CAPWAP_ELEMENT_80211_STATISTICS_HEADER__ */
