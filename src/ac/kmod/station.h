#ifndef __KMOD_AC_STATION_HEADER__
#define __KMOD_AC_STATION_HEADER__

#include "capwap_rfc.h"

/* */
struct sc_capwap_connection {
	int count;

	/* Session */
	struct sc_capwap_session_priv* sessionpriv;
	struct list_head list_session;

	/* Interface */
	struct sc_netdev_priv* devpriv;
	struct list_head list_dev;

	/* */
	uint16_t vlan;
	uint8_t radioid;
	uint8_t wlanidmask;
};

/* */
struct sc_capwap_station {
	struct list_head list;

	/* */
	uint8_t address[MACADDRESS_EUI48_LENGTH];
	struct sc_capwap_station* __rcu next_addr;

	/* Session */
	struct sc_capwap_session_priv* __rcu sessionpriv;
	struct list_head list_session;

	/* Interface */
	struct sc_netdev_priv* __rcu devpriv;
	struct list_head list_dev;

	/* */
	uint8_t bssid[MACADDRESS_EUI48_LENGTH];
	uint16_t vlan;
	uint8_t radioid;
	uint8_t wlanid;
};

/* */
void sc_stations_add(struct sc_capwap_station* station);
void sc_stations_free(struct sc_capwap_station* station);

/* */
struct sc_capwap_station* sc_stations_search(const uint8_t* macaddress);

/* */
int sc_stations_setconnection(struct sc_capwap_station* station);
void sc_stations_releaseconnection(struct sc_capwap_station* station);

#endif /* __KMOD_AC_STATION_HEADER__ */
