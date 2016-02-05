#include "config.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include "station.h"
#include "capwap.h"
#include "iface.h"

/* */
#define STATION_HASH_SIZE					65536

/* */
static LIST_HEAD(sc_station_list);
static struct sc_capwap_station* __rcu sc_station_hash_addr[STATION_HASH_SIZE];

/* */
static uint32_t sc_stations_hash_addr(const uint8_t* macaddress) {
	TRACEKMOD("### sc_stations_hash_addr\n");

	return (((((uint32_t)macaddress[4] << 8) | (uint32_t)macaddress[5]) ^ ((uint32_t)macaddress[3] << 4)) % STATION_HASH_SIZE);
}

/* */
static struct sc_capwap_connection* sc_stations_searchconnection(struct sc_capwap_station* station) {
	struct sc_capwap_connection* connection;
	struct sc_capwap_session_priv* sessionpriv = rcu_access_pointer(station->sessionpriv);
	struct sc_netdev_priv* devpriv = rcu_access_pointer(station->devpriv);

	TRACEKMOD("### sc_stations_searchconnection\n");

	list_for_each_entry(connection, &sessionpriv->list_connections, list_session) {
		if ((connection->devpriv == devpriv) && (connection->radioid == station->radioid) && (connection->vlan == station->vlan)) {
			return connection;
		}
	}

	return NULL;
}

/* */
void sc_stations_add(struct sc_capwap_station* station) {
	uint32_t hash;

	TRACEKMOD("### sc_stations_add\n");

	/* */
	list_add_rcu(&station->list, &sc_station_list);

	hash = sc_stations_hash_addr(station->address);
	station->next_addr = rcu_dereference_protected(sc_station_hash_addr[hash], sc_capwap_update_lock_is_locked());
	rcu_assign_pointer(sc_station_hash_addr[hash], station);
}

/* */
struct sc_capwap_station* sc_stations_search(const uint8_t* macaddress) {
	struct sc_capwap_station* station;

	TRACEKMOD("### sc_stations_search\n");

	/* */
	station = rcu_dereference_check(sc_station_hash_addr[sc_stations_hash_addr(macaddress)], sc_capwap_update_lock_is_locked());
	while (station) {
		if (!memcmp(&station->address, macaddress, MACADDRESS_EUI48_LENGTH)) {
			break;
		}

		/* */
		station = rcu_dereference_check(station->next_addr, sc_capwap_update_lock_is_locked());
	}

	return station;
}

/* */
void sc_stations_free(struct sc_capwap_station* station) {
	uint32_t hash;
	struct sc_capwap_station* search;

	TRACEKMOD("### sc_stations_free\n");

	/* */
	hash = sc_stations_hash_addr(station->address);
	search = rcu_dereference_protected(sc_station_hash_addr[hash], sc_capwap_update_lock_is_locked());

	if (search) {
		if (search == station) {
			rcu_assign_pointer(sc_station_hash_addr[hash], station->next_addr);
		} else {
			while (rcu_access_pointer(search->next_addr) && (rcu_access_pointer(search->next_addr) != station)) {
				search = rcu_dereference_protected(search->next_addr, sc_capwap_update_lock_is_locked());
			}

			if (rcu_access_pointer(search->next_addr)) {
				rcu_assign_pointer(search->next_addr, station->next_addr);
			}
		}
	}

	/* */
	list_del_rcu(&station->list_dev);
	list_del_rcu(&station->list_session);
	synchronize_net();

	kfree(station);
}

/* */
int sc_stations_setconnection(struct sc_capwap_station* station) {
	struct sc_capwap_connection* connection;

	TRACEKMOD("### sc_stations_setconnection\n");

	/* */
	connection = sc_stations_searchconnection(station);
	if (!connection) {
		connection = (struct sc_capwap_connection*)kzalloc(sizeof(struct sc_capwap_connection), GFP_KERNEL);
		if (!connection) {
			TRACEKMOD("*** Unable to create connection\n");
			return -ENOMEM;
		}

		/* */
		connection->sessionpriv = rcu_access_pointer(station->sessionpriv);
		list_add_rcu(&connection->list_session, &connection->sessionpriv->list_connections);
		connection->devpriv = rcu_access_pointer(station->devpriv);
		list_add_rcu(&connection->list_dev, &connection->devpriv->list_connections);
		connection->radioid = station->radioid;
		connection->vlan = station->vlan;
	}

	/* */
	connection->count++;
	connection->wlanidmask |= 1 << (station->wlanid - 1);
	return 0;
}

/* */
void sc_stations_releaseconnection(struct sc_capwap_station* station) {
	struct sc_capwap_connection* connection;

	TRACEKMOD("### sc_stations_releaseconnection\n");

	connection = sc_stations_searchconnection(station);
	if (connection) {
		TRACEKMOD("*** Release connection reference %d\n", connection->count);

		connection->count--;
		if (!connection->count) {
			list_del_rcu(&connection->list_session);
			list_del_rcu(&connection->list_dev);
			synchronize_net();

			kfree(connection);
		}
	}
}
