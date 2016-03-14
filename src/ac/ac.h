#ifndef __CAPWAP_AC_HEADER__
#define __CAPWAP_AC_HEADER__

/* standard include */
#include "capwap.h"
#include "capwap_network.h"
#include "capwap_protocol.h"
#include "capwap_event.h"
#include "capwap_lock.h"
#include "capwap_rwlock.h"
#include "capwap_list.h"
#include "capwap_hash.h"
#include "capwap_element.h"

#include <pthread.h>
#include <linux/if_ether.h>
#include <json-c/json.h>

#include <ac_kmod.h>

/* AC Configuration */
#define AC_DEFAULT_CONFIGURATION_FILE		"/etc/capwap/ac.conf"

#define AC_DEFAULT_MAXSTATION				128
#define AC_DEFAULT_MAXSESSIONS				128

#define VLAN_MAX							4096

/* AC runtime error return code */
#define AC_ERROR_SYSTEM_FAILER				-1000
#define AC_ERROR_LOAD_CONFIGURATION			-1001
#define AC_ERROR_NETWORK					-1002
#define AC_ERROR_MEMORY_LEAK				1

/* Min and max dfa values */
#define AC_DTLS_INTERVAL							60000

#define AC_JOIN_INTERVAL							60000

#define AC_CHANGE_STATE_PENDING_INTERVAL			25000

#define AC_DATA_CHECK_INTERVAL						30000

#define AC_RETRANSMIT_INTERVAL						3000
#define AC_MAX_RETRANSMIT							5

#define AC_DTLS_SESSION_DELETE_INTERVAL				5000

#define AC_MIN_ECHO_INTERVAL						1000
#define AC_ECHO_INTERVAL							30000
#define AC_MAX_ECHO_INTERVAL						256000

#define AC_MAX_DATA_KEEPALIVE_INTERVAL				256000

#define AC_MIN_DISCOVERY_INTERVAL					2000
#define AC_DISCOVERY_INTERVAL						20000
#define AC_MAX_DISCOVERY_INTERVAL					180000

#define AC_DECRYPT_ERROR_PERIOD_INTERVAL			120000
#define AC_IDLE_TIMEOUT_INTERVAL					300000
#define AC_WTP_FALLBACK_MODE						CAPWAP_WTP_FALLBACK_ENABLED

/* */
#define compat_json_object_object_get(obj, key)		({ 					\
	json_bool error; struct json_object* result = NULL;					\
	error = json_object_object_get_ex(obj, key, &result);				\
	(error ? result : NULL);											\
})

/* */
struct ac_if_datachannel {
	unsigned long index;

	int ifindex;
	char ifname[IFNAMSIZ];

	int mtu;

	char bridge[IFNAMSIZ];
};

/* */
struct ac_state {
	struct capwap_ecnsupport_element ecn;
	struct capwap_transport_element transport;
	struct capwap_timers_element timers;
	unsigned short decrypterrorreport_interval;
	struct capwap_idletimeout_element idletimeout;
	struct capwap_wtpfallback_element wtpfallback;
	
	/* */
	struct capwap_acipv4list_element acipv4list;
	struct capwap_acipv6list_element acipv6list;
};

/* */
struct ac_fds {
	int fdstotalcount;
	struct pollfd* fdspoll;

	int fdsnetworkcount;

	int msgqueuecount;
	int msgqueuestartpos;

	struct ac_kmod_event* kmodevents;
	int kmodeventscount;
	int kmodeventsstartpos;
};

/* AC */
struct ac_t {
	int standalone;
	int running;

	/* */
	struct ac_state dfa;
	struct capwap_network net;
	struct capwap_list* addrlist;
	unsigned short mtu;

	struct capwap_array* binding;

	struct capwap_acname_element acname;
	struct capwap_acdescriptor_element descriptor;

	/* Sessions message queue */
	int fdmsgsessions[2];

	/* Kernel module */
	struct ac_kmod_handle kmodhandle;

	/* Sessions */
	struct capwap_list* sessions;
	struct capwap_list* sessionsthread;
	capwap_rwlock_t sessionslock;

	/* Authorative Stations */
	struct capwap_hash* authstations;
	capwap_rwlock_t authstationslock;

	/* Data Channel Interfaces */
	struct capwap_hash* ifdatachannel;
	capwap_rwlock_t ifdatachannellock;

	/* Dtls */
	int enabledtls;
	struct capwap_dtls_context dtlscontext;

	/* Backend Management */
	char* backendacid;
	char* backendversion;
	struct capwap_array* availablebackends;
};

/* AC session thread */
struct ac_session_thread_t {
	pthread_t threadid;
};

/* AC session message queue item */
#define AC_MESSAGE_QUEUE_CLOSE_THREAD				1
#define AC_MESSAGE_QUEUE_CLOSE_ALLSESSIONS			2
#define AC_MESSAGE_QUEUE_UPDATE_CONFIGURATION		3

struct ac_session_msgqueue_item_t {
	unsigned long message;

	union {
		struct {
			pthread_t threadid;
		} message_close_thread;

		struct {
			struct json_object* jsonroot;
		} message_configuration;
	};
};

extern struct ac_t g_ac;

/* Primary thread */
int ac_execute(void);
int ac_execute_update_fdspool(struct ac_fds* fds);

int ac_valid_binding(unsigned short binding);
void ac_update_statistics(void);

#endif /* __CAPWAP_AC_HEADER__ */
