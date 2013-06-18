#ifndef __CAPWAP_AC_HEADER__
#define __CAPWAP_AC_HEADER__

/* standard include */
#include "capwap.h"
#include "capwap_network.h"
#include "capwap_protocol.h"
#include "capwap_lock.h"
#include "capwap_list.h"
#include "capwap_event.h"
#include "capwap_element.h"

#include <pthread.h>

/* AC Configuration */
#define AC_DEFAULT_CONFIGURATION_FILE		"/etc/capwap/ac.conf"

#define AC_DEFAULT_MAXSTATION				128
#define AC_DEFAULT_MAXSESSIONS				128

/* AC runtime error return code */
#define AC_ERROR_SYSTEM_FAILER				-1000
#define AC_ERROR_LOAD_CONFIGURATION			-1001
#define AC_ERROR_NETWORK					-1002
#define AC_ERROR_MEMORY_LEAK				1

/* Min and max dfa values */
#define AC_MIN_WAITDTLS_INTERVAL					30
#define AC_DEFAULT_WAITDTLS_INTERVAL				60
#define AC_MIN_WAITJOIN_INTERVAL					20
#define AC_DEFAULT_WAITJOIN_INTERVAL				60
#define AC_DEFAULT_CHANGE_STATE_PENDING_TIMER		25
#define AC_MIN_DISCOVERY_INTERVAL					2
#define AC_DEFAULT_DISCOVERY_INTERVAL				20
#define AC_MAX_DISCOVERY_INTERVAL					180
#define AC_DEFAULT_ECHO_INTERVAL					30
#define AC_MAX_ECHO_INTERVAL						256
#define AC_DEFAULT_DECRYPT_ERROR_PERIOD_INTERVAL	120
#define AC_DEFAULT_IDLE_TIMEOUT_INTERVAL			300
#define AC_DEFAULT_WTP_FALLBACK_MODE				CAPWAP_WTP_FALLBACK_ENABLED
#define AC_DEFAULT_DATA_CHECK_TIMER					30
#define AC_DEFAULT_RETRANSMIT_INTERVAL				3
#define AC_MAX_RETRANSMIT							5
#define AC_DEFAULT_DTLS_SESSION_DELETE				5

/* AC DFA */
struct ac_state {
	/* */
	struct capwap_ecnsupport_element ecn;
	struct capwap_transport_element transport;

	struct capwap_timers_element timers;
	unsigned short decrypterrorreport_interval;
	struct capwap_idletimeout_element idletimeout;
	struct capwap_wtpfallback_element wtpfallback;
	
	/* */
	struct capwap_acipv4list_element acipv4list;
	struct capwap_acipv6list_element acipv6list;

	/* */
	int rfcWaitJoin;
	int rfcChangeStatePendingTimer;
	int rfcDataCheckTimer;
	int rfcDTLSSessionDelete;

	/* Request retransmit */
	int rfcRetransmitInterval;
	int rfcRetransmitCount;
	int rfcMaxRetransmit;

	/* Dtls */
	int rfcWaitDTLS;
};

/* Handshake DTLS Data Channel */
struct ac_data_session_handshake {
	struct capwap_socket socket;
	struct sockaddr_storage acaddress;
	struct sockaddr_storage wtpaddress;
	struct capwap_dtls dtls;
};

/* AC */
struct ac_t {
	int standalone;
	int running;

	/* */
	struct ac_state dfa;
	struct capwap_network net;
	unsigned short mtu;

	struct capwap_array* binding;

	struct capwap_acname_element acname;
	struct capwap_acdescriptor_element descriptor;

	/* Sessions */
	capwap_event_t changesessionlist;
	struct capwap_list* sessions;
	capwap_lock_t sessionslock;
	struct capwap_list* datasessionshandshake;

	/* Dtls */
	int enabledtls;
	struct capwap_dtls_context dtlscontext;
};

extern struct ac_t g_ac;

/* Primary thread */
int ac_execute(void);

int ac_valid_binding(unsigned short binding);
void ac_update_statistics(void);

int ac_has_sessionid(struct capwap_sessionid_element* sessionid);
int ac_has_wtpid(unsigned char* id, unsigned short length);


#endif /* __CAPWAP_AC_HEADER__ */
