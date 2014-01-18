#ifndef __CAPWAP_WTP_HEADER__
#define __CAPWAP_WTP_HEADER__

/* standard include */
#include "capwap.h"
#include "capwap_dtls.h"
#include "capwap_network.h"
#include "capwap_protocol.h"
#include "wifi_drivers.h"
#include "wtp_radio.h"

/* WTP Configuration */
#define WTP_STANDARD_CONFIGURATION_FILE					"/etc/capwap/wtp.conf"

/* WTP runtime error return code */
#define WTP_ERROR_SYSTEM_FAILER				-1000
#define WTP_ERROR_LOAD_CONFIGURATION		-1001
#define WTP_ERROR_NETWORK					-1002
#define WTP_ERROR_INIT_BINDING				-1003
#define WTP_ERROR_MEMORY_LEAK				1

/* Min and max dfa values */
#define WTP_MIN_DISCOVERY_INTERVAL				2
#define WTP_DEFAULT_DISCOVERY_INTERVAL			20
#define WTP_MAX_DISCOVERY_INTERVAL				180
#define WTP_DEFAULT_DISCOVERY_COUNT				10
#define WTP_DEFAULT_SILENT_INTERVAL				30
#define WTP_DEFAULT_RETRANSMIT_INTERVAL			3
#define WTP_MAX_RETRANSMIT						5
#define WTP_MIN_WAITDTLS_INTERVAL				30
#define WTP_DEFAULT_WAITDTLS_INTERVAL			60
#define WTP_DEFAULT_STATISTICSTIMER_INTERVAL	120
#define WTP_DEFAULT_DATACHANNEL_KEEPALIVE		30
#define WTP_DEFAULT_DATACHANNEL_KEEPALIVEDEAD	60
#define WTP_MAX_DATACHANNEL_KEEPALIVEDEAD		240
#define WTP_DEFAULT_ECHO_INTERVAL				30
#define WTP_DEFAULT_DTLS_SESSION_DELETE			5
#define WTP_DEFAULT_FAILED_DTLS_SESSION_RETRY	3

#define WTP_INIT_REMOTE_SEQUENCE				0xff

/* WTP State machine */
struct wtp_state {
	unsigned long state;
	
	/* Discovery Information */
	int rfcDiscoveryInterval;
	int rfcMaxDiscoveryInterval;
	int rfcDiscoveryCount;
	int rfcMaxDiscoveries;
	
	/* Sulking Information */
	int rfcSilentInterval;
	
	/* Run */
	int rfcEchoInterval;
	
	/* Dtls Information */
	int rfcFailedDTLSSessionCount;
	int rfcFailedDTLSAuthFailCount;
	int rfcMaxFailedDTLSSessionRetry;
	
	/* Request retransmit */
	int rfcRetransmitInterval;
	int rfcRetransmitCount;
	int rfcMaxRetransmit;

	/* Data channel */
	int rfcDataChannelKeepAlive;
	int rfcDataChannelDeadInterval;

	/* Dtls */
	int rfcWaitDTLS;
	int rfcDTLSSessionDelete;
};

/* WTP */
struct wtp_t {
	int standalone;
	int running;

	char wlanprefix[IFNAMSIZ];

	/* */
	struct capwap_network net;
	struct pollfd* fds;
	int fdstotalcount;
	int fdsnetworkcount;

	/* */
	struct wtp_state dfa;

	struct capwap_wtpname_element name;
	struct capwap_acname_element acname;
	struct capwap_location_element location;

	unsigned short binding;

	struct capwap_discoverytype_element discoverytype;
	struct capwap_wtpframetunnelmode_element mactunnel;
	struct capwap_wtpmactype_element mactype;
	struct capwap_wtpboarddata_element boarddata;
	struct capwap_wtpdescriptor_element descriptor;

	struct capwap_sessionid_element sessionid;

	struct capwap_ecnsupport_element ecn;
	struct capwap_transport_element transport;
	struct capwap_statisticstimer_element statisticstimer;
	struct capwap_wtprebootstat_element rebootstat;

	struct capwap_packet_rxmng* rxmngctrlpacket;
	struct capwap_packet_rxmng* rxmngdatapacket;

	/* */
	unsigned char localseqnumber;
	unsigned char remoteseqnumber;
	unsigned short mtu;
	unsigned short fragmentid;
	struct capwap_list* requestfragmentpacket;
	struct capwap_list* responsefragmentpacket;
	unsigned char lastrecvpackethash[16];

	/* */
	int acdiscoveryrequest;
	unsigned long acpreferedselected;
	struct capwap_array* acdiscoveryarray;
	struct capwap_array* acpreferedarray;
	struct capwap_array* acdiscoveryresponse;

	struct sockaddr_storage wtpctrladdress;
	struct sockaddr_storage wtpdataaddress;
	struct sockaddr_storage acctrladdress;
	struct sockaddr_storage acdataaddress;
	struct capwap_socket acctrlsock;
	struct capwap_socket acdatasock;

	/* */
	struct capwap_array* radios;
	struct wifi_event* events;
	int eventscount;

	/* Radio ACL  */
	int defaultaclstations;
	struct capwap_hash* aclstations;

	/* Dtls */
	int enabledtls;
	unsigned char dtlsdatapolicy;
	unsigned char validdtlsdatapolicy;
	struct capwap_dtls_context dtlscontext;
	struct capwap_dtls ctrldtls;
	struct capwap_dtls datadtls;
	int teardown;
};

extern struct wtp_t g_wtp;

/* */
int wtp_update_radio_in_use();

/* Build capwap element helper */
void wtp_create_radioadmstate_element(struct capwap_packet_txmng* txmngpacket);
void wtp_create_radioopsstate_element(struct capwap_packet_txmng* txmngpacket);
void wtp_create_80211_wtpradioinformation_element(struct capwap_packet_txmng* txmngpacket);

#endif /* __CAPWAP_WTP_HEADER__ */
