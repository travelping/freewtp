#ifndef __CAPWAP_WTP_HEADER__
#define __CAPWAP_WTP_HEADER__

/* standard include */
#include "capwap.h"
#include "capwap_dtls.h"
#include "capwap_network.h"
#include "capwap_protocol.h"
#include "wtp_kmod.h"
#include "wifi_drivers.h"

/* WTP Configuration */
#define WTP_STANDARD_CONFIGURATION_FILE					"/etc/capwap/wtp.conf"

/* WTP runtime error return code */
#define WTP_ERROR_SYSTEM_FAILER				-1000
#define WTP_ERROR_LOAD_CONFIGURATION		-1001
#define WTP_ERROR_NETWORK					-1002
#define WTP_ERROR_INIT_BINDING				-1003
#define WTP_ERROR_MEMORY_LEAK				1

/* */
#define WTP_MIN_DISCOVERY_INTERVAL				2000
#define WTP_DISCOVERY_INTERVAL					20000
#define WTP_MAX_DISCOVERY_COUNT					10

#define WTP_SILENT_INTERVAL						30000

#define WTP_DTLS_INTERVAL						60000
#define WTP_DTLS_SESSION_DELETE					5000
#define WTP_FAILED_DTLS_SESSION_RETRY			3

#define WTP_RETRANSMIT_INTERVAL					3000
#define WTP_MAX_RETRANSMIT						5

#define WTP_DATACHANNEL_KEEPALIVE_INTERVAL		30000
#define WTP_DATACHANNEL_KEEPALIVEDEAD			60000

#define WTP_STATISTICSTIMER_INTERVAL			120000

#define WTP_ECHO_INTERVAL						30000

#define WTP_INIT_REMOTE_SEQUENCE				0xff

/* */
struct wtp_fds {
	int fdstotalcount;
	struct pollfd* fdspoll;

	int fdsnetworkcount;

	struct wtp_kmod_event* kmodevents;
	int kmodeventscount;
	int kmodeventsstartpos;

	struct wifi_event* wifievents;
	int wifieventscount;
	int wifieventsstartpos;
};

/* WTP */
struct wtp_t {
	int standalone;
	int running;

	/* */
	int kmodrequest;
	struct wtp_kmod_handle kmodhandle;

	/* */
	char wlanprefix[IFNAMSIZ];

	/* */
	struct capwap_network net;
	struct wtp_fds fds;

	/* */
	unsigned long state;
	int teardown;

	/* */
	int discoveryinterval;
	int discoverycount;
	int echointerval;

	/* Timer */
	struct capwap_timeout* timeout;
	unsigned long idtimercontrol;
	unsigned long idtimerecho;
	unsigned long idtimerkeepalive;
	unsigned long idtimerkeepalivedead;

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
	int retransmitcount;

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
	int faileddtlssessioncount;
	int faileddtlsauthfailcount;
};

extern struct wtp_t g_wtp;

/* */
int wtp_update_radio_in_use();

/* Build capwap element helper */
void wtp_create_radioadmstate_element(struct capwap_packet_txmng* txmngpacket);
void wtp_create_radioopsstate_element(struct capwap_packet_txmng* txmngpacket);
void wtp_create_80211_wtpradioinformation_element(struct capwap_packet_txmng* txmngpacket);

#endif /* __CAPWAP_WTP_HEADER__ */
