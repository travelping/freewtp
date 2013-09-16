#ifndef __AC_SESSION_HEADER__
#define __AC_SESSION_HEADER__

#include "capwap_dtls.h"
#include "ac_soap.h"

#define AC_DFA_NO_PACKET			0
#define AC_DFA_ACCEPT_PACKET		1
#define AC_DFA_DROP_PACKET			2
#define AC_DFA_DEAD					3

/* */
#define AC_SESSION_ACTION_CLOSE		0

/* AC packet */
struct ac_packet {
	int plainbuffer;
	char buffer[0];
};

/* */
struct ac_session_control {
	struct sockaddr_storage localaddress;
	unsigned short count;
};

/* */
struct ac_session_action {
	long action;
	long param;
	long length;
	char data[0];
};

/* AC sessions */
struct ac_session_t {
	struct ac_state dfa;

	/* Soap */
	struct ac_http_soap_request* soaprequest;

	/* */
	char* wtpid;

	unsigned long count;
	struct sockaddr_storage acctrladdress;
	struct sockaddr_storage acdataaddress;
	struct sockaddr_storage wtpctrladdress;
	struct sockaddr_storage wtpdataaddress;
	struct capwap_socket ctrlsocket;
	struct capwap_socket datasocket;
	struct timeout_control timeout;

	struct capwap_sessionid_element sessionid;
	unsigned short binding;

	int teardown;
	struct capwap_dtls ctrldtls;
	struct capwap_dtls datadtls;

	pthread_t threadid;

	capwap_event_t waitpacket;
	capwap_lock_t sessionlock;
	struct capwap_list* actionsession;
	struct capwap_list* controlpackets;
	struct capwap_list* datapackets;

	unsigned char localseqnumber;
	unsigned char remoteseqnumber;
	unsigned short mtu;
	unsigned short fragmentid;
	struct capwap_packet_rxmng* rxmngctrlpacket;
	struct capwap_packet_rxmng* rxmngdatapacket;
	struct capwap_list* requestfragmentpacket;
	struct capwap_list* responsefragmentpacket;
	unsigned char lastrecvpackethash[16];

	unsigned long state;

	struct capwap_imageidentifier_element startupimage;
};

/* */
void* ac_session_thread(void* param);
int ac_session_teardown_connection(struct ac_session_t* session);
int ac_session_release_reference(struct ac_session_t* session);

/* */
void ac_session_send_action(struct ac_session_t* session, long action, long param, void* data, long length);

/* */
void ac_dfa_change_state(struct ac_session_t* session, int state);

/* */
void ac_get_control_information(struct capwap_list* controllist);

/* */
void ac_free_reference_last_request(struct ac_session_t* session);
void ac_free_reference_last_response(struct ac_session_t* session);

/* */
int ac_dfa_state_join(struct ac_session_t* session, struct capwap_parsed_packet* packet);
int ac_dfa_state_postjoin(struct ac_session_t* session, struct capwap_parsed_packet* packet);
int ac_dfa_state_join_to_dtlsteardown(struct ac_session_t* session, struct capwap_parsed_packet* packet);

/* */
int ac_bio_send(struct capwap_dtls* dtls, char* buffer, int length, void* param);
int ac_dfa_state_dtlssetup(struct ac_session_t* session, struct capwap_parsed_packet* packet);
int ac_dfa_state_dtlsconnect(struct ac_session_t* session, struct capwap_parsed_packet* packet);
int ac_dfa_state_dtlsconnect_to_dtlsteardown(struct ac_session_t* session, struct capwap_parsed_packet* packet);

/* */
int ac_dfa_state_configure(struct ac_session_t* session, struct capwap_parsed_packet* packet);
int ac_dfa_state_configure_to_dtlsteardown(struct ac_session_t* session, struct capwap_parsed_packet* packet);

/* */
int ac_dfa_state_datacheck(struct ac_session_t* session, struct capwap_parsed_packet* packet);
int ac_dfa_state_datacheck_to_run(struct ac_session_t* session, struct capwap_parsed_packet* packet);
int ac_dfa_state_datacheck_to_dtlsteardown(struct ac_session_t* session, struct capwap_parsed_packet* packet);

/* */
int ac_dfa_state_imagedata(struct ac_session_t* session, struct capwap_parsed_packet* packet);
int ac_dfa_state_imagedata_to_dtlsteardown(struct ac_session_t* session, struct capwap_parsed_packet* packet);

/* */
int ac_dfa_state_run(struct ac_session_t* session, struct capwap_parsed_packet* packet);
int ac_dfa_state_run_to_reset(struct ac_session_t* session, struct capwap_parsed_packet* packet);
int ac_dfa_state_run_to_dtlsteardown(struct ac_session_t* session, struct capwap_parsed_packet* packet);

/* */
int ac_dfa_state_reset(struct ac_session_t* session, struct capwap_parsed_packet* packet);
int ac_dfa_state_reset_to_dtlsteardown(struct ac_session_t* session, struct capwap_parsed_packet* packet);

/* */
int ac_dfa_state_teardown(struct ac_session_t* session, struct capwap_parsed_packet* packet);
int ac_dfa_state_dead(struct ac_session_t* session, struct capwap_parsed_packet* packet);

/* Soap function */
struct ac_soap_response* ac_session_send_soap_request(struct ac_session_t* session, char* method, int numparam, ...);
#define ac_soap_authorizewtpsession(s, wtpid)								ac_session_send_soap_request((s), "authorizeWTPSession", 1, "xs:string", "idwtp", wtpid)
#define ac_soap_joinwtpsession(s, wtpid, joinparam)							ac_session_send_soap_request((s), "joinWTPSession", 2, "xs:string", "idwtp", wtpid, "xs:base64Binary", "join", joinparam)
#define ac_soap_configurestatuswtpsession(s, wtpid, confstatusparam)		ac_session_send_soap_request((s), "configureStatusWTPSession", 2, "xs:string", "idwtp", wtpid, "xs:base64Binary", "confstatus", confstatusparam)
#define ac_soap_changestatewtpsession(s, wtpid, changestateparam)			ac_session_send_soap_request((s), "changeStateWTPSession", 2, "xs:string", "idwtp", wtpid, "xs:base64Binary", "changestate", changestateparam)
#define ac_soap_runningwtpsession(s, wtpid)									ac_session_send_soap_request((s), "runningWTPSession", 1, "xs:string", "idwtp", wtpid)
#define ac_soap_teardownwtpsession(s, wtpid)								ac_session_send_soap_request((s), "teardownWTPSession", 1, "xs:string", "idwtp", wtpid)
#define ac_soap_checkwtpsession(s, wtpid)									ac_session_send_soap_request((s), "checkWTPSession", 1, "xs:string", "idwtp", wtpid)

#endif /* __AC_SESSION_HEADER__ */
