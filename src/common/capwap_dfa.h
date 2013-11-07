#ifndef __CAPWAP_DFA_HEADER__
#define __CAPWAP_DFA_HEADER__

#define CAPWAP_UNDEF_STATE								-1
#define CAPWAP_START_STATE								0
#define CAPWAP_IDLE_STATE								1
#define CAPWAP_DISCOVERY_STATE							2
#define CAPWAP_SULKING_STATE							3
#define CAPWAP_DTLS_CONNECT_STATE						4
#define CAPWAP_DTLS_TEARDOWN_STATE						5
#define CAPWAP_JOIN_STATE								6
#define CAPWAP_POSTJOIN_STATE							7
#define CAPWAP_IMAGE_DATA_STATE							8
#define CAPWAP_CONFIGURE_STATE							9
#define CAPWAP_RESET_STATE								10
#define CAPWAP_DATA_CHECK_STATE							11
#define CAPWAP_DATA_CHECK_TO_RUN_STATE					12
#define CAPWAP_RUN_STATE								13
#define CAPWAP_DEAD_STATE								14
#define CAPWAP_LAST_STATE								14

/* */
#ifdef DEBUG
char* capwap_dfa_getname(int state);
#else
#define capwap_dfa_getname(x)					""
#endif

#endif /* __CAPWAP_DFA_HEADER__ */
