#ifndef __WTP_DFA_HEADER__
#define __WTP_DFA_HEADER__

#include "capwap_network.h"
#include "capwap_protocol.h"
#include "capwap_element.h"

/* */	/* TODO da rifare */
struct wtp_discovery_response {
	struct capwap_array* controlipv4;
	struct capwap_array* controlipv6;
};

void wtp_free_discovery_response_array(void);

/* */
void wtp_teardown_connection(void);

/* */
void wtp_free_packet_rxmng(void);
void wtp_free_reference_last_request(void);
void wtp_free_reference_last_response(void);

/* State machine */
int wtp_dfa_running(void);
void wtp_dfa_change_state(int state);

/* */
void wtp_start_dtlssetup(void);
void wtp_start_datachannel(void);

/* */
void wtp_send_join(void);
void wtp_send_configure(void);
void wtp_send_datacheck(void);

/* */
void wtp_dfa_retransmition_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param);

int wtp_dfa_update_fdspool(struct wtp_fds* fds);
void wtp_dfa_free_fdspool(struct wtp_fds* fds);

/* */
void wtp_dfa_state_idle(void);

void wtp_dfa_state_discovery(struct capwap_parsed_packet* packet);
void wtp_dfa_state_discovery_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param);

void wtp_dfa_state_dtlsteardown(struct capwap_parsed_packet* packet);

void wtp_dfa_state_sulking(struct capwap_parsed_packet* packet);
void wtp_dfa_state_sulking_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param);

void wtp_dfa_state_join(struct capwap_parsed_packet* packet);

void wtp_dfa_state_configure(struct capwap_parsed_packet* packet);

void wtp_dfa_state_datacheck(struct capwap_parsed_packet* packet);

void wtp_dfa_state_run(struct capwap_parsed_packet* packet);
void wtp_dfa_state_run_echo_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param);
void wtp_dfa_state_run_keepalive_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param);
void wtp_dfa_state_run_keepalivedead_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param);

void wtp_dfa_state_reset(void);

/* */
void wtp_ieee80211_packet(uint8_t radioid, const struct ieee80211_header* header, int length);

void wtp_recv_data_keepalive(void);
void wtp_recv_data(uint8_t* buffer, int length);

void wtp_reset_state(void);

#endif /* __WTP_DFA_HEADER__ */
