#ifndef __WTP_DFA_HEADER__
#define __WTP_DFA_HEADER__

#include <ev.h>

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
void wtp_abort_connecting(void);

/* */
void wtp_socket_io_start(void);
void wtp_socket_io_stop(void);

/* */
void wtp_free_packet_rxmng(void);
void wtp_free_reference_last_request(void);
void wtp_free_reference_last_response(void);

/* State machine */
int wtp_dfa_running();
void wtp_dfa_change_state(int state);

/* */
void wtp_start_dtlssetup(void);
void wtp_start_datachannel(void);

/* */
void wtp_send_datacheck(void);

/* */
void wtp_dfa_start_retransmition_timer(void);
void wtp_dfa_stop_retransmition_timer(void);

/* */
void wtp_dfa_state_idle_enter(void);
void wtp_dfa_state_discovery_enter(void);
void wtp_dfa_state_sulking_enter(void);
void wtp_dfa_state_dtlsconnect_enter(void);
void wtp_dfa_state_dtlsteardown_enter(void);
void wtp_dfa_state_join_enter(void);
void wtp_dfa_state_configure_enter(void);
void wtp_dfa_state_reset_enter(void);
void wtp_dfa_state_datacheck_enter(void);
void wtp_dfa_state_run_enter(void);
void wtp_dfa_state_dead_enter(void);

void wtp_dfa_state_discovery(struct capwap_parsed_packet* packet);
void wtp_dfa_state_sulking(struct capwap_parsed_packet* packet);
void wtp_dfa_state_dtlsteardown(struct capwap_parsed_packet* packet);
void wtp_dfa_state_join(struct capwap_parsed_packet* packet);
void wtp_dfa_state_configure(struct capwap_parsed_packet* packet);
void wtp_dfa_state_datacheck(struct capwap_parsed_packet* packet);
void wtp_dfa_state_run(struct capwap_parsed_packet* packet);

/* */
void wtp_ieee80211_packet(uint8_t radioid, const struct ieee80211_header* header, int length);

void wtp_recv_data_keepalive(void);
void wtp_recv_data(uint8_t* buffer, int length);

void wtp_timeout_stop_all(void);
void wtp_reset_state(void);

#endif /* __WTP_DFA_HEADER__ */
