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
int wtp_bio_send(struct capwap_dtls* dtls, char* buffer, int length, void* param);

/* */
void wtp_teardown_connection(struct timeout_control* timeout);

/* */
void wtp_free_packet_rxmng(int isctrlmsg);
void wtp_free_reference_last_request(void);
void wtp_free_reference_last_response(void);

/* State machine */
int wtp_dfa_running(void);
void wtp_dfa_change_state(int state);

/* */
void wtp_start_dtlssetup(struct timeout_control* timeout);
void wtp_start_datachannel(struct timeout_control* timeout);

/* */
void wtp_send_join(struct timeout_control* timeout);
void wtp_send_configure(struct timeout_control* timeout);
void wtp_send_datacheck(struct timeout_control* timeout);

/* */
void wtp_dfa_state_idle(struct capwap_parsed_packet* packet, struct timeout_control* timeout);
void wtp_dfa_state_discovery(struct capwap_parsed_packet* packet, struct timeout_control* timeout);
void wtp_dfa_state_dtlsteardown(struct capwap_parsed_packet* packet, struct timeout_control* timeout);
void wtp_dfa_state_sulking(struct capwap_parsed_packet* packet, struct timeout_control* timeout);
void wtp_dfa_state_join(struct capwap_parsed_packet* packet, struct timeout_control* timeout);
void wtp_dfa_state_configure(struct capwap_parsed_packet* packet, struct timeout_control* timeout);
void wtp_dfa_state_datacheck(struct capwap_parsed_packet* packet, struct timeout_control* timeout);
void wtp_dfa_state_run(struct capwap_parsed_packet* packet, struct timeout_control* timeout);
void wtp_dfa_state_reset(struct capwap_parsed_packet* packet, struct timeout_control* timeout);

/* */
void wtp_send_data_wireless_packet(uint8_t radioid, uint8_t wlanid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength, int leavenativeframe);

#endif /* __WTP_DFA_HEADER__ */
