#include "wtp.h"
#include "capwap_dfa.h"
#include "wtp_dfa.h"

/* */
void wtp_dfa_state_sulking_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	g_wtp.discoverycount = 0;
	g_wtp.faileddtlssessioncount = 0;
	g_wtp.faileddtlsauthfailcount = 0;

	/* */
	wtp_dfa_change_state(CAPWAP_IDLE_STATE);
	wtp_dfa_state_idle();
}

/* */
void wtp_dfa_state_sulking(struct capwap_parsed_packet* packet) {
}
