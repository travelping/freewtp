#include "wtp.h"
#include "capwap_dfa.h"
#include "wtp_dfa.h"

/* */
void wtp_dfa_state_sulking(struct capwap_parsed_packet* packet) {
	if (!packet) {
		g_wtp.dfa.rfcDiscoveryCount = 0;
		g_wtp.dfa.rfcFailedDTLSSessionCount = 0;
		g_wtp.dfa.rfcFailedDTLSAuthFailCount = 0;

		/* */
		capwap_timeout_set(0, g_wtp.timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		wtp_dfa_change_state(CAPWAP_IDLE_STATE);
	}
}
