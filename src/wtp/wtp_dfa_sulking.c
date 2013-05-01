#include "wtp.h"
#include "capwap_dfa.h"
#include "wtp_dfa.h"

/* */
int wtp_dfa_state_sulking(struct capwap_packet* packet, struct timeout_control* timeout) {
	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);
	
	wtp_dfa_change_state(CAPWAP_SULKING_TO_IDLE_STATE);

	return WTP_DFA_NO_PACKET;
}

/* */
int wtp_dfa_state_sulking_to_idle(struct capwap_packet* packet, struct timeout_control* timeout) {
	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);
	
	g_wtp.dfa.rfcDiscoveryCount = 0;
	g_wtp.dfa.rfcFailedDTLSSessionCount = 0;
	g_wtp.dfa.rfcFailedDTLSAuthFailCount = 0;
	
	wtp_dfa_change_state(CAPWAP_IDLE_STATE);

	return WTP_DFA_NO_PACKET;
}
