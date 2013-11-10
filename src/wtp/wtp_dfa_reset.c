#include "wtp.h"
#include "capwap_dfa.h"
#include "wtp_dfa.h"

/* */
void wtp_dfa_state_reset(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	ASSERT(timeout != NULL);

	/* Teardown connection and close application */
	g_wtp.running = 0;
	wtp_teardown_connection(timeout);

	/* TODO schedule reboot device */
}
