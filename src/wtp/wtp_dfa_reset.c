#include "wtp.h"
#include "capwap_dfa.h"
#include "wtp_dfa.h"

/* */
void wtp_dfa_state_reset(void) {
	/* Teardown connection and close application */
	g_wtp.running = 0;
	wtp_teardown_connection();

	/* TODO schedule reboot device */
}
