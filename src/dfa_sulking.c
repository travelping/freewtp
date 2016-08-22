#include "wtp.h"
#include "capwap_dfa.h"
#include "dfa.h"

/* */
static void wtp_dfa_state_sulking_timeout(EV_P_ ev_timer *w, int revents)
{
	g_wtp.discoverycount = 0;
	g_wtp.faileddtlssessioncount = 0;
	g_wtp.faileddtlsauthfailcount = 0;

	/* */
	wtp_dfa_change_state(CAPWAP_IDLE_STATE);
}

/* */
void wtp_dfa_state_sulking_enter()
{
	ev_timer_init(&g_wtp.timercontrol, wtp_dfa_state_sulking_timeout,
		      WTP_SILENT_INTERVAL / 1000.0, 0.);
	ev_timer_start(EV_DEFAULT_UC_ &g_wtp.timercontrol);
}

/* */
void wtp_dfa_state_sulking(struct capwap_parsed_packet* packet) {
}
