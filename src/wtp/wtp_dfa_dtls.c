#include "wtp.h"
#include "capwap_dfa.h"
#include "wtp_dfa.h"
#include "wtp_radio.h"

/* */
static void wtp_dfa_state_dtlsconnect_timeout(EV_P_ ev_timer *w, int revents)
{
	log_printf(LOG_DEBUG, "DTLS Connect Timeout");
	wtp_teardown_connection();
}

/* */
void wtp_dfa_state_dead_enter(void)
{
	ev_break(EV_DEFAULT_UC_ EVBREAK_ALL);
}

/* */
void wtp_dfa_state_dtlsconnect_enter(void)
{
	ev_timer_init(&g_wtp.timercontrol, wtp_dfa_state_dtlsconnect_timeout,
		      WTP_DTLS_INTERVAL / 1000.0, 0.);
	ev_timer_start(EV_DEFAULT_UC_ &g_wtp.timercontrol);
}

/* */
void wtp_start_dtlssetup(void)
{
	/* Create DTLS session */
	if (!capwap_crypt_createsession(&g_wtp.dtls, &g_wtp.dtlscontext)) {
		wtp_dfa_change_state(CAPWAP_SULKING_STATE);
		return;
	}

	if (capwap_crypt_open(&g_wtp.dtls) == CAPWAP_HANDSHAKE_ERROR) {
		wtp_dfa_change_state(CAPWAP_SULKING_STATE);
	} else
		wtp_dfa_change_state(CAPWAP_DTLS_CONNECT_STATE);
}

/* */
void wtp_start_datachannel(void)
{
	union sockaddr_capwap dataaddr;

	/* Set AC data address */
	memcpy(&dataaddr, &g_wtp.dtls.peeraddr, sizeof(union sockaddr_capwap));
	CAPWAP_SET_NETWORK_PORT(&dataaddr, (CAPWAP_GET_NETWORK_PORT(&g_wtp.dtls.peeraddr) + 1));

#ifdef DEBUG
	{
		char addr[INET6_ADDRSTRLEN];
		log_printf(LOG_DEBUG, "Create data channel with peer %s:%d",
				     capwap_address_to_string(&dataaddr, addr, INET6_ADDRSTRLEN),
				     (int)CAPWAP_GET_NETWORK_PORT(&dataaddr));
	}
#endif

	/* Bind data address and Connect to AC data channel */
	if (wtp_kmod_create(g_wtp.net.localaddr.ss.ss_family, &dataaddr.ss, &g_wtp.sessionid, g_wtp.mtu) != 0) {
		/* Error to send packets */
		log_printf(LOG_ERR, "Error to send data channel keepalive packet");
		wtp_teardown_connection();
		return;
	}

	log_printf(LOG_ERR, "Data channel connected");
	/* Reset AC Prefered List Position */
	g_wtp.acpreferedselected = 0;

	/* Set timer */
	wtp_dfa_change_state(CAPWAP_RUN_STATE);
}

/* */
static void wtp_dfa_state_dtlsteardown_timeout(EV_P_ ev_timer *w, int revents)
{
	/* Free and reset resource */
	if (g_wtp.dtls.enable)
		capwap_crypt_freesession(&g_wtp.dtls);

	/* */
	if (g_wtp.acname.name) {
		capwap_free(g_wtp.acname.name);
		g_wtp.acname.name = NULL;
	}

	wtp_socket_io_stop();
	capwap_close_sockets(&g_wtp.net);

	/* */
	wtp_reset_state();

	/* */
	if (!g_wtp.running) {
		wtp_dfa_change_state(CAPWAP_DEAD_STATE);
	} else if ((g_wtp.faileddtlssessioncount >= WTP_FAILED_DTLS_SESSION_RETRY) ||
		   (g_wtp.faileddtlsauthfailcount >= WTP_FAILED_DTLS_SESSION_RETRY)) {
		wtp_dfa_change_state(CAPWAP_SULKING_STATE);
	} else
		wtp_dfa_change_state(CAPWAP_IDLE_STATE);
}

/* */
void wtp_dfa_state_dtlsteardown_enter(void)
{
	wtp_timeout_stop_all();
	ev_timer_init(&g_wtp.timercontrol, wtp_dfa_state_dtlsteardown_timeout,
		      WTP_DTLS_SESSION_DELETE / 1000.0, 0.);
	ev_timer_start(EV_DEFAULT_UC_ &g_wtp.timercontrol);
}

/* */
void wtp_dfa_state_dtlsteardown(struct capwap_parsed_packet* packet) {
}

/* Teardown connection */
void wtp_teardown_connection(void)
{
	g_wtp.teardown = 1;

	wtp_radio_reset();

	ev_io_stop(EV_DEFAULT_UC_ &g_wtp.socket_ev);

	/* DTLS Control */
	if (g_wtp.dtls.enable)
		capwap_crypt_close(&g_wtp.dtls);

	/* Close data channel session */
	wtp_kmod_resetsession();

	wtp_dfa_change_state(CAPWAP_DTLS_TEARDOWN_STATE);
}
