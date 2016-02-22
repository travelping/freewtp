#include "wtp.h"
#include "capwap_dfa.h"
#include "wtp_dfa.h"

/* */
static void wtp_dfa_state_dtlsconnect_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	wtp_teardown_connection();
}

/* */
void wtp_start_dtlssetup(void) {
	/* Create DTLS session */
	if (!capwap_crypt_createsession(&g_wtp.dtls, &g_wtp.dtlscontext)) {
		wtp_dfa_change_state(CAPWAP_SULKING_STATE);
		capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_SILENT_INTERVAL, wtp_dfa_state_sulking_timeout, NULL, NULL);
	} else {
		if (capwap_crypt_open(&g_wtp.dtls) == CAPWAP_HANDSHAKE_ERROR) {
			wtp_dfa_change_state(CAPWAP_SULKING_STATE);
			capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_SILENT_INTERVAL, wtp_dfa_state_sulking_timeout, NULL, NULL);
		} else {
			wtp_dfa_change_state(CAPWAP_DTLS_CONNECT_STATE);
			capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_DTLS_INTERVAL, wtp_dfa_state_dtlsconnect_timeout, NULL, NULL);
		}
	}
}

/* */
void wtp_start_datachannel(void) {
	union sockaddr_capwap dataaddr;

	/* Set AC data address */
	memcpy(&dataaddr, &g_wtp.dtls.peeraddr, sizeof(union sockaddr_capwap));
	CAPWAP_SET_NETWORK_PORT(&dataaddr, (CAPWAP_GET_NETWORK_PORT(&g_wtp.dtls.peeraddr) + 1));

#ifdef DEBUG
	{
		char addr[INET6_ADDRSTRLEN];
		capwap_logging_debug("Create data channel with peer %s:%d", capwap_address_to_string(&dataaddr, addr, INET6_ADDRSTRLEN), (int)CAPWAP_GET_NETWORK_PORT(&dataaddr));
	}
#endif

	/* Bind data address and Connect to AC data channel */
	if (wtp_kmod_create(g_wtp.net.localaddr.ss.ss_family, &dataaddr.ss, &g_wtp.sessionid, g_wtp.mtu) == 0) {
		capwap_logging_error("Data channel connected");
		/* Reset AC Prefered List Position */
		g_wtp.acpreferedselected = 0;

		/* Set timer */
		wtp_dfa_change_state(CAPWAP_RUN_STATE);
		capwap_timeout_unset(g_wtp.timeout, g_wtp.idtimercontrol);
		capwap_timeout_set(g_wtp.timeout, g_wtp.idtimerecho, g_wtp.echointerval, wtp_dfa_state_run_echo_timeout, NULL, NULL);
		capwap_timeout_set(g_wtp.timeout, g_wtp.idtimerkeepalivedead, WTP_DATACHANNEL_KEEPALIVEDEAD, wtp_dfa_state_run_keepalivedead_timeout, NULL, NULL);
	} else {
		/* Error to send packets */
		capwap_logging_error("Error to send data channel keepalive packet");
		wtp_teardown_connection();
	}
}

/* */
static void wtp_dfa_state_dtlsteardown_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	/* Free and reset resource */
	if (g_wtp.dtls.enable) {
		capwap_crypt_freesession(&g_wtp.dtls);
	}

	/* */
	if (g_wtp.acname.name) {
		capwap_free(g_wtp.acname.name);
		g_wtp.acname.name = NULL;
	}

	/* */
	wtp_free_reference_last_request();
	wtp_free_reference_last_response();
	wtp_free_packet_rxmng();

	/* */
	if (!g_wtp.running) {
		wtp_dfa_change_state(CAPWAP_DEAD_STATE);
	} else if ((g_wtp.faileddtlssessioncount >= WTP_FAILED_DTLS_SESSION_RETRY) || (g_wtp.faileddtlsauthfailcount >= WTP_FAILED_DTLS_SESSION_RETRY)) {
		wtp_dfa_change_state(CAPWAP_SULKING_STATE);
		capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_SILENT_INTERVAL, wtp_dfa_state_sulking_timeout, NULL, NULL);
	} else {
		wtp_dfa_change_state(CAPWAP_IDLE_STATE);
		wtp_dfa_state_idle();
	}
}

/* */
void wtp_dfa_state_dtlsteardown(struct capwap_parsed_packet* packet) {
}

/* Teardown connection */
void wtp_teardown_connection(void) {
	g_wtp.teardown = 1;

	/* TODO: close SSID ? */

	/* DTSL Control */
	if (g_wtp.dtls.enable) {
		capwap_crypt_close(&g_wtp.dtls);
	}

	/* Close data channel session */
	wtp_kmod_resetsession();

	/* */
	wtp_dfa_change_state(CAPWAP_DTLS_TEARDOWN_STATE);
	capwap_timeout_unsetall(g_wtp.timeout);
	capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_DTLS_SESSION_DELETE, wtp_dfa_state_dtlsteardown_timeout, NULL, NULL);
}
