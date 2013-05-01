#include "wtp.h"
#include "capwap_dfa.h"
#include "wtp_dfa.h"

/* DTLS BIO send */
int wtp_bio_send(struct capwap_dtls* dtls, char* buffer, int length, void* param) {
	struct capwap_socket* socket = ((dtls->session == CAPWAP_DTLS_CONTROL_SESSION) ? &g_wtp.acctrlsock : &g_wtp.acdatasock);
	struct sockaddr_storage* wtpaddress = ((dtls->session == CAPWAP_DTLS_CONTROL_SESSION) ? &g_wtp.wtpctrladdress : &g_wtp.wtpdataaddress);
	struct sockaddr_storage* acaddress = ((dtls->session == CAPWAP_DTLS_CONTROL_SESSION) ? &g_wtp.acctrladdress : &g_wtp.acdataaddress);
	
	return capwap_sendto(socket->socket[socket->type], buffer, length, wtpaddress, acaddress);
}

/* */
int wtp_dfa_state_dtlssetup(struct capwap_packet* packet, struct timeout_control* timeout) {
	int status = WTP_DFA_ACCEPT_PACKET;

	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);

	/* Create DTLS session */
	if (!capwap_crypt_createsession(&g_wtp.ctrldtls, CAPWAP_DTLS_CONTROL_SESSION, &g_wtp.dtlscontext, wtp_bio_send, NULL)) {
		wtp_dfa_change_state(CAPWAP_DTLS_SETUP_TO_IDLE_STATE);
		status = WTP_DFA_NO_PACKET;
	} else {
		if (capwap_crypt_open(&g_wtp.ctrldtls, &g_wtp.acctrladdress) == CAPWAP_HANDSHAKE_ERROR) {
			wtp_dfa_change_state(CAPWAP_DTLS_SETUP_TO_IDLE_STATE);
			status = WTP_DFA_NO_PACKET;
		} else {
			wtp_dfa_change_state(CAPWAP_DTLS_CONNECT_STATE);
			capwap_set_timeout(g_wtp.dfa.rfcWaitDTLS, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		}
	}

	return status;
}

/* */
int wtp_dfa_state_dtlsconnect(struct capwap_packet* packet, struct timeout_control* timeout) {
	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);
	
	wtp_dfa_change_state(CAPWAP_DTLS_CONNECT_TO_DTLS_TEARDOWN_STATE);
	return WTP_DFA_NO_PACKET;
}

/* */
int wtp_dfa_state_dtlsconnect_to_dtlsteardown(struct capwap_packet* packet, struct timeout_control* timeout) {
	ASSERT(packet == NULL);
	ASSERT(timeout != NULL);

	return wtp_teardown_connection(timeout);
}

/* Teardown connection */
int wtp_teardown_connection(struct timeout_control* timeout) {
	ASSERT(timeout != NULL);

	/* DTSL Control */
	if (g_wtp.ctrldtls.enable) {
		capwap_crypt_close(&g_wtp.ctrldtls);
	}
	
	/* DTLS Data */
	if (g_wtp.datadtls.enable) {
		capwap_crypt_close(&g_wtp.datadtls);
	}

	/* */
	capwap_killall_timeout(timeout);
	capwap_set_timeout(g_wtp.dfa.rfcDTLSSessionDelete, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
	wtp_dfa_change_state(CAPWAP_DTLS_TEARDOWN_STATE);
	return WTP_DFA_DROP_PACKET;
}

/* */
int wtp_dfa_state_dtlsteardown(struct capwap_packet* packet, struct timeout_control* timeout) {
	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);
	
	/* Free and reset resource */
	if (g_wtp.ctrldtls.enable) {
		capwap_crypt_freesession(&g_wtp.ctrldtls);
	}
	
	if (g_wtp.datadtls.enable) {
		capwap_crypt_freesession(&g_wtp.datadtls);
	}

	/* */
	wtp_free_reference_last_request();
	wtp_free_reference_last_response();

	/* */	
	if ((g_wtp.dfa.rfcFailedDTLSSessionCount >= g_wtp.dfa.rfcMaxFailedDTLSSessionRetry) || (g_wtp.dfa.rfcFailedDTLSAuthFailCount >= g_wtp.dfa.rfcMaxFailedDTLSSessionRetry)) {
		wtp_dfa_change_state(CAPWAP_DTLS_TEARDOWN_TO_SULKING_STATE);
	} else {
		wtp_dfa_change_state(CAPWAP_DTLS_TEARDOWN_TO_IDLE_STATE);
	}

	/* TODO controllare se è richiesto il ravvio del sistema */
	return WTP_DFA_NO_PACKET;
}

/* */
int wtp_dfa_state_dtlsteardown_to_sulking(struct capwap_packet* packet, struct timeout_control* timeout) {
	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);
	
	capwap_set_timeout(g_wtp.dfa.rfcSilentInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
	wtp_dfa_change_state(CAPWAP_SULKING_STATE);

	return WTP_DFA_DROP_PACKET;
}

/* */
int wtp_dfa_state_dtlsteardown_to_idle(struct capwap_packet* packet, struct timeout_control* timeout) {
	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);
	
	wtp_dfa_change_state(CAPWAP_IDLE_STATE);
	return WTP_DFA_NO_PACKET;
}
