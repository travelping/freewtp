#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* DTLS BIO send */
int ac_bio_send(struct capwap_dtls* dtls, char* buffer, int length, void* param) {
	struct ac_session_t* session = (struct ac_session_t*)param;
	struct capwap_socket* socket = ((dtls->session == CAPWAP_DTLS_CONTROL_SESSION) ? &session->ctrlsocket : &session->datasocket);
	struct sockaddr_storage* wtpaddress = ((dtls->session == CAPWAP_DTLS_CONTROL_SESSION) ? &session->wtpctrladdress : &session->wtpdataaddress);
	struct sockaddr_storage* acaddress = ((dtls->session == CAPWAP_DTLS_CONTROL_SESSION) ? &session->acctrladdress : &session->acdataaddress);
	
	return capwap_sendto(socket->socket[socket->type], buffer, length, acaddress, wtpaddress);
}

/* */
int ac_dfa_state_dtlssetup(struct ac_session_t* session, struct capwap_packet* packet) {
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);
	ASSERT(packet == NULL);

	/* Create DTLS session */
	if (!capwap_crypt_createsession(&session->ctrldtls, CAPWAP_DTLS_CONTROL_SESSION, &g_ac.dtlscontext, ac_bio_send, session)) {
		ac_dfa_change_state(session, CAPWAP_DTLS_SETUP_TO_IDLE_STATE);			/* TODO */
		status = AC_DFA_NO_PACKET;
	} else {
		if (capwap_crypt_open(&session->ctrldtls, &session->wtpctrladdress) == CAPWAP_HANDSHAKE_ERROR) {
			ac_dfa_change_state(session, CAPWAP_DTLS_SETUP_TO_IDLE_STATE);		/* TODO */
			status = AC_DFA_NO_PACKET;
		} else {
			ac_dfa_change_state(session, CAPWAP_DTLS_CONNECT_STATE);
		}
	}
	
	return status;
}

/* */
int ac_dfa_state_dtlsconnect(struct ac_session_t* session, struct capwap_packet* packet) {
	ASSERT(session != NULL);
	ASSERT(packet == NULL);

	ac_dfa_change_state(session, CAPWAP_DTLS_CONNECT_TO_DTLS_TEARDOWN_STATE);		/* TODO */
	return AC_DFA_NO_PACKET;
}

/* */
int ac_dfa_state_dtlsconnect_to_dtlsteardown(struct ac_session_t* session, struct capwap_packet* packet) {
	return ac_session_teardown_connection(session);
}
