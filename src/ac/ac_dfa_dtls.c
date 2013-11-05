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
int ac_dtls_setup(struct ac_session_t* session) {
	ASSERT(session != NULL);

	/* Create DTLS session */
	if (!capwap_crypt_createsession(&session->ctrldtls, CAPWAP_DTLS_CONTROL_SESSION, &g_ac.dtlscontext, ac_bio_send, session)) {
		return 0;
	}

	if (capwap_crypt_open(&session->ctrldtls, &session->wtpctrladdress) == CAPWAP_HANDSHAKE_ERROR) {
		return 0;
	}

	/* Wait DTLS handshake complete */
	ac_dfa_change_state(session, CAPWAP_DTLS_CONNECT_STATE);
	capwap_set_timeout(session->dfa.rfcWaitDTLS, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
	return 1;
}
