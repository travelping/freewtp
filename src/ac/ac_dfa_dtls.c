#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* DTLS BIO send */
static int ac_bio_send(struct capwap_dtls* dtls, char* buffer, int length, void* param) {
	struct ac_session_t* session = (struct ac_session_t*)param;

	ASSERT(dtls->session == CAPWAP_DTLS_CONTROL_SESSION);

	return capwap_sendto(session->connection.socket.socket[session->connection.socket.type], buffer, length, &session->connection.localaddr, &session->connection.remoteaddr);
}

/* DTLS BIO Data send */
static int ac_bio_data_send(struct capwap_dtls* dtls, char* buffer, int length, void* param) {
	struct ac_session_data_t* sessiondata = (struct ac_session_data_t*)param;

	ASSERT(dtls->session == CAPWAP_DTLS_DATA_SESSION);

	return capwap_sendto(sessiondata->connection.socket.socket[sessiondata->connection.socket.type], buffer, length, &sessiondata->connection.localaddr, &sessiondata->connection.remoteaddr);
}

/* */
void ac_dtls_setup_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	ac_session_teardown((struct ac_session_t*)context);		/* Configure timeout */
}

/* */
int ac_dtls_setup(struct ac_session_t* session) {
	ASSERT(session != NULL);

	/* Create DTLS session */
	if (!capwap_crypt_createsession(&session->dtls, CAPWAP_DTLS_CONTROL_SESSION, &g_ac.dtlscontext, ac_bio_send, session)) {
		return 0;
	}

	if (capwap_crypt_open(&session->dtls, &session->connection.remoteaddr) == CAPWAP_HANDSHAKE_ERROR) {
		return 0;
	}

	/* Wait DTLS handshake complete */
	ac_dfa_change_state(session, CAPWAP_DTLS_CONNECT_STATE);
	capwap_timeout_set(session->timeout, session->idtimercontrol, AC_DTLS_INTERVAL, ac_dtls_setup_timeout, session, NULL);
	return 1;
}

/* */
int ac_dtls_data_setup(struct ac_session_data_t* sessiondata) {
	ASSERT(sessiondata != NULL);

	/* Create DTLS session */
	if (!capwap_crypt_createsession(&sessiondata->dtls, CAPWAP_DTLS_DATA_SESSION, &g_ac.dtlscontext, ac_bio_data_send, sessiondata)) {
		return 0;
	}

	if (capwap_crypt_open(&sessiondata->dtls, &sessiondata->connection.remoteaddr) == CAPWAP_HANDSHAKE_ERROR) {
		return 0;
	}

	return 1;
}
