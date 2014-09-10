#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
int ac_dtls_setup(struct ac_session_t* session) {
	ASSERT(session != NULL);

	/* Create DTLS session */
	if (!capwap_crypt_createsession(&session->dtls, &g_ac.dtlscontext)) {
		return 0;
	}

	if (capwap_crypt_open(&session->dtls) == CAPWAP_HANDSHAKE_ERROR) {
		return 0;
	}

	/* Wait DTLS handshake complete */
	ac_dfa_change_state(session, CAPWAP_DTLS_CONNECT_STATE);
	capwap_timeout_set(session->timeout, session->idtimercontrol, AC_DTLS_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
	return 1;
}
