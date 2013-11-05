#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
void ac_dfa_state_teardown(struct ac_session_t* session) {
	ASSERT(session != NULL);

	// Notify teardown session
	if (session->wtpid) {
		struct ac_soap_response* response = ac_soap_teardownwtpsession(session, session->wtpid);
		if (response) {
			ac_soapclient_free_response(response);
		}
	}

	/* Defered free resource */
	ac_dfa_change_state(session, CAPWAP_DEAD_STATE);
}
