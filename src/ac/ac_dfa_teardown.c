#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
int ac_dfa_state_teardown(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	ASSERT(session != NULL);
	ASSERT(packet == NULL);

	// Notify teardown session
	if (session->wtpid) {
		struct ac_soap_response* response = ac_soap_teardownwtpsession(session, session->wtpid);
		if (response) {
			ac_soapclient_free_response(response);
		}
	}

	/* Defered free resource */
	ac_dfa_change_state(session, CAPWAP_DEAD_STATE);
	return AC_DFA_DROP_PACKET;
}
