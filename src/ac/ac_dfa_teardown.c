#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
int ac_dfa_state_teardown(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	ASSERT(session != NULL);
	ASSERT(packet == NULL);

	/* Defered free resource */
	ac_dfa_change_state(session, CAPWAP_DEAD_STATE);
	return AC_DFA_DROP_PACKET;
}

/* */
int ac_dfa_state_dead(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	ASSERT(session != NULL);
	ASSERT(packet == NULL);

	return AC_DFA_DEAD;
}
