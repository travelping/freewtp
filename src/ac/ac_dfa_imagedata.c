#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
int ac_dfa_state_imagedata(struct ac_session_t* session, struct capwap_packet* packet) {
	int status = AC_DFA_ACCEPT_PACKET;

	/* TODO */
	
	return status;
}

/* */
int ac_dfa_state_imagedata_to_dtlsteardown(struct ac_session_t* session, struct capwap_packet* packet) {
	return ac_session_teardown_connection(session);
}
