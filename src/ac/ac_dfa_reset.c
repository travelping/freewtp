#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
int ac_dfa_state_reset(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);

	if (packet) {
		unsigned short binding;

		/* */
		binding = GET_WBID_HEADER(packet->rxmngpacket->header);
		if ((binding == session->binding) && (packet->rxmngpacket->ctrlmsg.type == CAPWAP_RESET_RESPONSE) && ((session->localseqnumber - 1) == packet->rxmngpacket->ctrlmsg.seq)) {
			ac_dfa_change_state(session, CAPWAP_RESET_TO_DTLS_TEARDOWN_STATE);
			status = AC_DFA_NO_PACKET;
		}
	} else {
		/* No Configuration status response received */
		session->dfa.rfcRetransmitCount++;
		if (session->dfa.rfcRetransmitCount >= session->dfa.rfcMaxRetransmit) {
			/* Timeout reset state */
			ac_free_reference_last_request(session);
			ac_dfa_change_state(session, CAPWAP_RESET_TO_DTLS_TEARDOWN_STATE);
			status = AC_DFA_NO_PACKET;
		} else {
			/* Retransmit configuration request */	
			if (!capwap_crypt_sendto_fragmentpacket(&session->ctrldtls, session->ctrlsocket.socket[session->ctrlsocket.type], session->requestfragmentpacket, &session->acctrladdress, &session->wtpctrladdress)) {
				capwap_logging_debug("Warning: error to resend reset request packet");
			}

			/* Update timeout */
			capwap_set_timeout(session->dfa.rfcRetransmitInterval, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		}
	}

	return status;
}

/* */
int ac_dfa_state_reset_to_dtlsteardown(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	return ac_session_teardown_connection(session);
}
