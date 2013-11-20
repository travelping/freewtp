#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
void ac_dfa_state_reset(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	ASSERT(session != NULL);

	if (packet) {
		unsigned short binding;

		/* */
		binding = GET_WBID_HEADER(packet->rxmngpacket->header);
		if ((binding == session->binding) && (packet->rxmngpacket->ctrlmsg.type == CAPWAP_RESET_RESPONSE) && ((session->localseqnumber - 1) == packet->rxmngpacket->ctrlmsg.seq)) {
			struct capwap_resultcode_element* resultcode;

			/* Check the success of the Request */
			resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
			if (resultcode && !CAPWAP_RESULTCODE_OK(resultcode->code)) {
				capwap_logging_warning("Receive Reset Response with error: %d", (int)resultcode->code);
			}

			ac_session_teardown(session);
		}
	} else {
		/* No Configuration status response received */
		session->dfa.rfcRetransmitCount++;
		if (session->dfa.rfcRetransmitCount >= session->dfa.rfcMaxRetransmit) {
			/* Timeout reset state */
			ac_free_reference_last_request(session);
			ac_session_teardown(session);
		} else {
			/* Retransmit configuration request */
			if (!capwap_crypt_sendto_fragmentpacket(&session->dtls, session->connection.socket.socket[session->connection.socket.type], session->requestfragmentpacket, &session->connection.localaddr, &session->connection.remoteaddr)) {
				capwap_logging_debug("Warning: error to resend reset request packet");
			}

			/* Update timeout */
			capwap_set_timeout(session->dfa.rfcRetransmitInterval, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		}
	}
}
