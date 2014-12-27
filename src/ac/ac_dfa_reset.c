#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
void ac_dfa_state_reset(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	unsigned short binding;

	ASSERT(session != NULL);
	ASSERT(packet != NULL);

	binding = GET_WBID_HEADER(packet->rxmngpacket->header);
	if ((binding == session->binding) && (packet->rxmngpacket->ctrlmsg.type == CAPWAP_RESET_RESPONSE) && (session->localseqnumber == packet->rxmngpacket->ctrlmsg.seq)) {
		struct capwap_resultcode_element* resultcode;

		/* */
		session->localseqnumber++;

		/* Check the success of the Request */
		resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
		if (resultcode && !CAPWAP_RESULTCODE_OK(resultcode->code)) {
			capwap_logging_warning("Receive Reset Response with error: %d", (int)resultcode->code);
		}

		/* */
		ac_free_reference_last_request(session);
		ac_session_teardown(session);
	}
}
