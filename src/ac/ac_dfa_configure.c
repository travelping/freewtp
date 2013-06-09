#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
int ac_dfa_state_configure(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	unsigned long i;
	unsigned short binding;
	struct capwap_array* radioadmstate;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);
	
	if (packet) {
		binding = GET_WBID_HEADER(packet->rxmngpacket->header);
		/* TODO: gestione richiesta */

		/* Create response */
		capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, binding);
		txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_CONFIGURATION_STATUS_RESPONSE, packet->rxmngpacket->ctrlmsg.seq, session->mtu);

		/* Add message element */
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_TIMERS, &session->dfa.timers);

		radioadmstate = (struct capwap_array*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RADIOADMSTATE);
		for (i = 0; i < radioadmstate->count; i++) {
			struct capwap_decrypterrorreportperiod_element report;
			struct capwap_radioadmstate_element* radioadm = *(struct capwap_radioadmstate_element**)capwap_array_get_item_pointer(radioadmstate, i);

			report.radioid = radioadm->radioid;
			report.interval = session->dfa.decrypterrorreport_interval;
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD, &report);
		}

		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_IDLETIMEOUT, &session->dfa.idletimeout);
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPFALLBACK, &session->dfa.wtpfallback);

		if (session->dfa.acipv4list.addresses->count > 0) {
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ACIPV4LIST, &session->dfa.acipv4list);
		}

		if (session->dfa.acipv6list.addresses->count > 0) {
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ACIPV6LIST, &session->dfa.acipv6list);
		}

		/* CAPWAP_CREATE_RADIOOPRSTATE_ELEMENT */				/* TODO */
		/* CAPWAP_CREATE_WTPSTATICIPADDRESS_ELEMENT */			/* TODO */
		/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */		/* TODO */

		/* Configure response complete, get fragment packets */
		ac_free_reference_last_response(session);
		capwap_packet_txmng_get_fragment_packets(txmngpacket, session->responsefragmentpacket, session->fragmentid);
		if (session->responsefragmentpacket->count > 1) {
			session->fragmentid++;
		}

		/* Free packets manager */
		capwap_packet_txmng_free(txmngpacket);

		/* Save remote sequence number */
		session->remoteseqnumber = packet->rxmngpacket->ctrlmsg.seq;
		capwap_get_packet_digest(packet->rxmngpacket, packet->connection, session->lastrecvpackethash);

		/* Send Configure response to WTP */
		if (!capwap_crypt_sendto_fragmentpacket(&session->ctrldtls, session->ctrlsocket.socket[session->ctrlsocket.type], session->responsefragmentpacket, &session->acctrladdress, &session->wtpctrladdress)) {
			/* Response is already created and saved. When receive a re-request, DFA autoresponse */
			capwap_logging_debug("Warning: error to send configuration status response packet");
		}

		/* Change state */
		ac_dfa_change_state(session, CAPWAP_DATA_CHECK_STATE);
		capwap_set_timeout(session->dfa.rfcChangeStatePendingTimer, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
	} else {
		/* Configure timeout */
		ac_dfa_change_state(session, CAPWAP_CONFIGURE_TO_DTLS_TEARDOWN_STATE);
		status = AC_DFA_NO_PACKET;
	}

	return status;
}

/* */
int ac_dfa_state_configure_to_dtlsteardown(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	return ac_session_teardown_connection(session);
}
