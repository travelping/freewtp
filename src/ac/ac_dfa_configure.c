#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
int ac_dfa_state_configure(struct ac_session_t* session, struct capwap_packet* packet) {
	unsigned long i;
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);
	
	if (packet) {
		struct capwap_build_packet* buildpacket;
	
		buildpacket = capwap_rx_packet_create((void*)packet->header, packet->packetsize, packet->socket.isctrlsocket);
		if (buildpacket) {
			if (!capwap_build_packet_validate(buildpacket, NULL)) {
				unsigned short binding;

				/* */
				binding = GET_WBID_HEADER(&buildpacket->header);
				if (ac_valid_binding(binding) && (ntohl(buildpacket->ctrlmsg.type) == CAPWAP_CONFIGURATION_STATUS_REQUEST) && IS_SEQUENCE_SMALLER(session->remoteseqnumber, buildpacket->ctrlmsg.seq)) {
					struct capwap_element_configurationstatus_request configurationstatusrequest;
					
					/* Configuration Status request info*/
					capwap_init_element_configurationstatus_request(&configurationstatusrequest, binding);
					
					/* Parsing elements list */
					if (capwap_parsing_element_configurationstatus_request(&configurationstatusrequest, buildpacket->elementslist->first)) {
						struct capwap_build_packet* responsepacket;

						/* TODO: gestione richiesta */

						/* Create response */
						responsepacket = capwap_tx_packet_create(CAPWAP_RADIOID_NONE, binding);
						responsepacket->isctrlmsg = 1;

						/* Prepare configuration status response */
						capwap_build_packet_set_control_message_type(responsepacket, CAPWAP_CONFIGURATION_STATUS_RESPONSE, buildpacket->ctrlmsg.seq);
						capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_TIMERS_ELEMENT(&session->dfa.timers));
						
						for (i = 0; i < configurationstatusrequest.radioadmstatus->count; i++) {
							struct capwap_decrypterrorreportperiod_element report;
							struct capwap_radioadmstate_element* radioadm = (struct capwap_radioadmstate_element*)capwap_array_get_item_pointer(configurationstatusrequest.radioadmstatus, i);

							report.radioid = radioadm->radioid;
							report.interval = session->dfa.decrypterrorreport_interval;
							capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_DECRYPTERRORREPORTPERIOD_ELEMENT(&report));
						}
						
						capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_IDLETIMEOUT_ELEMENT(&session->dfa.idletimeout));
						capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_WTPFALLBACK_ELEMENT(&session->dfa.wtpfallback));

						if (session->dfa.acipv4list->count > 0) {
							capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_ACIPV4LIST_ELEMENT(session->dfa.acipv4list));
						}

						if (session->dfa.acipv6list->count > 0) {
							capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_ACIPV6LIST_ELEMENT(session->dfa.acipv6list));
						}
						
						/* CAPWAP_CREATE_RADIOOPRSTATE_ELEMENT */				/* TODO */
						/* CAPWAP_CREATE_WTPSTATICIPADDRESS_ELEMENT */			/* TODO */
						/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */		/* TODO */

						if (!capwap_build_packet_validate(responsepacket, NULL)) {
							int result;
							
							/* Free old reference for this request */
							ac_free_reference_last_response(session);
			
							/* Send configuration status response to WTP */
							result = capwap_fragment_build_packet(responsepacket, session->responsefragmentpacket, session->mtu, session->fragmentid);
							if (result >= 0) {
								if (result == 1) {
									session->fragmentid++;
								}
			
								/* Save remote sequence number */
								session->remoteseqnumber = buildpacket->ctrlmsg.seq;
								capwap_get_packet_digest((void*)packet->header, packet->packetsize, session->lastrecvpackethash);
			
								/* Send */
								for (i = 0; i < session->responsefragmentpacket->count; i++) {
									struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(session->responsefragmentpacket, i);
									ASSERT(txpacket != NULL);
									
									if (!capwap_crypt_sendto(&session->ctrldtls, session->ctrlsocket.socket[session->ctrlsocket.type], txpacket->header, txpacket->packetsize, &session->acctrladdress, &session->wtpctrladdress)) {
										/* Response is already created and saved. When receive a re-request, DFA autoresponse */
										capwap_logging_debug("Warning: error to send configuration status response packet");
										break;
									}
								}

								/* Change status */
								ac_dfa_change_state(session, CAPWAP_DATA_CHECK_STATE);
								capwap_set_timeout(session->dfa.rfcChangeStatePendingTimer, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
							}
						} else {
							capwap_logging_debug("Warning: build invalid configuration status response packet");
						}
						
						/* Free memory */
						capwap_build_packet_free(responsepacket);
					} 
					
					/* Free */
					capwap_free_element_configurationstatus_request(&configurationstatusrequest, binding);
				}
			}

			/* Free */
			capwap_build_packet_free(buildpacket);
		}
	} else {
		/* Configure timeout */
		ac_dfa_change_state(session, CAPWAP_CONFIGURE_TO_DTLS_TEARDOWN_STATE);
		status = AC_DFA_NO_PACKET;
	}

	return status;
}

/* */
int ac_dfa_state_configure_to_dtlsteardown(struct ac_session_t* session, struct capwap_packet* packet) {
	return ac_session_teardown_connection(session);
}
