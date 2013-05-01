#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"

/* */
int ac_dfa_state_join(struct ac_session_t* session, struct capwap_packet* packet) {
	int i;
	int status = AC_DFA_ACCEPT_PACKET;
	struct capwap_resultcode_element resultcode = { CAPWAP_RESULTCODE_FAILURE };
	struct capwap_build_packet* responsepacket;

	ASSERT(session != NULL);
	
	if (packet) {
		struct capwap_build_packet* buildpacket;
	
		buildpacket = capwap_rx_packet_create((void*)packet->header, packet->packetsize, packet->socket.isctrlsocket);
		if (buildpacket) {
			int validpacket;
			unsigned long checkpacket;
			struct capwap_array* returnedmessagearray = NULL;
			capwap_unrecognized_element_array* unrecognizedarray;
			struct capwap_element_join_request joinrequest;
			unsigned short binding = GET_WBID_HEADER(&buildpacket->header);

			/* */
			unrecognizedarray = capwap_array_create(sizeof(struct unrecognized_info), 0);
			
			/* */
			checkpacket = capwap_build_packet_validate(buildpacket, unrecognizedarray);
			if (!checkpacket) {
				if (ac_valid_binding(binding)) {
					if (ntohl(buildpacket->ctrlmsg.type) == CAPWAP_JOIN_REQUEST) {
						resultcode.code = CAPWAP_RESULTCODE_SUCCESS;
					} else {
						resultcode.code = CAPWAP_RESULTCODE_MSG_UNEXPECTED_INVALID_CURRENT_STATE;
					}
				} else {
					resultcode.code = CAPWAP_RESULTCODE_JOIN_FAILURE_BINDING_NOT_SUPPORTED;
				}
			} else {
				if ((checkpacket & CAPWAP_MISSING_MANDATORY_MSG_ELEMENT) != 0) {
					resultcode.code = CAPWAP_RESULTCODE_FAILURE_MISSING_MANDATORY_MSG_ELEMENT;
				} else if ((checkpacket & CAPWAP_UNRECOGNIZED_MSG_ELEMENT) != 0) {
					struct capwap_list_item* itemelement;
					
					resultcode.code = CAPWAP_RESULTCODE_FAILURE_UNRECOGNIZED_MESSAGE_ELEMENT;
					returnedmessagearray = capwap_array_create(sizeof(struct capwap_returnedmessage_element), unrecognizedarray->count);

					for (i = 0; i < unrecognizedarray->count; i++) {
						struct unrecognized_info* reasoninfo = capwap_array_get_item_pointer(unrecognizedarray, i);
						
						/* Search element */
						itemelement = buildpacket->elementslist->first;
						while (itemelement != NULL) {
							struct capwap_message_element* elementitem = (struct capwap_message_element*)itemelement->item;
							
							if (ntohs(elementitem->type) == reasoninfo->element) {
								struct capwap_returnedmessage_element* returnedelement = capwap_array_get_item_pointer(returnedmessagearray, i);
								unsigned short length = sizeof(struct capwap_message_element) + ntohs(elementitem->length);

								returnedelement->reason = reasoninfo->reason;
								returnedelement->length = min(length, CAPWAP_RETURNED_MESSAGE_MAX_LENGTH);
								memcpy(&returnedelement->message[0], elementitem, returnedelement->length);
								
								break;
							}
							
							/* Next */
							itemelement = itemelement->next;
						}
					}
				}
			}

			/* */
			capwap_array_free(unrecognizedarray);

			/* */
			capwap_init_element_join_request(&joinrequest, binding);
			if (resultcode.code == CAPWAP_RESULTCODE_SUCCESS) {
				/* Parsing elements list */
				if (capwap_parsing_element_join_request(&joinrequest, buildpacket->elementslist->first)) {
					/* TODO: gestione richiesta */
					
					/* Get sessionid */
					memcpy(&session->sessionid, joinrequest.sessionid, sizeof(struct capwap_sessionid_element));

					/* Get binding */
					session->binding = binding;

					resultcode.code = CAPWAP_RESULTCODE_SUCCESS;
				}
			}
			
			/* Create response */
			responsepacket = capwap_tx_packet_create(CAPWAP_RADIOID_NONE, binding);
			responsepacket->isctrlmsg = 1;

			/* Prepare join response */
			capwap_build_packet_set_control_message_type(responsepacket, CAPWAP_JOIN_RESPONSE, buildpacket->ctrlmsg.seq);
			capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_RESULTCODE_ELEMENT(&resultcode));

			/* Check is valid packet after parsing request */
			validpacket = (((resultcode.code == CAPWAP_RESULTCODE_SUCCESS) || (resultcode.code == CAPWAP_RESULTCODE_SUCCESS_NAT_DETECTED)) ? 1 : 0);
			if (validpacket) {
				struct capwap_list* controllist;
				struct capwap_list_item* item;
			
				/* Update statistics */
				ac_update_statistics();
				
				capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_ACDESCRIPTOR_ELEMENT(&g_ac.descriptor));
				capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_ACNAME_ELEMENT(&g_ac.acname));

				if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
					for (i = 0; i < joinrequest.binding.ieee80211.wtpradioinformation->count; i++) {
						struct capwap_80211_wtpradioinformation_element* radio;
			
						radio = (struct capwap_80211_wtpradioinformation_element*)capwap_array_get_item_pointer(joinrequest.binding.ieee80211.wtpradioinformation, i);
						capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_80211_WTPRADIOINFORMATION_ELEMENT(radio));
					}
				} else {
					capwap_logging_debug("Unknown capwap binding");
				}
				
				capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_ECNSUPPORT_ELEMENT(&session->dfa.ecn));

				/* Get information from any local address */
				controllist = capwap_list_create();
				ac_get_control_information(controllist);
			
				for (item = controllist->first; item != NULL; item = item->next) {
					struct ac_session_control* sessioncontrol = (struct ac_session_control*)item->item;
				
					if (sessioncontrol->localaddress.ss_family == AF_INET) {
						struct capwap_controlipv4_element element;
						
						memcpy(&element.address, &((struct sockaddr_in*)&sessioncontrol->localaddress)->sin_addr, sizeof(struct in_addr));
						element.wtpcount = sessioncontrol->count;
						capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_CONTROLIPV4_ELEMENT(&element));
					} else if (sessioncontrol->localaddress.ss_family == AF_INET6) {
						struct capwap_controlipv6_element element;
						
						memcpy(&element.address, &((struct sockaddr_in6*)&sessioncontrol->localaddress)->sin6_addr, sizeof(struct in6_addr));
						element.wtpcount = sessioncontrol->count;
						capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_CONTROLIPV6_ELEMENT(&element));
					}
				}
			
				capwap_list_free(controllist);	

				if (session->acctrladdress.ss_family == AF_INET) {
					struct capwap_localipv4_element addr;
					
					memcpy(&addr.address, &((struct sockaddr_in*)&session->acctrladdress)->sin_addr, sizeof(struct in_addr));
					capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_LOCALIPV4_ELEMENT(&addr));
				} else if (session->acctrladdress.ss_family == AF_INET6) {
					struct capwap_localipv6_element addr;
					
					memcpy(&addr.address, &((struct sockaddr_in6*)&session->acctrladdress)->sin6_addr, sizeof(struct in6_addr));
					capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_LOCALIPV6_ELEMENT(&addr));
				}

				/* CAPWAP_CREATE_ACIPV4LIST_ELEMENT */				/* TODO */
				/* CAPWAP_CREATE_ACIPV6LIST_ELEMENT */				/* TODO */
				capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_TRANSPORT_ELEMENT(&session->dfa.transport));
				/* CAPWAP_CREATE_IMAGEIDENTIFIER_ELEMENT */			/* TODO */
				/* CAPWAP_CREATE_MAXIMUMMESSAGELENGTH_ELEMENT */	/* TODO */
				/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */	/* TODO */
			} else if (resultcode.code == CAPWAP_RESULTCODE_FAILURE_UNRECOGNIZED_MESSAGE_ELEMENT) {
				ASSERT(returnedmessagearray != NULL);

				for (i = 0; i < returnedmessagearray->count; i++) {
					capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_RETURNEDMESSAGE_ELEMENT(capwap_array_get_item_pointer(returnedmessagearray, i)));
				}
				
				capwap_array_free(returnedmessagearray);
			}

			/* Validate packet */
			if (!validpacket || !capwap_build_packet_validate(responsepacket, NULL)) {
				int result;
				
				/* Free old reference for this request */
				ac_free_reference_last_response(session);

				/* Send join response to WTP */
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
							capwap_logging_debug("Warning: error to send join response packet");
							break;
						}
					}
				}
			} else {
				capwap_logging_debug("Warning: build invalid join response packet");
			}

			/* Free memory */
			capwap_build_packet_free(responsepacket);
			capwap_free_element_join_request(&joinrequest, binding);
			capwap_build_packet_free(buildpacket);
					
			/* Change state */
			if (validpacket) {
				ac_dfa_change_state(session, CAPWAP_POSTJOIN_STATE);
			} else {
				ac_dfa_change_state(session, CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE);
				status = AC_DFA_NO_PACKET;
			}
		}
	} else {
		/* Join timeout */
		ac_dfa_change_state(session, CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE);
		status = AC_DFA_NO_PACKET;
	}

	return status;
}

/* */
int ac_dfa_state_postjoin(struct ac_session_t* session, struct capwap_packet* packet) {
	int status = AC_DFA_ACCEPT_PACKET;
	
	ASSERT(session != NULL);
	
	if (packet) {
		unsigned short lengthpayload;

		lengthpayload = packet->packetsize - GET_HLEN_HEADER(packet->header) * 4;
		if (lengthpayload >= sizeof(struct capwap_control_message)) {
			struct capwap_control_message* ctrlmsg = (struct capwap_control_message*)packet->payload;
			unsigned long type = ntohl(ctrlmsg->type);

			if (type == CAPWAP_CONFIGURATION_STATUS_REQUEST) {
				ac_dfa_change_state(session, CAPWAP_CONFIGURE_STATE);
				status = ac_dfa_state_configure(session, packet);
			} else if (type == CAPWAP_IMAGE_DATA_REQUEST) {
				ac_dfa_change_state(session, CAPWAP_IMAGE_DATA_STATE);
				status = ac_dfa_state_imagedata(session, packet);
			}
		}
	} else {
		/* Join timeout */
		ac_dfa_change_state(session, CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE);
		status = AC_DFA_NO_PACKET;
	}

	return status;
}

/* */
int ac_dfa_state_join_to_dtlsteardown(struct ac_session_t* session, struct capwap_packet* packet) {
	return ac_session_teardown_connection(session);
}
