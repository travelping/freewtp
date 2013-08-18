#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"
#include "ac_backend.h"
#include <json/json.h>

/* */
static int ac_dfa_state_join_check_authorizejoin(struct ac_session_t* session, struct ac_soap_response* response) {
	if (response->responsecode != HTTP_RESULT_OK) {
		/* TODO: check return failed code */
		return CAPWAP_RESULTCODE_JOIN_FAILURE_UNKNOWN_SOURCE;
	}

	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
static struct ac_soap_response* ac_dfa_state_join_parsing_request(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	const char* jsonmessage;
	char* base64confstatus;
	struct json_object* jsonparam;
	struct ac_soap_response* response;

	/* Create SOAP request with JSON param
		{
		}
	*/

	/* */
	jsonparam = json_object_new_object();

	/* Get JSON param and convert base64 */
	jsonmessage = json_object_to_json_string(jsonparam);
	base64confstatus = capwap_alloc(AC_BASE64_ENCODE_LENGTH(strlen(jsonmessage)));
	ac_base64_string_encode(jsonmessage, base64confstatus);

	/* Send message */
	response = ac_soap_joinevent(session, session->wtpid, base64confstatus);

	/* Free JSON */
	json_object_put(jsonparam);
	capwap_free(base64confstatus);

	return response;
}

/* */
static uint32_t ac_dfa_state_join_create_response(struct ac_session_t* session, struct capwap_parsed_packet* packet, struct ac_soap_response* response, struct capwap_packet_txmng* txmngpacket) {
	int i;
	int length;
	char* json;
	xmlChar* xmlResult;
	struct json_object* jsonroot;
	struct capwap_list* controllist;
	struct capwap_list_item* item;
	unsigned short binding = GET_WBID_HEADER(packet->rxmngpacket->header);

	if ((response->responsecode != HTTP_RESULT_OK) || !response->xmlResponseReturn) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Receive SOAP response with JSON result
		{
		}
	*/

	/* Decode base64 result */
	xmlResult = xmlNodeGetContent(response->xmlResponseReturn);
	if (!xmlResult) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	length = xmlStrlen(xmlResult);
	if (!length) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	json = (char*)capwap_alloc(AC_BASE64_DECODE_LENGTH(length));
	ac_base64_string_decode((const char*)xmlResult, json);

	xmlFree(xmlResult);

	/* Parsing JSON result */
	jsonroot = json_tokener_parse(json);
	capwap_free(json);

	/* Add message elements response, every local value can be overwrite from backend server */

	/* Update statistics */
	ac_update_statistics();

	/* */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ACDESCRIPTION, &g_ac.descriptor);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ACNAME, &g_ac.acname);

	if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		struct capwap_array* wtpradioinformation = (struct capwap_array*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION);

		for (i = 0; i < wtpradioinformation->count; i++) {
			struct capwap_80211_wtpradioinformation_element* radio;

			radio = *(struct capwap_80211_wtpradioinformation_element**)capwap_array_get_item_pointer(wtpradioinformation, i);
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION, radio);
		}
	}

	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ECNSUPPORT, &session->dfa.ecn);

	/* Get information from any local address */
	controllist = capwap_list_create();
	ac_get_control_information(controllist);

	for (item = controllist->first; item != NULL; item = item->next) {
		struct ac_session_control* sessioncontrol = (struct ac_session_control*)item->item;

		if (sessioncontrol->localaddress.ss_family == AF_INET) {
			struct capwap_controlipv4_element element;

			memcpy(&element.address, &((struct sockaddr_in*)&sessioncontrol->localaddress)->sin_addr, sizeof(struct in_addr));
			element.wtpcount = sessioncontrol->count;
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_CONTROLIPV4, &element);
		} else if (sessioncontrol->localaddress.ss_family == AF_INET6) {
			struct capwap_controlipv6_element element;

			memcpy(&element.address, &((struct sockaddr_in6*)&sessioncontrol->localaddress)->sin6_addr, sizeof(struct in6_addr));
			element.wtpcount = sessioncontrol->count;
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_CONTROLIPV6, &element);
		}
	}

	capwap_list_free(controllist);

	if (session->acctrladdress.ss_family == AF_INET) {
		struct capwap_localipv4_element addr;

		memcpy(&addr.address, &((struct sockaddr_in*)&session->acctrladdress)->sin_addr, sizeof(struct in_addr));
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_LOCALIPV4, &addr);
	} else if (session->acctrladdress.ss_family == AF_INET6) {
		struct capwap_localipv6_element addr;

		memcpy(&addr.address, &((struct sockaddr_in6*)&session->acctrladdress)->sin6_addr, sizeof(struct in6_addr));
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_LOCALIPV6, &addr);
	}

	/* CAPWAP_CREATE_ACIPV4LIST_ELEMENT */				/* TODO */
	/* CAPWAP_CREATE_ACIPV6LIST_ELEMENT */				/* TODO */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_TRANSPORT, &session->dfa.transport);
	/* CAPWAP_CREATE_IMAGEIDENTIFIER_ELEMENT */			/* TODO */
	/* CAPWAP_CREATE_MAXIMUMMESSAGELENGTH_ELEMENT */	/* TODO */
	/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */	/* TODO */

	if (jsonroot) {
		json_object_put(jsonroot);
	}

	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
int ac_dfa_state_join(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	struct ac_soap_response* response;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_sessionid_element* sessionid;
	struct capwap_wtpboarddata_element* wtpboarddata;
	int status = AC_DFA_ACCEPT_PACKET;
	struct capwap_resultcode_element resultcode = { .code = CAPWAP_RESULTCODE_FAILURE };

	ASSERT(session != NULL);
	
	if (packet) {
		unsigned short binding;

		/* Check binding */
		binding = GET_WBID_HEADER(packet->rxmngpacket->header);
		if (ac_valid_binding(binding)) {
			if (packet->rxmngpacket->ctrlmsg.type == CAPWAP_JOIN_REQUEST) {
				/* Get sessionid and verify unique id */
				sessionid = (struct capwap_sessionid_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_SESSIONID);
				if (!ac_has_sessionid(sessionid)) {
					char* wtpid;

					/* Checking macaddress for detect if WTP already connected */
					wtpboarddata = (struct capwap_wtpboarddata_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_WTPBOARDDATA);

					/* Get printable WTPID */
					wtpid = ac_get_printable_wtpid(wtpboarddata);
					if (wtpid && !ac_has_wtpid(wtpid)) {
						/* Request authorization of Backend for complete join */
						response = ac_soap_authorizejoin(session, wtpid);
						if (response) {
							resultcode.code = ac_dfa_state_join_check_authorizejoin(session, response);
							ac_soapclient_free_response(response);
						} else {
							resultcode.code = CAPWAP_RESULTCODE_JOIN_FAILURE_UNKNOWN_SOURCE;
						}
					} else {
						resultcode.code = CAPWAP_RESULTCODE_JOIN_FAILURE_UNKNOWN_SOURCE;
					}

					/* */
					if (CAPWAP_RESULTCODE_OK(resultcode.code)) {
						session->wtpid = wtpid;
						memcpy(&session->sessionid, sessionid, sizeof(struct capwap_sessionid_element));
						session->binding = binding;
					} else {
						capwap_free(wtpid);
					}
				} else {
					resultcode.code = CAPWAP_RESULTCODE_JOIN_FAILURE_ID_ALREADY_IN_USE;
				}
			} else {
				resultcode.code = CAPWAP_RESULTCODE_MSG_UNEXPECTED_INVALID_CURRENT_STATE;
			}
		} else {
			resultcode.code = CAPWAP_RESULTCODE_JOIN_FAILURE_BINDING_NOT_SUPPORTED;
		}

		/* Create response */
		capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, binding);
		txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_JOIN_RESPONSE, packet->rxmngpacket->ctrlmsg.seq, session->mtu);

		/* */
		if (CAPWAP_RESULTCODE_OK(resultcode.code)) {
			response = ac_dfa_state_join_parsing_request(session, packet);
			if (response) {
				resultcode.code = ac_dfa_state_join_create_response(session, packet, response, txmngpacket);
				ac_soapclient_free_response(response);
			}
		}

		/* Add always result code message element */
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RESULTCODE, &resultcode);

		/* Join response complete, get fragment packets */
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

		/* Send Join response to WTP */
		if (capwap_crypt_sendto_fragmentpacket(&session->ctrldtls, session->ctrlsocket.socket[session->ctrlsocket.type], session->responsefragmentpacket, &session->acctrladdress, &session->wtpctrladdress)) {
			if (CAPWAP_RESULTCODE_OK(resultcode.code)) {
				ac_dfa_change_state(session, CAPWAP_POSTJOIN_STATE);
			} else {
				ac_dfa_change_state(session, CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE);
				status = AC_DFA_NO_PACKET;
			}
		} else {
			/* Error to send packets */
			capwap_logging_debug("Warning: error to send join response packet");
			ac_dfa_change_state(session, CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE);
			status = AC_DFA_NO_PACKET;
		}
	} else {
		/* Join timeout */
		ac_dfa_change_state(session, CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE);
		status = AC_DFA_NO_PACKET;
	}

	return status;
}

/* */
int ac_dfa_state_postjoin(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);

	if (packet) {
		if (packet->rxmngpacket->ctrlmsg.type == CAPWAP_CONFIGURATION_STATUS_REQUEST) {
			ac_dfa_change_state(session, CAPWAP_CONFIGURE_STATE);
			status = ac_dfa_state_configure(session, packet);
		} else if (packet->rxmngpacket->ctrlmsg.type == CAPWAP_IMAGE_DATA_REQUEST) {
			ac_dfa_change_state(session, CAPWAP_IMAGE_DATA_STATE);
			status = ac_dfa_state_imagedata(session, packet);
		} else {
			ac_dfa_change_state(session, CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE);
			status = AC_DFA_NO_PACKET;
		}
	} else {
		/* Join timeout */
		ac_dfa_change_state(session, CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE);
		status = AC_DFA_NO_PACKET;
	}

	return status;
}

/* */
int ac_dfa_state_join_to_dtlsteardown(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	return ac_session_teardown_connection(session);
}
