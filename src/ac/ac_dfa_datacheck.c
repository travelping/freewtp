#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"
#include "ac_json.h"
#include <json/json.h>

/* */
static struct ac_soap_response* ac_dfa_state_datacheck_parsing_request(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	int i;
	const char* jsonmessage;
	char* base64confstatus;
	struct capwap_array* elemarray;
	struct json_object* jsonarray;
	struct json_object* jsonparam;
	struct json_object* jsonhash;
	struct ac_soap_response* response;
	struct capwap_resultcode_element* resultcode;
	unsigned short binding = GET_WBID_HEADER(packet->rxmngpacket->header);

	/* Create SOAP request with JSON param
		{
			RadioOperationalState: [
				{
					RadioID: [int],
					State: [int],
					Cause: [int]
				}
			],
			ResultCode: {
				Code: [int]
			},
			ReturnedMessageElement: [
				{
				}
			],
			<IEEE 802.11 BINDING>
			WTPRadio: [
				{
					RadioID: [int],
					IEEE80211WTPRadioFailAlarm: {
						Type: [int],
						Status: [int]
					}
				}
			}
		}
	*/

	/* */
	jsonparam = json_object_new_object();

	/* RadioOperationalState */
	jsonarray = json_object_new_array();
	elemarray = (struct capwap_array*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RADIOOPRSTATE);
	for (i = 0; i < elemarray->count; i++) {
		json_object* jsonradioops;
		struct capwap_radiooprstate_element* radioops = *(struct capwap_radiooprstate_element**)capwap_array_get_item_pointer(elemarray, i);

		/* */
		jsonradioops = json_object_new_object();
		json_object_object_add(jsonradioops, "RadioID", json_object_new_int((int)radioops->radioid));
		json_object_object_add(jsonradioops, "State", json_object_new_int((int)radioops->state));
		json_object_object_add(jsonradioops, "Cause", json_object_new_int((int)radioops->cause));
		json_object_array_add(jsonarray, jsonradioops);
	}

	json_object_object_add(jsonparam, "RadioOperationalState", jsonarray);

	/* ResultCode */
	resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);

	jsonhash = json_object_new_object();
	json_object_object_add(jsonhash, "Code", json_object_new_int((int)resultcode->code));
	json_object_object_add(jsonparam, "ResultCode", jsonhash);

	/* ReturnedMessageElement */
	jsonarray = json_object_new_array();
	/* TODO */
	json_object_object_add(jsonparam, "ReturnedMessageElement", jsonarray);

	/* Binding message */
	if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		struct ac_json_ieee80211_wtpradio wtpradio;
		struct capwap_list_item* search = packet->messages->first;

		/* Reording message by radioid and management */
		ac_json_ieee80211_init(&wtpradio);

		while (search) {
			struct capwap_message_element_itemlist* messageelement = (struct capwap_message_element_itemlist*)search->item;

			/* Parsing only IEEE 802.11 message element */
			if (IS_80211_MESSAGE_ELEMENTS(messageelement->type)) {
				if (!ac_json_ieee80211_parsingmessageelement(&wtpradio, messageelement)) {
					json_object_put(jsonparam);
					return NULL;
				}
			}

			/* Next */
			search = search->next;
		}

		/* Generate JSON tree */
		jsonarray = ac_json_ieee80211_getjson(&wtpradio);
		json_object_object_add(jsonparam, IEEE80211_BINDING_JSON_ROOT, jsonarray);

		/* Free resource */
		ac_json_ieee80211_free(&wtpradio);
	}

	/* Get JSON param and convert base64 */
	jsonmessage = json_object_to_json_string(jsonparam);
	base64confstatus = capwap_alloc(AC_BASE64_ENCODE_LENGTH(strlen(jsonmessage)));
	ac_base64_string_encode(jsonmessage, base64confstatus);

	/* Send message */
	response = ac_soap_changestatewtpsession(session, session->wtpid, base64confstatus);

	/* Free JSON */
	json_object_put(jsonparam);
	capwap_free(base64confstatus);

	return response;
}

/* */
static uint32_t ac_dfa_state_datacheck_create_response(struct ac_session_t* session, struct capwap_parsed_packet* packet, struct ac_soap_response* response, struct capwap_packet_txmng* txmngpacket) {
	int length;
	char* json;
	xmlChar* xmlResult;
	struct json_object* jsonroot;

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

	/* CAPWAP_ELEMENT_VENDORPAYLOAD */			/* TODO */

	if (jsonroot) {
		json_object_put(jsonroot);
	}

	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
int ac_dfa_state_datacheck(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);
	
	if (packet) {
		struct ac_soap_response* response;
		uint32_t result = CAPWAP_RESULTCODE_FAILURE;

		/* Create response */
		capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, GET_WBID_HEADER(packet->rxmngpacket->header));
		txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_CHANGE_STATE_EVENT_RESPONSE, packet->rxmngpacket->ctrlmsg.seq, session->mtu);

		/* Parsing request and add message element for respone message */
		response = ac_dfa_state_datacheck_parsing_request(session, packet);
		if (response) {
			result = ac_dfa_state_datacheck_create_response(session, packet, response, txmngpacket);
			ac_soapclient_free_response(response);
		}

		/* With error add result code message element */
		if (!CAPWAP_RESULTCODE_OK(result)) {
			struct capwap_resultcode_element resultcode = { .code = result };
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RESULTCODE, &resultcode);

			/* */
			if (result == CAPWAP_RESULTCODE_FAILURE) {
				/* TODO: Add AC List Message Elements */
			}
		}

		/* Change event response complete, get fragment packets */
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

		/* Send Change event response to WTP */
		if (!capwap_crypt_sendto_fragmentpacket(&session->ctrldtls, session->ctrlsocket.socket[session->ctrlsocket.type], session->responsefragmentpacket, &session->acctrladdress, &session->wtpctrladdress)) {
			/* Response is already created and saved. When receive a re-request, DFA autoresponse */
			capwap_logging_debug("Warning: error to send change event response packet");
		}

		/* Change state */
		if (CAPWAP_RESULTCODE_OK(result)) {
			ac_dfa_change_state(session, CAPWAP_DATA_CHECK_TO_RUN_STATE);
			capwap_set_timeout(session->dfa.rfcDataCheckTimer, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		} else {
			ac_dfa_change_state(session, CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
			status = AC_DFA_NO_PACKET;
		}
	} else {
		/* Configure timeout */
		ac_dfa_change_state(session, CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
		status = AC_DFA_NO_PACKET;
	}

	return status;
}

/* */
int ac_dfa_state_datacheck_to_run(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	struct capwap_list* txfragpacket;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct ac_soap_response* response;
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);
	
	if (packet) {
		/* Wait Data Channel Keep-Alive packet */
		if (!packet->rxmngpacket->isctrlpacket && IS_FLAG_K_HEADER(packet->rxmngpacket->header)) {
			if (!memcmp(capwap_get_message_element_data(packet, CAPWAP_ELEMENT_SESSIONID), &session->sessionid, sizeof(struct capwap_sessionid_element))) {
				int result = 0;

				/* Build packet */
				capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, GET_WBID_HEADER(packet->rxmngpacket->header));
				capwap_header_set_keepalive_flag(&capwapheader, 1);
				txmngpacket = capwap_packet_txmng_create_data_message(&capwapheader, session->mtu);

				/* Add message element */
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_SESSIONID, &session->sessionid);

				/* Data keepalive complete, get fragment packets into local list */
				txfragpacket = capwap_list_create();
				capwap_packet_txmng_get_fragment_packets(txmngpacket, txfragpacket, 0);
				if (txfragpacket->count == 1) {
					/* Send Data keepalive to WTP */
					if (capwap_crypt_sendto_fragmentpacket(&session->datadtls, session->datasocket.socket[session->datasocket.type], txfragpacket, &session->acdataaddress, &session->wtpdataaddress)) {
						result = 1;
					} else {
						capwap_logging_debug("Warning: error to send data channel keepalive packet");
					}
				} else {
					capwap_logging_debug("Warning: error to send data channel keepalive packet, fragment packet");
				}

				/* Free packets manager */
				capwap_list_free(txfragpacket);
				capwap_packet_txmng_free(txmngpacket);

				/* Capwap handshake complete, notify event to backend */
				if (result) {
					result = 0;
					response = ac_soap_runningwtpsession(session, session->wtpid);
					if (response) {
						if (response->responsecode == HTTP_RESULT_OK) {
							result = 1;
						}

						ac_soapclient_free_response(response);
					}
				}

				/* */
				if (result) {
					ac_dfa_change_state(session, CAPWAP_RUN_STATE);
					capwap_set_timeout(AC_MAX_ECHO_INTERVAL, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
				} else {
					ac_dfa_change_state(session, CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
					status = AC_DFA_NO_PACKET;
				}
			}
		}
	} else {
		/* Configure timeout */
		ac_dfa_change_state(session, CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
		status = AC_DFA_NO_PACKET;
	}

	return status;
}

/* */
int ac_dfa_state_datacheck_to_dtlsteardown(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	return ac_session_teardown_connection(session);
}
