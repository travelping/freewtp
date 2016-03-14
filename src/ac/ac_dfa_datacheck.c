#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"
#include "ac_json.h"
#include <json-c/json.h>

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
			if (IS_80211_MESSAGE_ELEMENTS(messageelement->id)) {
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
	struct json_object* jsonroot;

	/* Receive SOAP response with JSON result
		{
		}
	*/

	/* Add message elements response, every local value can be overwrite from backend server */
	jsonroot = ac_soapclient_parse_json_response(response);
	if (!jsonroot) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* CAPWAP_ELEMENT_VENDORPAYLOAD */			/* TODO */

	if (jsonroot) {
		json_object_put(jsonroot);
	}

	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
void ac_dfa_state_datacheck(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	struct ac_soap_response* response;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	uint32_t result = CAPWAP_RESULTCODE_FAILURE;

	ASSERT(session != NULL);
	ASSERT(packet != NULL);

	/* Create response */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, GET_WBID_HEADER(packet->rxmngpacket->header));
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_CHANGE_STATE_EVENT_RESPONSE, packet->rxmngpacket->ctrlmsg.seq, session->mtu);

	/* Parsing request and add message element for respone message */
	response = ac_dfa_state_datacheck_parsing_request(session, packet);
	if (response) {
		result = ac_dfa_state_datacheck_create_response(session, packet, response, txmngpacket);
		ac_soapclient_free_response(response);

		/* Create data session */
		if (CAPWAP_RESULTCODE_OK(result)) {
			if (ac_kmod_new_datasession(&session->sessionid, (uint8_t)session->binding, session->mtu)) {
				result = CAPWAP_RESULTCODE_FAILURE;
			}
		}
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
	session->remotetype = packet->rxmngpacket->ctrlmsg.type;
	session->remoteseqnumber = packet->rxmngpacket->ctrlmsg.seq;

	/* Send Change event response to WTP */
	if (!capwap_crypt_sendto_fragmentpacket(&session->dtls, session->responsefragmentpacket)) {
		/* Response is already created and saved. When receive a re-request, DFA autoresponse */
		capwap_logging_debug("Warning: error to send change event response packet");
	}

	/* Change state */
	if (CAPWAP_RESULTCODE_OK(result)) {
		ac_dfa_change_state(session, CAPWAP_DATA_CHECK_TO_RUN_STATE);
		capwap_timeout_set(session->timeout, session->idtimercontrol, AC_DATA_CHECK_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
		capwap_timeout_set(session->timeout, session->idtimerkeepalivedead, AC_MAX_DATA_KEEPALIVE_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
	} else {
		ac_session_teardown(session);
	}
}
