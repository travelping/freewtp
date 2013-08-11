#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_array.h"
#include "ac_session.h"
#include <json/json.h>
#include <arpa/inet.h>

/* */
static struct ac_soap_response* ac_dfa_state_configure_parsing_request(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	int i;
	const char* jsonmessage;
	char* base64confstatus;
	struct json_object* jarray;
	struct json_object* jsonparam;
	struct json_object* jhash;
	struct capwap_array* elemarray;
	struct capwap_statisticstimer_element* statisticstimer;
	struct capwap_wtprebootstat_element* wtprebootstat;
	struct capwap_wtpstaticipaddress_element* wtpstaticipaddress;
	struct ac_soap_response* response;

	/* Create SOAP request with JSON param
		{
			RadioAdministrativeState: [
				{
					RadioID: [int],
					AdminState: [int]
				}
			],
			StatisticsTimer: {
				StatisticsTimer: [int]
			},
			WTPRebootStatistics: {
				RebootCount: [int],
				ACInitiatedCount: [int],
				LinkFailureCount: [int],
				SWFailureCount: [int],
				HWFailureCount: [int],
				OtherFailureCount: [int],
				UnknownFailureCount: [int],
				LastFailureType: [int]
			},
			ACNamePriority: [
				{
					Priority: [int],
					ACName: [string]
				}
			],
			WTPStaticIPAddressInformation: {
				IPAddress: [string],
				Netmask: [string],
				Gateway: [string],
				Static: [int]
			}
		}
	*/

	/* */
	jsonparam = json_object_new_object();

	/* RadioAdministrativeState */
	jarray = json_object_new_array();
	elemarray = (struct capwap_array*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RADIOADMSTATE);
	for (i = 0; i < elemarray->count; i++) {
		json_object* jradioadm;
		struct capwap_radioadmstate_element* radioadm = *(struct capwap_radioadmstate_element**)capwap_array_get_item_pointer(elemarray, i);

		/* */
		jradioadm = json_object_new_object();
		json_object_object_add(jradioadm, "RadioID", json_object_new_int((int)radioadm->radioid));
		json_object_object_add(jradioadm, "AdminState", json_object_new_int((int)radioadm->state));
		json_object_array_add(jarray, jradioadm);
	}

	json_object_object_add(jsonparam, "RadioAdministrativeState", jarray);

	/* StatisticsTimer */
	statisticstimer = (struct capwap_statisticstimer_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_STATISTICSTIMER);

	jhash = json_object_new_object();
	json_object_object_add(jhash, "StatisticsTimer", json_object_new_int((int)statisticstimer->timer));
	json_object_object_add(jsonparam, "StatisticsTimer", jhash);

	/* WTPRebootStatistics */
	wtprebootstat = (struct capwap_wtprebootstat_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_WTPREBOOTSTAT);

	jhash = json_object_new_object();
	json_object_object_add(jhash, "RebootCount", json_object_new_int((int)wtprebootstat->rebootcount));
	json_object_object_add(jhash, "ACInitiatedCount", json_object_new_int((int)wtprebootstat->acinitiatedcount));
	json_object_object_add(jhash, "LinkFailureCount", json_object_new_int((int)wtprebootstat->linkfailurecount));
	json_object_object_add(jhash, "SWFailureCount", json_object_new_int((int)wtprebootstat->swfailurecount));
	json_object_object_add(jhash, "HWFailureCount", json_object_new_int((int)wtprebootstat->hwfailurecount));
	json_object_object_add(jhash, "OtherFailureCount", json_object_new_int((int)wtprebootstat->otherfailurecount));
	json_object_object_add(jhash, "UnknownFailureCount", json_object_new_int((int)wtprebootstat->unknownfailurecount));
	json_object_object_add(jhash, "LastFailureType", json_object_new_int((int)wtprebootstat->lastfailuretype));
	json_object_object_add(jsonparam, "WTPRebootStatistics", jhash);

	/* ACNamePriority */
	elemarray = (struct capwap_array*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_ACNAMEPRIORITY);
	if (elemarray && elemarray->count) {
		jarray = json_object_new_array();
		for (i = 0; i < elemarray->count; i++) {
			json_object* jacname;
			struct capwap_acnamepriority_element* acname = *(struct capwap_acnamepriority_element**)capwap_array_get_item_pointer(elemarray, i);

			/* */
			jacname = json_object_new_object();
			json_object_object_add(jacname, "Priority", json_object_new_int((int)acname->priority));
			json_object_object_add(jacname, "ACName", json_object_new_string((char*)acname->name));
			json_object_array_add(jarray, jacname);
		}

		json_object_object_add(jsonparam, "ACNamePriority", jarray);
	}

	/* WTPStaticIPAddressInformation */
	wtpstaticipaddress = (struct capwap_wtpstaticipaddress_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_WTPSTATICIPADDRESS);
	if (wtpstaticipaddress) {
		char ipbuffer[INET_ADDRSTRLEN];

		/* */
		jhash = json_object_new_object();
		json_object_object_add(jhash, "IPAddress", json_object_new_string(inet_ntop(AF_INET, (void*)&wtpstaticipaddress->address, ipbuffer, INET_ADDRSTRLEN)));
		json_object_object_add(jhash, "Netmask", json_object_new_string(inet_ntop(AF_INET, (void*)&wtpstaticipaddress->netmask, ipbuffer, INET_ADDRSTRLEN)));
		json_object_object_add(jhash, "Gateway", json_object_new_string(inet_ntop(AF_INET, (void*)&wtpstaticipaddress->gateway, ipbuffer, INET_ADDRSTRLEN)));
		json_object_object_add(jhash, "Static", json_object_new_int((int)wtpstaticipaddress->staticip));
		json_object_object_add(jsonparam, "WTPStaticIPAddressInformation", jhash);
	}

	/* Get JSON param and convert base64 */
	jsonmessage = json_object_to_json_string(jsonparam);
	base64confstatus = capwap_alloc(AC_BASE64_ENCODE_LENGTH(strlen(jsonmessage)));
	if (!base64confstatus) {
		capwap_outofmemory();
	}

	ac_base64_string_encode(jsonmessage, base64confstatus);

	/* Send message */
	response = ac_soap_configureStatus(session, session->wtpid, base64confstatus);

	/* Free JSON */
	json_object_put(jsonparam);
	capwap_free(base64confstatus);

	return response;
}

/* */
int ac_dfa_state_configure(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	unsigned long i;
	struct capwap_array* radioadmstate;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	int status = AC_DFA_ACCEPT_PACKET;

	ASSERT(session != NULL);
	
	if (packet) {
		/* Parsing request */
		struct ac_soap_response* response = ac_dfa_state_configure_parsing_request(session, packet);
		if (response) {
			/* Create response */
			capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, GET_WBID_HEADER(packet->rxmngpacket->header));
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

			/* */
			ac_soapclient_free_response(response);

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
			ac_dfa_change_state(session, CAPWAP_CONFIGURE_TO_DTLS_TEARDOWN_STATE);
			status = AC_DFA_NO_PACKET;
		}
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
