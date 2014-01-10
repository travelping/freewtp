#include "ac.h"
#include "capwap_dfa.h"
#include "ac_backend.h"
#include "ac_soap.h"
#include "ac_session.h"
#include <json/json.h>

/* */
#define AC_BACKEND_WAIT_TIMEOUT							10000
#define SOAP_PROTOCOL_RESPONSE_WAIT_EVENT_TIMEOUT		70000

/* */
struct ac_backend_t {
	pthread_t threadid;
	int endthread;

	capwap_event_t wait;
	capwap_lock_t lock;
	capwap_lock_t backendlock;

	/* Backend Soap */
	int activebackend;
	int backendstatus;
	int errorjoinbackend;

	/* Session */
	char* backendsessionid;

	/* Soap Request */
	struct ac_http_soap_request* soaprequest;
};

static struct ac_backend_t g_ac_backend;

/* */
static int ac_backend_parsing_closewtpsession_event(const char* idevent, struct json_object* jsonparams) {
	int result = 0;
	struct ac_session_t* session;
	struct json_object* jsonwtpid;

	/* Params CloseWTPSession Action
		{
			WTPId: [string]
		}
	*/

	/* WTPId */
	jsonwtpid = json_object_object_get(jsonparams, "WTPId");
	if (!jsonwtpid || (json_object_get_type(jsonwtpid) != json_type_string)) {
		return 0;
	}

	/* Get session */
	session = ac_search_session_from_wtpid(json_object_get_string(jsonwtpid));
	if (session) {
		struct ac_session_notify_event_t notify;

		/* Notify Request to Complete Event */
		strcpy(notify.idevent, idevent);
		notify.action = NOTIFY_ACTION_CHANGE_STATE;
		notify.session_state = CAPWAP_DEAD_STATE;
		ac_session_send_action(session, AC_SESSION_ACTION_NOTIFY_EVENT, 0, (void*)&notify, sizeof(struct ac_session_notify_event_t));

		/* Async close session */
		capwap_logging_debug("Receive close wtp session for WTP %s", session->wtpid);
		ac_session_send_action(session, AC_SESSION_ACTION_CLOSE, 0, NULL, 0);

		/* */
		ac_session_release_reference(session);
		result = 1;
	}

	return result;
}

/* */
static int ac_backend_parsing_resetwtp_event(const char* idevent, struct json_object* jsonparams) {
	int result = 0;
	struct ac_session_t* session;
	struct json_object* jsonwtpid;
	struct json_object* jsonimage;
	struct json_object* jsonvendor;
	struct json_object* jsondata;

	/* Params ResetWTP Action
		{
			WTPId: [string],
			ImageIdentifier: {
				Vendor: [int],
				Data: [string]
			}
		}
	*/

	/* WTPId */
	jsonwtpid = json_object_object_get(jsonparams, "WTPId");
	if (!jsonwtpid || (json_object_get_type(jsonwtpid) != json_type_string)) {
		return 0;
	}

	/* ImageIdentifier */
	jsonimage = json_object_object_get(jsonparams, "ImageIdentifier");
	if (!jsonimage || (json_object_get_type(jsonimage) != json_type_object)) {
		return 0;
	}

	jsonvendor = json_object_object_get(jsonimage, "Vendor");
	jsondata = json_object_object_get(jsonimage, "Data");
	if (!jsonvendor || !jsondata || (json_object_get_type(jsonvendor) != json_type_int) || (json_object_get_type(jsondata) != json_type_string)) {
		return 0;
	}

	/* Get session */
	session = ac_search_session_from_wtpid(json_object_get_string(jsonwtpid));
	if (session) {
		const char* name = json_object_get_string(jsondata);
		if (name && *name) {
			int length;
			struct ac_notify_reset_t* reset;
			struct ac_session_notify_event_t notify;

			/* Notification data */
			length = sizeof(struct ac_notify_reset_t) + strlen(name) + 1;
			reset = (struct ac_notify_reset_t*)capwap_alloc(length);

			/* */
			reset->vendor = (uint32_t)json_object_get_int(jsonvendor);
			strcpy((char*)reset->name, name);

			/* Notify Request to Complete Event */
			strcpy(notify.idevent, idevent);
			notify.action = NOTIFY_ACTION_CHANGE_STATE;
			notify.session_state = CAPWAP_DEAD_STATE;
			ac_session_send_action(session, AC_SESSION_ACTION_NOTIFY_EVENT, 0, (void*)&notify, sizeof(struct ac_session_notify_event_t));

			/* Notify Action */
			capwap_logging_debug("Receive reset request for WTP %s", session->wtpid);
			ac_session_send_action(session, AC_SESSION_ACTION_RESET_WTP, 0, (void*)reset, length);
			result = 1;

			/* */
			capwap_free(reset);
		}

		ac_session_release_reference(session);
	}

	return result;
}

/* */
static int ac_backend_parsing_addwlan_event(const char* idevent, struct json_object* jsonparams) {
	int result = 0;
	struct ac_session_t* session;
	struct json_object* jsonwtpid;
	struct json_object* jsonradioid;
	struct json_object* jsonwlanid;
	struct json_object* jsoncapability;
	struct json_object* jsonqos;
	struct json_object* jsonauthtype;
	struct json_object* jsonmacmode;
	struct json_object* jsontunnelmode;
	struct json_object* jsonhidessid;
	struct json_object* jsonssid;
	const char* ssid;

	/* Params AddWLAN Action
		{
			WTPId: [string],
			RadioId: [int],
			VirtualAPId: [int],
			Capability: [int],
			Key: {
				TODO
			},
			DefaultQoS: [int],
			AuthType: [int],
			MACMode: [int],
			TunnelMode: [int],
			SuppressSSID: [bool],
			SSID: [string],
			IE: {
				TODO
			}
		}
	*/

	/* WTPId */
	jsonwtpid = json_object_object_get(jsonparams, "WTPId");
	if (!jsonwtpid || (json_object_get_type(jsonwtpid) != json_type_string)) {
		return 0;
	}

	/* RadioId */
	jsonradioid = json_object_object_get(jsonparams, "RadioId");
	if (!jsonradioid || (json_object_get_type(jsonradioid) != json_type_int)) {
		return 0;
	}

	/* VirtualAPId */
	jsonwlanid = json_object_object_get(jsonparams, "VirtualAPId");
	if (!jsonwlanid || (json_object_get_type(jsonwlanid) != json_type_int)) {
		return 0;
	}

	/* Capability */
	jsoncapability = json_object_object_get(jsonparams, "Capability");
	if (!jsoncapability || (json_object_get_type(jsoncapability) != json_type_int)) {
		return 0;
	}

	/* Key */
	/* TODO */

	/* DefaultQoS */
	jsonqos = json_object_object_get(jsonparams, "DefaultQoS");
	if (!jsonqos || (json_object_get_type(jsonqos) != json_type_int)) {
		return 0;
	}

	/* AuthType */
	jsonauthtype = json_object_object_get(jsonparams, "AuthType");
	if (!jsonauthtype || (json_object_get_type(jsonauthtype) != json_type_int)) {
		return 0;
	}

	/* MACMode */
	jsonmacmode = json_object_object_get(jsonparams, "MACMode");
	if (!jsonmacmode || (json_object_get_type(jsonmacmode) != json_type_int)) {
		return 0;
	}

	/* TunnelMode */
	jsontunnelmode = json_object_object_get(jsonparams, "TunnelMode");
	if (!jsontunnelmode || (json_object_get_type(jsontunnelmode) != json_type_int)) {
		return 0;
	}

	/* SuppressSSID */
	jsonhidessid = json_object_object_get(jsonparams, "SuppressSSID");
	if (!jsonhidessid || (json_object_get_type(jsonhidessid) != json_type_boolean)) {
		return 0;
	}

	/* SSID */
	jsonssid = json_object_object_get(jsonparams, "SSID");
	if (jsonssid && (json_object_get_type(jsonssid) == json_type_string)) {
		ssid = json_object_get_string(jsonssid);
		if (strlen(ssid) > CAPWAP_ADD_WLAN_SSID_LENGTH) {
			return 0;
		}
	} else {
		return 0;
	}

	/* IE */
	/* TODO */

	/* Get session */
	session = ac_search_session_from_wtpid(json_object_get_string(jsonwtpid));
	if (session) {
		int length;
		struct ac_notify_addwlan_t* addwlan;
		struct ac_session_notify_event_t notify;

		/* Notification data */
		length = sizeof(struct ac_notify_addwlan_t);
		addwlan = (struct ac_notify_addwlan_t*)capwap_alloc(length);

		/* */
		addwlan->radioid = (uint8_t)json_object_get_int(jsonradioid);
		addwlan->wlanid = (uint8_t)json_object_get_int(jsonwlanid);
		addwlan->capability = (uint16_t)json_object_get_int(jsoncapability);
		addwlan->qos = (uint8_t)json_object_get_int(jsonqos);
		addwlan->authmode = (uint8_t)json_object_get_int(jsonauthtype);
		addwlan->macmode = (uint8_t)json_object_get_int(jsonmacmode);
		addwlan->tunnelmode = (uint8_t)json_object_get_int(jsontunnelmode);
		addwlan->suppressssid = (uint8_t)(json_object_get_boolean(jsonhidessid) ? 1 : 0);
		strcpy(addwlan->ssid, ssid);

		/* Notify Request to Complete Event */
		strcpy(notify.idevent, idevent);
		notify.action = NOTIFY_ACTION_RECEIVE_RESPONSE_CONTROLMESSAGE;
		notify.ctrlmsg_type = CAPWAP_IEEE80211_WLAN_CONFIGURATION_RESPONSE;
		ac_session_send_action(session, AC_SESSION_ACTION_NOTIFY_EVENT, 0, (void*)&notify, sizeof(struct ac_session_notify_event_t));

		/* Notify Action */
		capwap_logging_debug("Receive AddWLAN request for WTP %s with SSID: %s", session->wtpid, addwlan->ssid);
		ac_session_send_action(session, AC_SESSION_ACTION_ADDWLAN, 0, (void*)addwlan, length);

		/* */
		ac_session_release_reference(session);
		capwap_free(addwlan);
		result = 1;
	}

	return result;
}

/* */
static int ac_backend_parsing_updatewlan_event(const char* idevent, struct json_object* jsonparams) {
	int result = 0;

	return result;
}

/* */
static int ac_backend_parsing_deletewlan_event(const char* idevent, struct json_object* jsonparams) {
	int result = 0;

	return result;
}

/* */
static int ac_backend_soap_update_event(const char* idevent, int status) {
	int result = 0;
	char buffer[256];
	struct ac_soap_request* request;
	struct ac_http_soap_server* server;

	ASSERT(g_ac_backend.soaprequest == NULL);
	ASSERT(g_ac_backend.backendsessionid != NULL);

	/* Get HTTP Soap Server */
	server = *(struct ac_http_soap_server**)capwap_array_get_item_pointer(g_ac.availablebackends, g_ac_backend.activebackend);

	/* Critical section */
	capwap_lock_enter(&g_ac_backend.lock);

	/* Build Soap Request */
	if (!g_ac_backend.endthread) {
		request = ac_soapclient_create_request("updateBackendEvent", SOAP_NAMESPACE_URI);
		if (request) {
			ac_soapclient_add_param(request, "xs:string", "idsession", g_ac_backend.backendsessionid);
			ac_soapclient_add_param(request, "xs:string", "idevent", idevent);
			ac_soapclient_add_param(request, "xs:int", "status", capwap_itoa(status, buffer));
			g_ac_backend.soaprequest = ac_soapclient_prepare_request(request, server);
		}
	}

	capwap_lock_exit(&g_ac_backend.lock);

	/* */
	if (!g_ac_backend.soaprequest) {
		if (request) {
			ac_soapclient_free_request(request);
		}

		return 0;
	}

	/* Send Request & Recv Response */
	if (ac_soapclient_send_request(g_ac_backend.soaprequest, "")) {
		struct ac_soap_response* response = ac_soapclient_recv_response(g_ac_backend.soaprequest);
		if (response) {
			ac_soapclient_free_response(response);
		}
	}

	/* Critical section */
	capwap_lock_enter(&g_ac_backend.lock);

	/* Free resource */
	ac_soapclient_close_request(g_ac_backend.soaprequest, 1);
	g_ac_backend.soaprequest = NULL;

	capwap_lock_exit(&g_ac_backend.lock);

	return result;
}

/* */
static void ac_backend_parsing_event(struct json_object* jsonitem) {
	struct json_object* jsonvalue;

	ASSERT(jsonitem != NULL);

	/* Receive event into JSON result
		{
			EventID: [int],
			Action: [string],
			Params: {
				<Depends on the Action>
			}
		}
	*/

	/* Get EventID */
	jsonvalue = json_object_object_get(jsonitem, "EventID");
	if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_string)) {
		const char* idevent = json_object_get_string(jsonvalue);

		/* Get Action */
		jsonvalue = json_object_object_get(jsonitem, "Action");
		if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_string)) {
			const char* action = json_object_get_string(jsonvalue);
			if (action) {
				jsonvalue = json_object_object_get(jsonitem, "Params");
				if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_object)) {
					int result = 0;

					/* Parsing params according to the action */
					if (!strcmp(action, "CloseWTPSession")) {
						result = ac_backend_parsing_closewtpsession_event(idevent, jsonvalue);
					} else if (!strcmp(action, "ResetWTP")) {
						result = ac_backend_parsing_resetwtp_event(idevent, jsonvalue);
					} else if (!strcmp(action, "AddWLAN")) {
						result = ac_backend_parsing_addwlan_event(idevent, jsonvalue);
					} else if (!strcmp(action, "UpdateWLAN")) {
						result = ac_backend_parsing_updatewlan_event(idevent, jsonvalue);
					} else if (!strcmp(action, "DeleteWLAN")) {
						result = ac_backend_parsing_deletewlan_event(idevent, jsonvalue);
					}

					/* Notify result action */
					ac_backend_soap_update_event(idevent, (result ? SOAP_EVENT_STATUS_RUNNING : SOAP_EVENT_STATUS_GENERIC_ERROR));
				}
			}
		}
	}
}

/* */
static int ac_backend_soap_join(int forcereset) {
	int result = 0;
	struct ac_soap_request* request;
	struct ac_http_soap_server* server;

	ASSERT(g_ac_backend.soaprequest == NULL);
	ASSERT(g_ac_backend.backendsessionid == NULL);

	/* Get HTTP Soap Server */
	server = *(struct ac_http_soap_server**)capwap_array_get_item_pointer(g_ac.availablebackends, g_ac_backend.activebackend);

	/* Critical section */
	capwap_lock_enter(&g_ac_backend.lock);

	/* Build Soap Request */
	if (!g_ac_backend.endthread) {
		request = ac_soapclient_create_request("joinBackend", SOAP_NAMESPACE_URI);
		if (request) {
			ac_soapclient_add_param(request, "xs:string", "idac", g_ac.backendacid);
			ac_soapclient_add_param(request, "xs:string", "version", g_ac.backendversion);
			ac_soapclient_add_param(request, "xs:boolean", "forcereset", (forcereset ? "true" : "false"));
			g_ac_backend.soaprequest = ac_soapclient_prepare_request(request, server);
		}
	}

	capwap_lock_exit(&g_ac_backend.lock);

	/* */
	if (!g_ac_backend.soaprequest) {
		if (request) {
			ac_soapclient_free_request(request);
		}

		return 0;
	}

	/* Send Request & Recv Response */
	if (ac_soapclient_send_request(g_ac_backend.soaprequest, "")) {
		struct ac_soap_response* response = ac_soapclient_recv_response(g_ac_backend.soaprequest);
		if (response) {
			/* Get join result */
			if ((response->responsecode == HTTP_RESULT_OK) && response->xmlResponseReturn) {
				xmlChar* xmlResult = xmlNodeGetContent(response->xmlResponseReturn);
				if (xmlStrlen(xmlResult)) {
					result = 1;
					g_ac_backend.backendsessionid = capwap_duplicate_string((const char*)xmlResult);
				}

				xmlFree(xmlResult);
			}

			/* */
			ac_soapclient_free_response(response);
		}
	}

	/* Critical section */
	capwap_lock_enter(&g_ac_backend.lock);

	/* Free resource */
	ac_soapclient_close_request(g_ac_backend.soaprequest, 1);
	g_ac_backend.soaprequest = NULL;

	capwap_lock_exit(&g_ac_backend.lock);

	return result;
}

/* */
static int ac_backend_soap_waitevent(void) {
	int result = -1;
	struct ac_soap_request* request;
	struct ac_http_soap_server* server;
	struct json_object* jsonroot = NULL;

	ASSERT(g_ac_backend.soaprequest == NULL);
	ASSERT(g_ac_backend.backendsessionid != NULL);

	/* Get HTTP Soap Server */
	server = *(struct ac_http_soap_server**)capwap_array_get_item_pointer(g_ac.availablebackends, g_ac_backend.activebackend);

	/* Critical section */
	capwap_lock_enter(&g_ac_backend.lock);

	/* Build Soap Request */
	if (!g_ac_backend.endthread) {
		request = ac_soapclient_create_request("waitBackendEvent", SOAP_NAMESPACE_URI);
		if (request) {
			ac_soapclient_add_param(request, "xs:string", "idsession", g_ac_backend.backendsessionid);
			g_ac_backend.soaprequest = ac_soapclient_prepare_request(request, server);

			/* Change result timeout */
			g_ac_backend.soaprequest->responsetimeout = SOAP_PROTOCOL_RESPONSE_WAIT_EVENT_TIMEOUT;
		}
	}

	capwap_lock_exit(&g_ac_backend.lock);

	/* */
	if (!g_ac_backend.soaprequest) {
		if (request) {
			ac_soapclient_free_request(request);
		}

		return -1;
	}

	/* Send Request & Recv Response */
	if (ac_soapclient_send_request(g_ac_backend.soaprequest, "")) {
		struct ac_soap_response* response = ac_soapclient_recv_response(g_ac_backend.soaprequest);
		if (response) {
			/* Wait event result */
			if ((response->responsecode == HTTP_RESULT_OK) && response->xmlResponseReturn) {
				int length;
				char* json;
				xmlChar* xmlResult;

				/* Decode base64 result */
				xmlResult = xmlNodeGetContent(response->xmlResponseReturn);
				if (!xmlResult) {
					return CAPWAP_RESULTCODE_FAILURE;
				}

				length = xmlStrlen(xmlResult);
				if (!length) {
					xmlFree(xmlResult);
					return CAPWAP_RESULTCODE_FAILURE;
				}

				json = (char*)capwap_alloc(AC_BASE64_DECODE_LENGTH(length));
				ac_base64_string_decode((const char*)xmlResult, json);

				xmlFree(xmlResult);

				/* Parsing JSON result */
				jsonroot = json_tokener_parse(json);
				capwap_free(json);
			}

			/* */
			ac_soapclient_free_response(response);
		}
	}

	/* Critical section */
	capwap_lock_enter(&g_ac_backend.lock);

	/* Free resource */
	ac_soapclient_close_request(g_ac_backend.soaprequest, 1);
	g_ac_backend.soaprequest = NULL;

	capwap_lock_exit(&g_ac_backend.lock);

	/* Parsing JSON command after close event request */
	if (jsonroot) {
		if (json_object_get_type(jsonroot) == json_type_array) {
			int i;
			int length;

			/* Parsing every message into JSON result */
			length = json_object_array_length(jsonroot);
			for (i = 0; i < length; i++) {
				struct json_object* jsonitem = json_object_array_get_idx(jsonroot, i);
				if (jsonitem && (json_object_get_type(jsonitem) == json_type_object)) {
					ac_backend_parsing_event(jsonitem);
				}
			}

			/* Parsing complete */
			result = 0;
		}

		/* Free JSON */
		json_object_put(jsonroot);
	}

	return result;
}

/* */
static void ac_backend_soap_leave(void) {
	struct ac_soap_request* request;
	struct ac_http_soap_server* server;

	ASSERT(g_ac_backend.soaprequest == NULL);

	/* */
	if (!g_ac_backend.backendstatus || !g_ac_backend.backendsessionid) {
		return;
	}

	/* Get HTTP Soap Server */
	server = *(struct ac_http_soap_server**)capwap_array_get_item_pointer(g_ac.availablebackends, g_ac_backend.activebackend);

	/* Critical section */
	capwap_lock_enter(&g_ac_backend.lock);

	/* Build Soap Request */
	request = ac_soapclient_create_request("leaveBackend", SOAP_NAMESPACE_URI);
	if (request) {
		ac_soapclient_add_param(request, "xs:string", "idsession", g_ac_backend.backendsessionid);
		g_ac_backend.soaprequest = ac_soapclient_prepare_request(request, server);
	}

	capwap_lock_exit(&g_ac_backend.lock);

	/* */
	if (!g_ac_backend.soaprequest) {
		if (request) {
			ac_soapclient_free_request(request);
		}

		return;
	}

	/* Send Request & Recv Response */
	if (ac_soapclient_send_request(g_ac_backend.soaprequest, "")) {
		struct ac_soap_response* response = ac_soapclient_recv_response(g_ac_backend.soaprequest);
		if (response) {
			ac_soapclient_free_response(response);
		}
	}

	/* Critical section */
	capwap_lock_enter(&g_ac_backend.lock);

	/* Free resource */
	ac_soapclient_close_request(g_ac_backend.soaprequest, 1);
	g_ac_backend.soaprequest = NULL;

	capwap_lock_exit(&g_ac_backend.lock);
}

/* */
static void ac_backend_run(void) {
	int result;
	int connected = 0;
	int forcereset = 1;

	capwap_lock_enter(&g_ac_backend.backendlock);

	while (!g_ac_backend.endthread) {
		if (connected) {
			result = ac_backend_soap_waitevent();
			if (result < 0) {
				if (g_ac_backend.endthread) {
					break;
				}

				/* Connection error, change Backend Server */
				connected = 0;
				capwap_logging_debug("Lost connection with Backend Server");
				capwap_lock_enter(&g_ac_backend.backendlock);

				/* Lost session id */
				capwap_free(g_ac_backend.backendsessionid);
				g_ac_backend.backendsessionid = NULL;

				/* Change backend */
				g_ac_backend.activebackend = (g_ac_backend.activebackend + 1) % g_ac.availablebackends->count;
			}
		} else {
			/* Join with a Backend Server */
			if (ac_backend_soap_join(forcereset)) {
				capwap_logging_debug("Joined with Backend Server");

				/* Join Complete */
				connected = 1;
				forcereset = 0;
				g_ac_backend.backendstatus = 1;
				g_ac_backend.errorjoinbackend = 0;
				capwap_lock_exit(&g_ac_backend.backendlock);
			} else {
				/* Change Backend Server */
				g_ac_backend.activebackend = (g_ac_backend.activebackend + 1) % g_ac.availablebackends->count;
				g_ac_backend.errorjoinbackend++;

				/* Wait timeout before continue */
				if (g_ac_backend.errorjoinbackend >= g_ac.availablebackends->count) {
					capwap_logging_debug("Unable to join with Backend Server");

					/* */
					forcereset = 1;
					g_ac_backend.backendstatus = 0;
					g_ac_backend.errorjoinbackend = 0;

					/* Wait before retry join to backend server */
					capwap_lock_exit(&g_ac_backend.backendlock);
					capwap_event_wait_timeout(&g_ac_backend.wait, AC_BACKEND_WAIT_TIMEOUT);
					capwap_lock_enter(&g_ac_backend.backendlock);
				}
			}
		}
	}

	/* Leave Backend */
	ac_backend_soap_leave();
	g_ac_backend.backendstatus = 0;

	/* */
	if (g_ac_backend.backendsessionid) {
		capwap_free(g_ac_backend.backendsessionid);
		g_ac_backend.backendsessionid = NULL;
	}

	/* */
	if (!connected) {
		capwap_lock_exit(&g_ac_backend.backendlock);
	}
}

/* */
static void* ac_backend_thread(void* param) {
	capwap_logging_debug("Backend start");
	ac_backend_run();
	capwap_logging_debug("Backend stop");

	/* Thread exit */
	pthread_exit(NULL);
	return NULL;
}

/* */
int ac_backend_isconnect(void) {
	return (g_ac_backend.backendstatus ? 1 : 0);
}

/* */
struct ac_http_soap_request* ac_backend_createrequest_with_session(char* method, char* uri) {
	struct ac_http_soap_server* server;
	struct ac_soap_request* request;
	struct ac_http_soap_request* soaprequest = NULL;

	/* Get active connection only if Backend Management Thread is not trying to connect with a Backend Server */
	capwap_lock_enter(&g_ac_backend.backendlock);

	if (ac_backend_isconnect()) {
		server = *(struct ac_http_soap_server**)capwap_array_get_item_pointer(g_ac.availablebackends, g_ac_backend.activebackend);

		/* Build Soap Request */
		request = ac_soapclient_create_request(method, SOAP_NAMESPACE_URI);
		if (request) {
			soaprequest = ac_soapclient_prepare_request(request, server);
			if (soaprequest) {
				ac_soapclient_add_param(request, "xs:string", "idsession", g_ac_backend.backendsessionid);
			} else {
				ac_soapclient_free_request(request);
			}
		}
	}

	capwap_lock_exit(&g_ac_backend.backendlock);

	return soaprequest;
}

/* */
int ac_backend_start(void) {
	int result;

	memset(&g_ac_backend, 0, sizeof(struct ac_backend_t));

	/* */
	if (!g_ac.backendacid) {
		capwap_logging_error("AC Backend ID isn't set");
		return 0;
	} else if (!g_ac.backendversion) {
		capwap_logging_error("Backend Protocol Version isn't set");
		return 0;
	} else if (!g_ac.availablebackends->count) {
		capwap_logging_error("List of available backends is empty");
		return 0;
	}

	/* Init */
	capwap_lock_init(&g_ac_backend.lock);
	capwap_lock_init(&g_ac_backend.backendlock);
	capwap_event_init(&g_ac_backend.wait);

	/* Create thread */
	result = pthread_create(&g_ac_backend.threadid, NULL, ac_backend_thread, NULL);
	if (result) {
		capwap_logging_debug("Unable create backend thread");
		return 0;
	}

	return 1;
}

/* */
void ac_backend_stop(void) {
	void* dummy;

	g_ac_backend.endthread = 1;

	/* Critical section */
	capwap_lock_enter(&g_ac_backend.lock);

	if (g_ac_backend.soaprequest) {
		ac_soapclient_shutdown_request(g_ac_backend.soaprequest);
	}

	/* */
	capwap_lock_exit(&g_ac_backend.lock);
	capwap_event_signal(&g_ac_backend.wait);

	/* Wait close thread */
	pthread_join(g_ac_backend.threadid, &dummy);
}

/* */
void ac_backend_free(void) {
	capwap_event_destroy(&g_ac_backend.wait);
	capwap_lock_destroy(&g_ac_backend.lock);
	capwap_lock_destroy(&g_ac_backend.backendlock);
}
