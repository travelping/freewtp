#include "ac.h"
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

	/* Soap Request */
	struct ac_http_soap_request* soaprequest;
};

static struct ac_backend_t g_ac_backend;

/* */
static void ac_backend_parsing_closewtpsession_event(const char* eventid, struct json_object* jsonparams) {
	struct ac_session_t* session;
	struct json_object* jsonvalue;

	/* Params CloseWTPSession Action
		{
			WTPId: [string]
		}
	*/

	/* Get WTPId */
	jsonvalue = json_object_object_get(jsonparams, "WTPId");
	if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_string)) {
		const char* wtpid = json_object_get_string(jsonvalue);

		/* Get session */
		session = ac_search_session_from_wtpid(wtpid);
		if (session) {
			capwap_logging_debug("Receive close wtp session for WTP %s", session->wtpid);

			/* Close session */
			ac_session_close(session);
			ac_session_release_reference(session);
		}
	}
}

/* */
static void ac_backend_parsing_resetwtp_event(const char* eventid, struct json_object* jsonparams) {
	struct ac_session_t* session;
	struct json_object* jsonvalue;
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

	/* Get WTPId */
	jsonvalue = json_object_object_get(jsonparams, "WTPId");
	if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_string)) {
		/* Get session */
		session = ac_search_session_from_wtpid(json_object_get_string(jsonvalue));
		if (session) {
			/* Get ImageIdentifier */
			jsonimage = json_object_object_get(jsonparams, "ImageIdentifier");
			if (jsonimage && (json_object_get_type(jsonimage) == json_type_object)) {
				jsonvendor = json_object_object_get(jsonimage, "Vendor");
				jsondata = json_object_object_get(jsonimage, "Data");

				if (jsonvendor && jsondata && (json_object_get_type(jsonvendor) == json_type_int) && (json_object_get_type(jsondata) == json_type_string)) {
					struct ac_notify_reset_t reset;

					/* */
					memset(&reset, 0, sizeof(struct ac_notify_reset_t));
					reset.startupimage.vendor = (uint32_t)json_object_get_int(jsonvendor);
					reset.startupimage.name = (uint8_t*)capwap_duplicate_string(json_object_get_string(jsondata));

					/* */
					capwap_logging_debug("Receive reset request for WTP %s", session->wtpid);

					/* Notify Action */
					ac_session_send_action(session, AC_SESSION_ACTION_RESET_WTP, 0, (void*)&reset, sizeof(struct ac_notify_reset_t));
				}
			}

			ac_session_release_reference(session);
		}
	}
}

/* */
static void ac_backend_parsing_addwlan_event(const char* eventid, struct json_object* jsonparams) {
}

/* */
static void ac_backend_parsing_updatewlan_event(const char* eventid, struct json_object* jsonparams) {
}

/* */
static void ac_backend_parsing_deletewlan_event(const char* eventid, struct json_object* jsonparams) {
}

/* */
static void ac_backend_parsing_event(struct json_object* jsonitem) {
	struct json_object* jsonvalue;

	ASSERT(jsonitem != NULL);

	/* Receive event into JSON result
		{
			EventID: [string],
			Action: [string],
			Params: {
				<Depends on the Action>
			}
		}
	*/

	/* Get EventID */
	jsonvalue = json_object_object_get(jsonitem, "EventID");
	if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_string)) {
		const char* eventid = json_object_get_string(jsonvalue);
		if (eventid) {
			/* Get Action */
			jsonvalue = json_object_object_get(jsonitem, "Action");
			if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_string)) {
				const char* action = json_object_get_string(jsonvalue);
				if (action) {
					jsonvalue = json_object_object_get(jsonitem, "Params");
					if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_object)) {
						/* Parsing params according to the action */
						if (!strcmp(action, "CloseWTPSession")) {
							ac_backend_parsing_closewtpsession_event(eventid, jsonvalue);
						} else if (!strcmp(action, "ResetWTP")) {
							ac_backend_parsing_resetwtp_event(eventid, jsonvalue);
						} else if (!strcmp(action, "AddWLAN")) {
							ac_backend_parsing_addwlan_event(eventid, jsonvalue);
						} else if (!strcmp(action, "UpdateWLAN")) {
							ac_backend_parsing_updatewlan_event(eventid, jsonvalue);
						} else if (!strcmp(action, "DeleteWLAN")) {
							ac_backend_parsing_deletewlan_event(eventid, jsonvalue);
						}
					}
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

	ASSERT(g_ac.backendsessionid == NULL);
	ASSERT(g_ac_backend.soaprequest == NULL);

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
					g_ac.backendsessionid = capwap_duplicate_string((const char*)xmlResult);
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

	ASSERT(g_ac_backend.soaprequest == NULL);
	ASSERT(g_ac.backendsessionid != NULL);

	/* Get HTTP Soap Server */
	server = *(struct ac_http_soap_server**)capwap_array_get_item_pointer(g_ac.availablebackends, g_ac_backend.activebackend);

	/* Critical section */
	capwap_lock_enter(&g_ac_backend.lock);

	/* Build Soap Request */
	if (!g_ac_backend.endthread) {
		request = ac_soapclient_create_request("waitBackendEvent", SOAP_NAMESPACE_URI);
		if (request) {
			ac_soapclient_add_param(request, "xs:string", "idsession", g_ac.backendsessionid);
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
				int i;
				int length;
				char* json;
				xmlChar* xmlResult;
				struct json_object* jsonroot;

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

				if (jsonroot) {
					if (json_object_get_type(jsonroot) == json_type_array) {
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
static void ac_backend_soap_leave(void) {
	struct ac_soap_request* request;
	struct ac_http_soap_server* server;

	ASSERT(g_ac_backend.soaprequest == NULL);

	/* */
	if (!g_ac_backend.backendstatus || !g_ac.backendsessionid) {
		return;
	}

	/* Get HTTP Soap Server */
	server = *(struct ac_http_soap_server**)capwap_array_get_item_pointer(g_ac.availablebackends, g_ac_backend.activebackend);

	/* Critical section */
	capwap_lock_enter(&g_ac_backend.lock);

	/* Build Soap Request */
	request = ac_soapclient_create_request("leaveBackend", SOAP_NAMESPACE_URI);
	if (request) {
		ac_soapclient_add_param(request, "xs:string", "idsession", g_ac.backendsessionid);
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
				capwap_free(g_ac.backendsessionid);
				g_ac.backendsessionid = NULL;

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
	if (g_ac.backendsessionid) {
		capwap_free(g_ac.backendsessionid);
		g_ac.backendsessionid = NULL;
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
struct ac_http_soap_server* ac_backend_gethttpsoapserver(void) {
	struct ac_http_soap_server* result;

	if (!ac_backend_isconnect()) {
		return NULL;
	}

	/* Get active connection only if Backend Management Thread is not trying to connect with a Backend Server */
	capwap_lock_enter(&g_ac_backend.backendlock);
	result = *(struct ac_http_soap_server**)capwap_array_get_item_pointer(g_ac.availablebackends, g_ac_backend.activebackend);
	capwap_lock_exit(&g_ac_backend.backendlock);

	return result;
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
	capwap_lock_exit(&g_ac_backend.backendlock);
	capwap_event_signal(&g_ac_backend.wait);

	/* Wait close thread */
	pthread_join(g_ac_backend.threadid, &dummy);

	/* */
	capwap_event_destroy(&g_ac_backend.wait);
	capwap_lock_destroy(&g_ac_backend.lock);
}
