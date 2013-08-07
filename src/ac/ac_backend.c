#include "ac.h"
#include "ac_backend.h"
#include "ac_soap.h"

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
static int ac_backend_soap_join(void) {
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
			ac_soapclient_add_param(request, "xs:string", "acid", g_ac.backendacid);
			ac_soapclient_add_param(request, "xs:string", "version", g_ac.backendversion);
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
			ac_soapclient_add_param(request, "xs:string", "sessionid", g_ac.backendsessionid);
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
			/*if ((response->responsecode == HTTP_RESULT_OK) && response->xmlResponseReturn) {
				 TODO 
			}*/
			result = 0;

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
		ac_soapclient_add_param(request, "xs:string", "sessionid", g_ac.backendsessionid);
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
			if (ac_backend_soap_join()) {
				capwap_logging_debug("Joined with Backend Server");

				/* Join Complete */
				connected = 1;
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
