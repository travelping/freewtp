#include "ac.h"
#include "ac_backend.h"
#include "ac_soap.h"

/* */
#define SOAP_NAMESPACE_URI					"http://smartcapwap/namespace"

/* */
#define AC_BACKEND_WAIT_TIMEOUT				60000

/* */
struct ac_backend_t {
	pthread_t threadid;
	int endthread;

	capwap_event_t wait;

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

	/* Get HTTP Soap Server */
	server = *(struct ac_http_soap_server**)capwap_array_get_item_pointer(g_ac.availablebackends, g_ac_backend.activebackend);

	/* Build Soap Request */
	request = ac_soapclient_create_request("joinBackend", SOAP_NAMESPACE_URI);
	if (!request) {
		return 0;
	}

	/* Prepare to Send Request */
	g_ac_backend.soaprequest = ac_soapclient_prepare_request(request, server);
	if (!g_ac_backend.soaprequest) {
		ac_soapclient_free_request(request);
		return 0;
	}

	/* Send Request & Recv Response */
	if (ac_soapclient_send_request(g_ac_backend.soaprequest, "presence::joinBackend")) {
		struct ac_soap_response* response = ac_soapclient_recv_response(g_ac_backend.soaprequest);
		if (response) {

			/* */
			ac_soapclient_free_response(response);
		}
	}

	/* */
	ac_soapclient_close_request(g_ac_backend.soaprequest, 1);
	g_ac_backend.soaprequest = NULL;

	return result;
}

/* */
static void ac_backend_soap_leave(void) {
	if (!g_ac_backend.backendstatus) {
		return;
	}

}

/* */
static void ac_backend_run(void) {
	while (!g_ac_backend.endthread) {
		if (g_ac_backend.backendstatus) {
		} else {
			/* Join with a Backend Server */
			if (ac_backend_soap_join()) {
				/* Join Complete */
				g_ac_backend.backendstatus = 1;
				g_ac_backend.errorjoinbackend = 0;
			} else {
				/* Change Backend Server */
				g_ac_backend.activebackend = (g_ac_backend.activebackend + 1) % g_ac.availablebackends->count;
				g_ac_backend.errorjoinbackend++;

				/* Wait timeout before continue */
				if (g_ac_backend.errorjoinbackend >= g_ac.availablebackends->count) {
					capwap_event_wait_timeout(&g_ac_backend.wait, AC_BACKEND_WAIT_TIMEOUT);

					/* */
					g_ac_backend.errorjoinbackend = 0;
				}
			}
		}
	}

	/* Leave backend */
	ac_backend_soap_leave();
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
	if (!ac_backend_isconnect()) {
		return NULL;
	}

	return *(struct ac_http_soap_server**)capwap_array_get_item_pointer(g_ac.availablebackends, g_ac_backend.activebackend);
}

/* */
int ac_backend_start(void) {
	int result;

	memset(&g_ac_backend, 0, sizeof(struct ac_backend_t));

	/* */
	if (!g_ac.availablebackends->count) {
		capwap_logging_error("List of available backends is empty");
		return 0;
	}

	/* Init */
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
	capwap_event_signal(&g_ac_backend.wait);
	pthread_join(g_ac_backend.threadid, &dummy);

	/* */
	capwap_event_destroy(&g_ac_backend.wait);
}
