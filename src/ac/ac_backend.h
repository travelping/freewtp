#ifndef __AC_BACKEND_HEADER__
#define __AC_BACKEND_HEADER__

/* */
#define SOAP_NAMESPACE_URI					"http://smartcapwap/namespace"

/* SOAP event status*/
#define SOAP_EVENT_STATUS_GENERIC_ERROR		-1
#define SOAP_EVENT_STATUS_CANCEL			-2
#define SOAP_EVENT_STATUS_RUNNING			0
#define SOAP_EVENT_STATUS_COMPLETE			1

/* */
int ac_backend_start(void);
void ac_backend_stop(void);
void ac_backend_free(void);

/* */
int ac_backend_isconnect(void);
struct ac_http_soap_request* ac_backend_createrequest_with_session(char* method, char* uri);

#endif /* __AC_BACKEND_HEADER__ */
