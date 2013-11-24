#ifndef __AC_BACKEND_HEADER__
#define __AC_BACKEND_HEADER__

/* */
#define SOAP_NAMESPACE_URI					"http://smartcapwap/namespace"

/* SOAP event status*/
#define SOAP_EVENT_STATUS_GENERIC_ERROR		-1
#define SOAP_EVENT_STATUS_RUNNING			0
#define SOAP_EVENT_STATUS_COMPLETE			1

/* Reset notification */
struct ac_notify_reset_t {
	uint32_t vendor;
	uint8_t name[0];
};

/* */
int ac_backend_start(void);
void ac_backend_stop(void);

/* */
int ac_backend_isconnect(void);
struct ac_http_soap_request* ac_backend_createrequest_with_session(char* method, char* uri);

#endif /* __AC_BACKEND_HEADER__ */
