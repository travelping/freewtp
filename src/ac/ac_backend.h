#ifndef __AC_BACKEND_HEADER__
#define __AC_BACKEND_HEADER__

/* */
#define SOAP_NAMESPACE_URI					"http://smartcapwap/namespace"

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
struct ac_http_soap_server* ac_backend_gethttpsoapserver(void);

#endif /* __AC_BACKEND_HEADER__ */
