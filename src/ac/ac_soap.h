#ifndef __AC_SOAP_HEADER__
#define __AC_SOAP_HEADER__

#include <libxml/tree.h>
#include <libxml/parser.h>

/* */
#define SOAP_HTTP_PROTOCOL				1
#define SOAP_HTTPS_PROTOCOL				2

#define SOAP_HTTP_PORT					80
#define SOAP_HTTPS_PORT					443

#define HTTP_RESULT_CONTINUE			100
#define HTTP_RESULT_OK					200

#define SOAP_PROTOCOL_REQUEST_TIMEOUT		10000
#define SOAP_PROTOCOL_RESPONSE_TIMEOUT		10000
#define SOAP_PROTOCOL_CLOSE_TIMEOUT			10000

/* */
struct ac_http_soap_server {
	int protocol;
	union sockaddr_capwap address;

	char* host;
	char* path;

	/* SSL/TLS context */
	void* sslcontext;
};

/* */
struct ac_soap_request {
	xmlDocPtr xmlDocument;
	xmlNodePtr xmlRoot;
	xmlNodePtr xmlBody;
	xmlNodePtr xmlRequest;

	char* method;
};

/* */
struct ac_http_soap_request {
	struct ac_http_soap_server* server;
	struct ac_soap_request* request;

	int sock;
	int requesttimeout;
	int responsetimeout;

	/* SSL info */
	struct capwap_socket_ssl* sslsock;

	/* Information for SOAP Response */
	int httpstate;
	int responsecode;
	int contentlength;
	int contentxml;
};

/* */
struct ac_soap_response {
	int responsecode;
	xmlDocPtr xmlDocument;
	xmlNodePtr xmlRoot;
	xmlNodePtr xmlBody;

	/* Valid response */
	xmlNodePtr xmlResponse;
	xmlNodePtr xmlResponseReturn;

	/* Fault response */
	xmlNodePtr xmlFault;
	xmlNodePtr xmlFaultCode;
	xmlNodePtr xmlFaultString;
};

/* */
void ac_soapclient_init(void);
void ac_soapclient_free(void);

/* */
struct ac_http_soap_server* ac_soapclient_create_server(const char* url);
void ac_soapclient_free_server(struct ac_http_soap_server* server);

/* Request */
struct ac_soap_request* ac_soapclient_create_request(char* method, char* urinamespace);
int ac_soapclient_add_param(struct ac_soap_request* request, const char* type, const char* name, const char* value);
char* ac_soapclient_get_request(struct ac_soap_request* request);
void ac_soapclient_free_request(struct ac_soap_request* request);

/* Transport Request */
struct ac_http_soap_request* ac_soapclient_prepare_request(struct ac_soap_request* request, struct ac_http_soap_server* server);
int ac_soapclient_send_request(struct ac_http_soap_request* httprequest, char* soapaction);
struct ac_soap_response* ac_soapclient_recv_response(struct ac_http_soap_request* httprequest);

struct json_object* ac_soapclient_parse_json_response(struct ac_soap_response* response);

void ac_soapclient_shutdown_request(struct ac_http_soap_request* httprequest);
void ac_soapclient_close_request(struct ac_http_soap_request* httprequest, int closerequest);

/* Response */
void ac_soapclient_free_response(struct ac_soap_response* response);

/* Base64 */
#define AC_BASE64_ENCODE_LENGTH(x)			((((x) + 2) / 3) * 4 + 1)
#define AC_BASE64_DECODE_LENGTH(x)			(((x) / 4) * 3 + 1)
void ac_base64_string_encode(const char* plain, char* encoded);
int ac_base64_binary_encode(const char* plain, int length, char* encoded);
void ac_base64_string_decode(const char* encoded, char* plain);
int ac_base64_binary_decode(const char* encoded, int length, char* plain);

#endif /* __AC_SOAP_HEADER__ */
