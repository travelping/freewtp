#include "ac.h"
#include "ac_soap.h"
#include "capwap_socket.h"

/* */
#define SOAP_PROTOCOL_CONNECT_TIMEOUT		10000

/* */
#define HTTP_RESPONSE_STATUS_CODE			0
#define HTTP_RESPONSE_HEADER				1
#define HTTP_RESPONSE_BODY					2
#define HTTP_RESPONSE_ERROR					3

/* */
static const char l_encodeblock[] = 
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char l_decodeblock[] = 
	"\x3f\x00\x00\x00\x40\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x00"
	"\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
	"\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a"
	"\x00\x00\x00\x00\x00\x00\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24"
	"\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34";

/* */
xmlNodePtr ac_xml_get_children(xmlNodePtr parent) {
	xmlNodePtr children;

	ASSERT(parent != NULL);

	/* */
	children = parent->xmlChildrenNode;
	while ((children != NULL) && (children->type != XML_ELEMENT_NODE)) {
		children = children->next;
	}

	return children;
}

/* */
xmlNodePtr ac_xml_get_next(xmlNodePtr element) {
	xmlNodePtr node;

	ASSERT(element != NULL);

	node = element->next;
	while ((node != NULL) && (node->type != XML_ELEMENT_NODE)) {
		node = node->next;
	}

	return node;
}

xmlNodePtr ac_xml_search_child(xmlNodePtr parent, char* prefix, char* name) {
	xmlNodePtr children;

	ASSERT(parent != NULL);
	ASSERT(name != NULL);

	children = ac_xml_get_children(parent);
	while (children != NULL) {
		if (!xmlStrcmp(children->name, BAD_CAST name) && (!prefix || !xmlStrcmp(children->ns->prefix, BAD_CAST prefix))) {
			break;
		}

		/* */
		children = ac_xml_get_next(children);
	}

	return children;
}

/* */
static int ac_soapclient_parsing_url(struct ac_http_soap_server* server, const char* url) {
	int length;
	int protocol;
	int host;
	int port;
	int hostlength;
	int pathlength;

	ASSERT(server != NULL);
	ASSERT(url != NULL);

	/* */
	length = strlen(url);
	if (length < 8) {
		/* Invalid URL */
		return 0;
	}

	/* Search protocol */
	protocol = 0;
	while (url[protocol] && url[protocol] != ':') {
		protocol++;
	}

	if (!protocol || (protocol + 3 >= length)) {
		/* Invalid URL */
		return 0;
	} else if ((url[protocol] != ':') || (url[protocol + 1] != '/') || (url[protocol + 2] != '/')) {
		/* Invalid URL */
		return 0;
	}

	/* Parsing protocol */
	if (!strncasecmp(url, "http", protocol)) {
		server->protocol = SOAP_HTTP_PROTOCOL;
	} else if (!strncasecmp(url, "https", protocol)) {
		server->protocol = SOAP_HTTPS_PROTOCOL;
	} else {
		/* Unknown protocol */
		return 0;
	}

	protocol += 3;

	/* Search hostname */
	host = protocol;
	while (url[host] && (url[host] != ':') && (url[host] != '/')) {
		host++;
	}

	if (host == protocol) {
		/* Invalid hostname */
		return 0;
	}

	/* Search port */
	port = host;
	if (url[port] == ':') {
		while (url[port] && (url[port] != '/')) {
			port++;
		}
	}

	/* Retrieve hostname */
	hostlength = port - protocol;
	server->host = capwap_alloc(hostlength + 1);
	strncpy(server->host, &url[protocol], hostlength);
	server->host[hostlength] = 0;

	/* Parsing hostname */
	if (!capwap_address_from_string(server->host, &server->address)) {
		/* Invalid hostname */
		return 0;
	}

	if (port == host) {
		/* Get default port */
		if (server->protocol == SOAP_HTTP_PROTOCOL) {
			CAPWAP_SET_NETWORK_PORT(&server->address, SOAP_HTTP_PORT);
		} else if (server->protocol == SOAP_HTTPS_PROTOCOL) {
			CAPWAP_SET_NETWORK_PORT(&server->address, SOAP_HTTPS_PORT);
		}
	}

	/* Retrieve path */
	pathlength = length - port;
	if (!pathlength) {
		pathlength = 1;
	}

	server->path = capwap_alloc(pathlength + 1);
	if (length == port) {
		strcpy(server->path, "/");
	} else {
		strncpy(server->path, &url[port], pathlength);
		server->path[pathlength] = 0;
	}

	return 1;
}

/* */
static int ac_soapclient_connect(struct ac_http_soap_request* httprequest) {
	int result = 0;

	if (httprequest->server->protocol == SOAP_HTTP_PROTOCOL) {
		result = capwap_socket_connect(httprequest->sock, &httprequest->server->address, SOAP_PROTOCOL_CONNECT_TIMEOUT);
	} else if (httprequest->server->protocol == SOAP_HTTPS_PROTOCOL) {
		result = capwap_socket_connect(httprequest->sock, &httprequest->server->address, SOAP_PROTOCOL_CONNECT_TIMEOUT);
		if (result) {
			/* Establish SSL/TLS connection */
			httprequest->sslsock = capwap_socket_ssl_connect(httprequest->sock, httprequest->server->sslcontext, SOAP_PROTOCOL_CONNECT_TIMEOUT);
			if (!httprequest->sslsock) {
				result = 0;
			}
		}
	}

	return result;
}

/* */
static int ac_soapclient_send_http(struct ac_http_soap_request* httprequest, char* soapaction, char* body, int length) {
	time_t ts;
	struct tm stm;
	char datetime[32];
	int headerlength;
	int result;
	char* buffer;

	/* Retrieve datetime */
	ts = time(NULL);
	localtime_r(&ts, &stm);
	strftime(datetime, 32, "%a, %d %b %Y %T %z", &stm);

	/* Calculate header length */
	headerlength = 150 + length + strlen(httprequest->server->path) + strlen(httprequest->server->host) + strlen(datetime) + strlen((soapaction ? soapaction : ""));
	buffer = capwap_alloc(headerlength);

	/* HTTP headers */
	result = snprintf(buffer, headerlength,
		"POST %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Date: %s\r\n"
		"Content-Length: %d\r\n"
		"Content-Type: text/xml\r\n"
		"Connection: Close\r\n"
		"SoapAction: %s\r\n"
		"Expect: 100-continue\r\n"
		"\r\n"
		"%s",
		httprequest->server->path,
		httprequest->server->host,
		datetime,
		length,
		(soapaction ? soapaction : ""),
		body
	);

	/* Send headers */
	if (result < 0) {
		result = 0;
	} else {
		int sendlength = -1;

		/* Send packet */
		if (httprequest->server->protocol == SOAP_HTTP_PROTOCOL) {
			sendlength = capwap_socket_send(httprequest->sock, buffer, result, httprequest->requesttimeout);
		} else if (httprequest->server->protocol == SOAP_HTTPS_PROTOCOL) {
			sendlength = capwap_socket_crypto_send(httprequest->sslsock, buffer, result, httprequest->requesttimeout);
		}

		/* Check result */
		result = ((sendlength == result) ? 1 : 0);
	}

	/* */
	capwap_free(buffer);
	return result;
}

/* */
static int ac_soapclient_http_readline(struct ac_http_soap_request* httprequest, char* buffer, int length) {
	int result = -1;
	int bufferpos = 0;

	for (;;) {
		/* Receive packet into temporaly buffer */
		if (httprequest->server->protocol == SOAP_HTTP_PROTOCOL) {
			if (capwap_socket_recv(httprequest->sock, &buffer[bufferpos], 1, httprequest->responsetimeout) != 1) {
				break;			/* Connection error */
			}
		} else if (httprequest->server->protocol == SOAP_HTTPS_PROTOCOL) {
			if (capwap_socket_crypto_recv(httprequest->sslsock, &buffer[bufferpos], 1, httprequest->responsetimeout) != 1) {
				break;			/* Connection error */
			}
		}

		/* Update buffer size */
		bufferpos += 1;
		if (bufferpos >= length) {
			break;			/* Buffer overflow */
		}

		/* Search line */
		if ((bufferpos > 1) && (buffer[bufferpos - 2] == '\r') && (buffer[bufferpos - 1] == '\n')) {
			result = bufferpos - 2;
			buffer[result] = 0;
			break;
		}
	}

	return result;
}

/* */
static int ac_soapclient_xml_io_read(void* ctx, char* buffer, int len) {
	int result = -1;
	char respbuffer[8192];
	int respbufferlength = 0;
	struct ac_http_soap_request* httprequest = (struct ac_http_soap_request*)ctx;

	while ((httprequest->httpstate == HTTP_RESPONSE_STATUS_CODE) || (httprequest->httpstate == HTTP_RESPONSE_HEADER)) {
		/* Receive packet into temporaly buffer */
		respbufferlength = ac_soapclient_http_readline(httprequest, respbuffer, sizeof(respbuffer));
		if (respbufferlength == -1) {
			httprequest->httpstate = HTTP_RESPONSE_ERROR;
		} else if (httprequest->httpstate == HTTP_RESPONSE_STATUS_CODE) {
			int temp;
			int descpos;

			/* Parse response code */
			temp = sscanf(respbuffer, "HTTP/1.1 %d %n", &httprequest->responsecode, &descpos);
			if (temp != 1) {
				httprequest->httpstate = HTTP_RESPONSE_ERROR;
				break;
			}

			/* Parsing headers */
			httprequest->httpstate = HTTP_RESPONSE_HEADER;
		} else if (httprequest->httpstate == HTTP_RESPONSE_HEADER) {
			char* value;

			if (!respbufferlength) {
				if (httprequest->responsecode == HTTP_RESULT_CONTINUE) {
					if (!httprequest->contentlength) {
						httprequest->httpstate = HTTP_RESPONSE_STATUS_CODE;
					} else {
						httprequest->httpstate = HTTP_RESPONSE_ERROR;
					}
				} else if (httprequest->contentxml && (httprequest->contentlength > 0)) {
					httprequest->httpstate = HTTP_RESPONSE_BODY;		/* Retrieve body */
				} else {
					httprequest->httpstate = HTTP_RESPONSE_ERROR;
				}
			} else {
				/* Separate key from value */
				value = strchr(respbuffer, ':');
				if (!value) {
					httprequest->httpstate = HTTP_RESPONSE_ERROR;
				} else {
					*value = 0;
					value++;
					while (*value == ' ') {
						value++;
					}

					/* */
					if (!strcmp(respbuffer, "Content-Length")) {
						httprequest->contentlength = atoi(value);
						if (!httprequest->contentlength) {
							httprequest->httpstate = HTTP_RESPONSE_ERROR;
						}
					} else if (!strcmp(respbuffer, "Content-Type")) {
						char* param;

						/* Remove param from value */
						param = strchr(value, ';');
						if (param) {
							*param = 0;
						}

						if (!strcmp(value, "text/xml")) {
							httprequest->contentxml = 1;
						} else {
							httprequest->httpstate = HTTP_RESPONSE_ERROR;
						}
					}
				}
			}
		}
	}

	if (httprequest->httpstate == HTTP_RESPONSE_BODY) {
		if (!httprequest->contentlength) {
			return 0;
		}

		/* Receive body directly into XML buffer */
		if (httprequest->server->protocol == SOAP_HTTP_PROTOCOL) {
			result = capwap_socket_recv(httprequest->sock, buffer, len, httprequest->responsetimeout);
		} else if (httprequest->server->protocol == SOAP_HTTPS_PROTOCOL) {
			result = capwap_socket_crypto_recv(httprequest->sslsock, buffer, len, httprequest->responsetimeout);
		}

		if (result > 0) {
			httprequest->contentlength -= result;
		}
	}

	return result;
}

/* */
static int ac_soapclient_xml_io_close(void *ctx) {
	struct ac_http_soap_request* httprequest = (struct ac_http_soap_request*)ctx;

	if ((httprequest->httpstate != HTTP_RESPONSE_BODY) || httprequest->contentlength) {
		return -1;
	}

	return 0;
}

/* */
static void ac_soapclient_parse_error(void* ctxt, const char* msg, ...) {
}

/* */
void ac_soapclient_init(void) {
	xmlInitParser();
	xmlSetGenericErrorFunc(NULL, ac_soapclient_parse_error);
	xmlThrDefSetGenericErrorFunc(NULL, ac_soapclient_parse_error);
}

/* */
void ac_soapclient_free(void) {
	xmlCleanupParser();
}

/* */
struct ac_http_soap_server* ac_soapclient_create_server(const char* url) {
	struct ac_http_soap_server* server;

	ASSERT(url != NULL);

	/* */
	server = (struct ac_http_soap_server*)capwap_alloc(sizeof(struct ac_http_soap_server));
	memset(server, 0, sizeof(struct ac_http_soap_server));

	/* */
	if (!ac_soapclient_parsing_url(server, url)) {
		ac_soapclient_free_server(server);
		return NULL;
	}

	return server;
}

/* */
void ac_soapclient_free_server(struct ac_http_soap_server* server) {
	ASSERT(server != NULL);

	if (server->host) {
		capwap_free(server->host);
	}

	if (server->path) {
		capwap_free(server->path);
	}

	if (server->sslcontext) {
		capwap_socket_crypto_freecontext(server->sslcontext);
	}

	capwap_free(server);
}

/* */
struct ac_soap_request* ac_soapclient_create_request(char* method, char* urinamespace) {
	char* tagMethod;
	struct ac_soap_request* request;

	ASSERT(method != NULL);
	ASSERT(urinamespace != NULL);

	/* */
	request = (struct ac_soap_request*)capwap_alloc(sizeof(struct ac_soap_request));
	memset(request, 0, sizeof(struct ac_soap_request));

	/* Build XML SOAP Request */
	request->xmlDocument = xmlNewDoc(BAD_CAST "1.0");
	request->xmlRoot = xmlNewNode(NULL, BAD_CAST "SOAP-ENV:Envelope");
	xmlNewProp(request->xmlRoot, BAD_CAST "xmlns:xsd", BAD_CAST "http://www.w3.org/2001/XMLSchema");
	xmlNewProp(request->xmlRoot, BAD_CAST "xmlns:xsi", BAD_CAST "http://www.w3.org/2001/XMLSchema-instance");
	xmlNewProp(request->xmlRoot, BAD_CAST "xmlns:SOAP-ENC", BAD_CAST "http://schemas.xmlsoap.org/soap/encoding/");
	xmlNewProp(request->xmlRoot, BAD_CAST "SOAP-ENV:encodingStyle", BAD_CAST "http://schemas.xmlsoap.org/soap/encoding/");
	xmlNewProp(request->xmlRoot, BAD_CAST "xmlns:SOAP-ENV", BAD_CAST "http://schemas.xmlsoap.org/soap/envelope/");
	xmlNewProp(request->xmlRoot, BAD_CAST "xmlns:tns", BAD_CAST urinamespace);
	xmlDocSetRootElement(request->xmlDocument, request->xmlRoot);

	xmlNewChild(request->xmlRoot, NULL, BAD_CAST "SOAP-ENV:Header", NULL);
	request->xmlBody = xmlNewChild(request->xmlRoot, NULL, BAD_CAST "SOAP-ENV:Body", NULL);

	/* */
	request->method = capwap_duplicate_string(method);

	/* Create request */
	tagMethod = capwap_alloc(strlen(method) + 5);
	sprintf(tagMethod, "tns:%s", method);
	request->xmlRequest = xmlNewChild(request->xmlBody, NULL, BAD_CAST tagMethod, NULL);
	capwap_free(tagMethod);

	return request;
}

/* */
void ac_soapclient_free_request(struct ac_soap_request* request)  {
	ASSERT(request != NULL);

	if (request->xmlDocument) {
		xmlFreeDoc(request->xmlDocument);
	}

	if (request->method) {
		capwap_free(request->method);
	}

	capwap_free(request);
}

/* */
int ac_soapclient_add_param(struct ac_soap_request* request, const char* type, const char* name, const char* value) {
	xmlNodePtr xmlParam;

	ASSERT(request != NULL);
	ASSERT(name != NULL);
	ASSERT(value != NULL);

	/* */
	xmlParam = xmlNewTextChild(request->xmlRequest, NULL, BAD_CAST name, BAD_CAST value);
	if (!xmlParam) {
		return 0;
	}

	if (type) {
		if (!xmlNewProp(xmlParam, BAD_CAST "xsi:type", BAD_CAST type)) {
			return 0;
		}
	}

	return 1;
}

/* */
char* ac_soapclient_get_request(struct ac_soap_request* request) {
	char* result;
	size_t length;
	xmlBufferPtr buffer;

	ASSERT(request != NULL);
	ASSERT(request->xmlDocument != NULL);

	/* */
	buffer = xmlBufferCreate();
	length = xmlNodeDump(buffer, request->xmlDocument, request->xmlRoot, 1, 0);

	/* Clone XML document string */
	result = capwap_alloc(length + 1);
	memcpy(result, (char*)xmlBufferContent(buffer), length);
	result[length] = 0;

	/* */
	xmlBufferFree(buffer);
	return result;
}

/* */
struct ac_http_soap_request* ac_soapclient_prepare_request(struct ac_soap_request* request, struct ac_http_soap_server* server) {
	struct ac_http_soap_request* httprequest;

	ASSERT(request != NULL);
	ASSERT(request->xmlDocument != NULL);
	ASSERT(request->xmlRoot != NULL);
	ASSERT(server != NULL);

	/* */
	httprequest = (struct ac_http_soap_request*)capwap_alloc(sizeof(struct ac_http_soap_request));
	memset(httprequest, 0, sizeof(struct ac_http_soap_request));

	/* */
	httprequest->request = request;
	httprequest->server = server;
	httprequest->requesttimeout = SOAP_PROTOCOL_REQUEST_TIMEOUT;
	httprequest->responsetimeout = SOAP_PROTOCOL_RESPONSE_TIMEOUT;

	/* Create socket */
	httprequest->sock = socket(httprequest->server->address.ss.ss_family, SOCK_STREAM, 0);
	if (httprequest->sock < 0) {
		ac_soapclient_close_request(httprequest, 0);
		return NULL;
	}

	return httprequest;
}

/* */
int ac_soapclient_send_request(struct ac_http_soap_request* httprequest, char* soapaction) {
	char* buffer;
	size_t length;
	xmlBufferPtr xmlBuffer;

	ASSERT(httprequest != NULL);

	/* Retrieve XML SOAP Request */
	xmlBuffer = xmlBufferCreate();
	length = xmlNodeDump(xmlBuffer, httprequest->request->xmlDocument, httprequest->request->xmlRoot, 1, 0);
	if (!length) {
		return 0;
	}

	buffer = (char*)xmlBufferContent(xmlBuffer);

	/* Connect to remote host */
	if (!ac_soapclient_connect(httprequest)) {
		xmlBufferFree(xmlBuffer);
		return 0;
	}

	/* Send HTTP Header */
	if (!ac_soapclient_send_http(httprequest, soapaction, buffer, (int)length)) {
		xmlBufferFree(xmlBuffer);
		return 0;
	}

	/* Sent SOAP Request */
	xmlBufferFree(xmlBuffer);
	return 1;
}

/* */
void ac_soapclient_shutdown_request(struct ac_http_soap_request* httprequest) {
	ASSERT(httprequest != NULL);

	if (httprequest->sslsock) {
		capwap_socket_ssl_shutdown(httprequest->sslsock, SOAP_PROTOCOL_CLOSE_TIMEOUT);
	}

	if (httprequest->sock >= 0) {
		capwap_socket_shutdown(httprequest->sock);
	}
}

/* */
void ac_soapclient_close_request(struct ac_http_soap_request* httprequest, int closerequest) {
	ASSERT(httprequest != NULL);

	/* */
	if (closerequest && httprequest->request) {
		ac_soapclient_free_request(httprequest->request);
	}

	/* */
	if (httprequest->sslsock) {
		capwap_socket_ssl_shutdown(httprequest->sslsock, SOAP_PROTOCOL_CLOSE_TIMEOUT);
		capwap_socket_ssl_close(httprequest->sslsock);
		capwap_free(httprequest->sslsock);
	}

	/* Close socket */
	if (httprequest->sock >= 0) {
		capwap_socket_close(httprequest->sock);
	}

	capwap_free(httprequest);
}

/* */
struct ac_soap_response* ac_soapclient_recv_response(struct ac_http_soap_request* httprequest) {
	struct ac_soap_response* response;

	ASSERT(httprequest != NULL);
	ASSERT(httprequest->sock >= 0);

	/* */
	response = (struct ac_soap_response*)capwap_alloc(sizeof(struct ac_soap_response));
	memset(response, 0, sizeof(struct ac_soap_response));

	/* Receive HTTP response into XML callback */
	httprequest->httpstate = HTTP_RESPONSE_STATUS_CODE;
	response->xmlDocument = xmlReadIO(ac_soapclient_xml_io_read, ac_soapclient_xml_io_close, (void*)httprequest, "", NULL, 0);
	if (!response->xmlDocument) {
		ac_soapclient_free_response(response);
		return NULL;
	}

	/* Parsing response */
	response->responsecode = httprequest->responsecode;
	response->xmlRoot = xmlDocGetRootElement(response->xmlDocument);
	if (!response->xmlRoot) {
		ac_soapclient_free_response(response);
		return NULL;
	}

	/* Retrieve Body */
	response->xmlBody = ac_xml_search_child(response->xmlRoot, "SOAP-ENV", "Body");
	if (!response->xmlBody) {
		ac_soapclient_free_response(response);
		return NULL;
	}

	/* Retrieve response */
	if (response->responsecode == HTTP_RESULT_OK) {
		char* tagMethod = capwap_alloc(strlen(httprequest->request->method) + 9);
		sprintf(tagMethod, "%sResponse", httprequest->request->method);
		response->xmlResponse = ac_xml_search_child(response->xmlBody, NULL, tagMethod);
		capwap_free(tagMethod);

		if (!response->xmlResponse) {
			ac_soapclient_free_response(response);
			return NULL;
		}

		/* Retrieve optional return response */
		response->xmlResponseReturn = ac_xml_search_child(response->xmlResponse, NULL, "return");
	} else {
		/* Retrieve Fault */
		response->xmlFault = ac_xml_search_child(response->xmlBody, "SOAP-ENV", "Fault");
		if (!response->xmlFault) {
			ac_soapclient_free_response(response);
			return NULL;
		}

		/* Retrieve FaultCode */
		response->xmlFaultCode = ac_xml_search_child(response->xmlFault, NULL, "faultcode");
		if (!response->xmlFaultCode) {
			ac_soapclient_free_response(response);
			return NULL;
		}

		/* Retrieve FaultString */
		response->xmlFaultString = ac_xml_search_child(response->xmlFault, NULL, "faultstring");
		if (!response->xmlFaultString) {
			ac_soapclient_free_response(response);
			return NULL;
		}
	}

	return response;
}

/* */
struct json_object* ac_soapclient_parse_json_response(struct ac_soap_response* response) {
	int length;
	char* json;
	xmlChar* xmlResult;
	struct json_object* jsonroot;

	ASSERT(response != NULL);

	/* */
	if ((response->responsecode != HTTP_RESULT_OK) || !response->xmlResponseReturn) {
		return NULL;
	}

	/* Decode base64 result */
	xmlResult = xmlNodeGetContent(response->xmlResponseReturn);
	if (!xmlResult) {
		return NULL;
	}

	length = xmlStrlen(xmlResult);
	if (!length) {
		xmlFree(xmlResult);
		return NULL;
	}

	json = (char*)capwap_alloc(AC_BASE64_DECODE_LENGTH(length));
	ac_base64_string_decode((const char*)xmlResult, json);

	xmlFree(xmlResult);

	/* Parsing JSON result */
	jsonroot = json_tokener_parse(json);
	capwap_free(json);

	return jsonroot;
}

/* */
void ac_soapclient_free_response(struct ac_soap_response* response) {
	ASSERT(response != NULL);

	if (response->xmlDocument) {
		xmlFreeDoc(response->xmlDocument);
	}

	capwap_free(response);
}

/* */
int ac_base64_binary_encode(const char* plain, int length, char* encoded) {
	int result = 0;

	ASSERT(plain != NULL);
	ASSERT(encoded != NULL);

	while (length > 0) {
		int len = ((length > 1) ? ((length > 2) ? 3 : 2) : 1);

		/* Encode block */
		encoded[0] = l_encodeblock[plain[0] >> 2];
		encoded[1] = l_encodeblock[((plain[0] & 0x03) << 4) | ((plain[1] & 0xf0) >> 4)];
		encoded[2] = (len > 1 ? l_encodeblock[((plain[1] & 0x0f) << 2) | ((plain[2] & 0xc0) >> 6)] : '=');
		encoded[3] = (len > 2 ? l_encodeblock[plain[2] & 0x3f] : '=');

		/* Next block */
		plain += len;
		length -= len;
		encoded += 4;
		result += 4;
	}

	return result;
}

/* */
void ac_base64_string_encode(const char* plain, char* encoded) {
	int result;

	ASSERT(plain != NULL);
	ASSERT(encoded != NULL);

	/* Encode base64 */
	result = ac_base64_binary_encode(plain, strlen(plain), encoded);

	/* Terminate string */
	encoded[result] = 0;
}

/* */
int ac_base64_binary_decode(const char* encoded, int length, char* plain) {
	int i;
	char bufdec[3];
	int result = 0;

	ASSERT(encoded != NULL);
	ASSERT(plain != NULL);

	while (length > 0) {
		int len = 0;
		char bufenc[4] = { 0, 0, 0, 0 };

		for (i = 0; i < 4 && (length > 0); i++) {
			char element = 0;
			while ((length > 0) && !element) {
				element = *encoded++;
				element = (((element < 43) || (element > 122)) ? 0 : l_decodeblock[element - 43]);
				length--;
			}

			if (element) {
				len++;
				bufenc[i] = element - 1;
			}
		}

		if (len) {
			bufdec[0] = (bufenc[0] << 2 | bufenc[1] >> 4);
			bufdec[1] = (bufenc[1] << 4 | bufenc[2] >> 2);
			bufdec[2] = (((bufenc[2] << 6) & 0xc0) | bufenc[3]);

			for (i = 0; i < len - 1; i++) {
				*plain++ = bufdec[i];
				result++;
			}
		}
	}

	/* Terminate string */
	return result;
}

/* */
void ac_base64_string_decode(const char* encoded, char* plain) {
	int result;

	ASSERT(encoded != NULL);
	ASSERT(plain != NULL);

	/* Decode base64 */
	result = ac_base64_binary_decode(encoded, strlen(encoded), plain);

	/* Terminate string */
	plain[result] = 0;
}
