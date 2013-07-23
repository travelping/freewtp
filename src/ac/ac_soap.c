#include "ac.h"
#include "ac_soap.h"
#include "capwap_socket.h"

/* */
#define SOAP_PROTOCOL_CONNECT_TIMEOUT		10000
#define SOAP_PROTOCOL_REQUEST_TIMEOUT		10000
#define SOAP_PROTOCOL_RESPONSE_TIMEOUT		10000

/* */
#define HTTP_RESPONSE_STATUS_CODE			0
#define HTTP_RESPONSE_HEADER				1
#define HTTP_RESPONSE_BODY					2
#define HTTP_RESPONSE_ERROR					3

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
	/* TODO: write code for SSL connection
	} else if (!strncasecmp(url, "https", protocol)) {
		server->protocol = SOAP_HTTPS_PROTOCOL;*/
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
	if (!server->host) {
		capwap_outofmemory();
	}

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
	if (!server->path) {
		capwap_outofmemory();
	}

	if (length == port) {
		strcpy(server->path, "/");
	} else {
		strncpy(server->path, &url[port], pathlength);
		server->path[pathlength] = 0;
	}

	return 1;
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
	headerlength = 128 + length + strlen(httprequest->server->path) + strlen(httprequest->server->host) + strlen(datetime) + strlen((soapaction ? soapaction : ""));
	buffer = capwap_alloc(headerlength);
	if (!buffer) {
		capwap_outofmemory();
	}

	/* HTTP headers */
	result = snprintf(buffer, headerlength,
		"POST %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Date: %s\r\n"
		"Content-Length: %d\r\n"
		"Content-Type: text/xml\r\n"
		"Connection: Close\r\n"
		"SoapAction: %s\r\n"
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
		if (capwap_socket_send_timeout(httprequest->sock, buffer, result, SOAP_PROTOCOL_REQUEST_TIMEOUT) == result) {
			result = 1;
		} else {
			result = 0;
		}
	}

	/* */
	capwap_free(buffer);
	return result;
}

/* */
static int ac_soapclient_xml_io_read(void* ctx, char* buffer, int len) {
	int result = -1;
	struct ac_http_soap_request* httprequest = (struct ac_http_soap_request*)ctx;

	if ((httprequest->httpstate == HTTP_RESPONSE_STATUS_CODE) || (httprequest->httpstate == HTTP_RESPONSE_HEADER)) {
		char respbuffer[8192];
		int respbufferlength = 0;

		for (;;) {
			/* Receive packet into temporaly buffer */
			if (capwap_socket_recv_timeout(httprequest->sock, &respbuffer[respbufferlength], 1, SOAP_PROTOCOL_RESPONSE_TIMEOUT) != 1) {
				httprequest->httpstate = HTTP_RESPONSE_ERROR;
				break;
			}

			/* Update buffer size */
			respbufferlength += 1;
			if (respbufferlength >= sizeof(respbuffer)) {
				/* Buffer overflow */
				httprequest->httpstate = HTTP_RESPONSE_ERROR;
				break;
			}

			/* Search line */
			if ((respbufferlength > 1) && (respbuffer[respbufferlength - 2] == '\r') && (respbuffer[respbufferlength - 1] == '\n')) {
				if (httprequest->httpstate == HTTP_RESPONSE_STATUS_CODE) {
					int temp;
					int descpos;

					/* Parse response code */
					respbuffer[respbufferlength - 2] = 0;
					temp = sscanf(respbuffer, "HTTP/1.1 %d %n", &httprequest->responsecode, &descpos);
					if ((temp != 1) || (httprequest->responsecode != 200)) {
						httprequest->httpstate = HTTP_RESPONSE_ERROR;
						break;
					}

					/* Parsing headers */
					respbufferlength = 0;
					httprequest->httpstate = HTTP_RESPONSE_HEADER;
				} else if (httprequest->httpstate == HTTP_RESPONSE_HEADER) {
					char* value;

					if (respbufferlength == 2) {
						if (httprequest->contentlength > 0) {
							/* Retrieve body */
							httprequest->httpstate = HTTP_RESPONSE_BODY;
						} else {
							httprequest->httpstate = HTTP_RESPONSE_ERROR;
						}

						break;
					}

					/* Separate key from value */
					respbuffer[respbufferlength - 2] = 0;
					value = strchr(respbuffer, ':');
					if (!value) {
						httprequest->httpstate = HTTP_RESPONSE_ERROR;
						break;
					}

					/* */
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
							break;
						}
					} else if (!strcmp(respbuffer, "Content-Type")) {
						char* param;

						/* Remove param from value */
						param = strchr(value, ';');
						if (param) {
							*param = 0;
						}

						if (strcmp(value, "text/xml")) {
							httprequest->httpstate = HTTP_RESPONSE_ERROR;
							break;
						}
					}

					/* Next header */
					respbufferlength = 0;
				}
			}
		}
	}

	if (httprequest->httpstate == HTTP_RESPONSE_BODY) {
		if (!httprequest->contentlength) {
			return 0;
		}

		/* Receive body directly into XML buffer */
		result = capwap_socket_recv_timeout(httprequest->sock, buffer, len, SOAP_PROTOCOL_RESPONSE_TIMEOUT);
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
	if (!server) {
		capwap_outofmemory();
	}

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
	if (!request) {
		capwap_outofmemory();
	}

	memset(request, 0, sizeof(struct ac_soap_request));

	/* Build XML SOAP Request */
	request->xmlDocument = xmlNewDoc(BAD_CAST "1.0");
	request->xmlRoot = xmlNewNode(NULL, BAD_CAST "SOAP-ENV:Envelope");
	xmlNewProp(request->xmlRoot, BAD_CAST "xmlns:xsd", BAD_CAST "http://www.w3.org/2001/XMLSchema");
	xmlNewProp(request->xmlRoot, BAD_CAST "xmlns:xsi", BAD_CAST "http://www.w3.org/2001/XMLSchema-instance");
	xmlNewProp(request->xmlRoot, BAD_CAST "xmlns:SOAP-ENC", BAD_CAST "http://schemas.xmlsoap.org/soap/encoding/");
	xmlNewProp(request->xmlRoot, BAD_CAST "SOAP-ENV:encodingStyle", BAD_CAST "http://schemas.xmlsoap.org/soap/encoding/");
	xmlNewProp(request->xmlRoot, BAD_CAST "xmlns:SOAP-ENV", BAD_CAST "http://schemas.xmlsoap.org/soap/envelope/");
	xmlNewProp(request->xmlRequest, BAD_CAST "xmlns:tns", BAD_CAST urinamespace);
	xmlDocSetRootElement(request->xmlDocument, request->xmlRoot);

	xmlNewChild(request->xmlRoot, NULL, BAD_CAST "SOAP-ENV:Header", NULL);
	request->xmlBody = xmlNewChild(request->xmlRoot, NULL, BAD_CAST "SOAP-ENV:Body", NULL);

	/* */
	request->method = capwap_duplicate_string(method);

	/* Create request */
	tagMethod = capwap_alloc(strlen(method) + 5);
	if (!tagMethod) {
		capwap_outofmemory();
	}

	/* Append Request */
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
int ac_soapclient_add_param(struct ac_soap_request* request, char* type, char* name, char* value) {
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
	if (!httprequest) {
		capwap_outofmemory();
	}

	/* */
	memset(httprequest, 0, sizeof(struct ac_http_soap_request));
	httprequest->request = request;
	httprequest->server = server;

	/* Create socket */
	httprequest->sock = socket(httprequest->server->address.ss_family, SOCK_STREAM, 0);
	if (httprequest->sock < 0) {
		ac_soapclient_close_request(httprequest, 0);
		return NULL;
	}

	/* Non blocking socket */
	if (!capwap_socket_nonblocking(httprequest->sock, 1)) {
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
	if (!capwap_socket_connect_timeout(httprequest->sock, &httprequest->server->address, SOAP_PROTOCOL_CONNECT_TIMEOUT)) {
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
void ac_soapclient_close_request(struct ac_http_soap_request* httprequest, int closerequest) {
	ASSERT(httprequest != NULL);

	/* */
	if (closerequest && httprequest->request) {
		ac_soapclient_free_request(httprequest->request);
	}

	/* Close socket */
	if (httprequest->sock >= 0) {
		capwap_socket_nonblocking(httprequest->sock, 0);
		shutdown(httprequest->sock, SHUT_RDWR);
		close(httprequest->sock);
	}

	capwap_free(httprequest);
}

/* */
struct ac_soap_response* ac_soapclient_recv_response(struct ac_http_soap_request* httprequest) {
	char* tagMethod;
	struct ac_soap_response* response;

	ASSERT(httprequest != NULL);
	ASSERT(httprequest->sock >= 0);

	/* */
	response = (struct ac_soap_response*)capwap_alloc(sizeof(struct ac_soap_response));
	if (!response) {
		capwap_outofmemory();
	}

	memset(response, 0, sizeof(struct ac_soap_response));

	/* Receive HTTP response into XML callback */
	httprequest->httpstate = HTTP_RESPONSE_STATUS_CODE;
	response->xmlDocument = xmlReadIO(ac_soapclient_xml_io_read, ac_soapclient_xml_io_close, (void*)httprequest, "", NULL, 0);
	if (!response->xmlDocument) {
		ac_soapclient_free_response(response);
		return NULL;
	}

	/* Parsing response */
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
	tagMethod = capwap_alloc(strlen(httprequest->request->method) + 9);
	if (!tagMethod) {
		capwap_outofmemory();
	}

	sprintf(tagMethod, "%sResponse", httprequest->request->method);
	response->xmlResponse = ac_xml_search_child(response->xmlBody, NULL, tagMethod);
	capwap_free(tagMethod);

	if (!response->xmlResponse) {
		ac_soapclient_free_response(response);
		return NULL;
	}

	/* Retrieve Return response */
	response->xmlResponseReturn = ac_xml_search_child(response->xmlResponse, NULL, "return");
	if (!response->xmlResponseReturn) {
		ac_soapclient_free_response(response);
		return NULL;
	}

	return response;
}

/* */
void ac_soapclient_free_response(struct ac_soap_response* response) {
	ASSERT(response != NULL);

	if (response->xmlDocument) {
		xmlFreeDoc(response->xmlDocument);
	}

	capwap_free(response);
}
