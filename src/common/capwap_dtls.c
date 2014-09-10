#include "capwap.h"
#include "capwap_dtls.h"
#include "capwap_protocol.h"
#include <cyassl/options.h>
#include <cyassl/ssl.h>
#include <cyassl/ctaocrypt/sha.h>

/* */
static const char g_char2hex[] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	-1, -1, -1, -1, -1, -1, -1,
	10, 11, 12, 13, 14, 15,  		/* Upper Case A - F */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	10, 11, 12, 13, 14, 15			/* Lower Case a - f */
};
static const int g_char2hex_length = sizeof(g_char2hex) / sizeof(g_char2hex[0]);

/* */
static int capwap_bio_method_recv(CYASSL* ssl, char* buffer, int length, void* context) {
	struct capwap_dtls* dtls = (struct capwap_dtls*)context;
	struct capwap_dtls_header* dtlspreamble;
	int size;

	/* Check read packet */	
	if ((dtls->length < sizeof(struct capwap_dtls_header)) || !dtls->buffer) {
		if (!dtls->length && !dtls->buffer) {
			return CYASSL_CBIO_ERR_WANT_READ;		/* Notify empty buffer */
		}

		return CYASSL_CBIO_ERR_GENERAL;
	}
	
	/* Check DTLS Capwap Preamble */
	dtlspreamble = (struct capwap_dtls_header*)dtls->buffer;
	if ((dtlspreamble->preamble.version != CAPWAP_PROTOCOL_VERSION) || (dtlspreamble->preamble.type != CAPWAP_PREAMBLE_DTLS_HEADER)) {
		capwap_logging_debug("Wrong DTLS Capwap Preamble");
		return CYASSL_CBIO_ERR_GENERAL;		/* Wrong DTLS Capwap Preamble */
	}

	/* */
	size = dtls->length - sizeof(struct capwap_dtls_header);
	dtls->length = 0;

	dtls->buffer += sizeof(struct capwap_dtls_header);
	if (size > length) {
		dtls->buffer = NULL;
		return CYASSL_CBIO_ERR_GENERAL;
	}
	
	/* Copy DTLS packet */
	memcpy(buffer, dtls->buffer, size);
	dtls->buffer = NULL;

	return size;
}

/* */
static int capwap_bio_method_send(CYASSL* ssl, char* buffer, int length, void* context) {
	char data[CAPWAP_MAX_PACKET_SIZE];
	struct capwap_dtls* dtls = (struct capwap_dtls*)context;
	struct capwap_dtls_header* dtlspreamble = (struct capwap_dtls_header*)data;

	/* Check for maxium size of packet */
	if (length > (CAPWAP_MAX_PACKET_SIZE - sizeof(struct capwap_dtls_header))) {
		return CYASSL_CBIO_ERR_GENERAL;
	}

	/* Create DTLS Capwap Preamble */
	dtlspreamble->preamble.version = CAPWAP_PROTOCOL_VERSION;
	dtlspreamble->preamble.type = CAPWAP_PREAMBLE_DTLS_HEADER;
	dtlspreamble->reserved1 = dtlspreamble->reserved2 = dtlspreamble->reserved3 = 0;
	memcpy(&data[0] + sizeof(struct capwap_dtls_header), buffer, length);

	/* Send packet */
	if (capwap_sendto(dtls->sock, data, length + sizeof(struct capwap_dtls_header), &dtls->peeraddr) <= 0) {
		return CYASSL_CBIO_ERR_GENERAL;
	}

	/* Don't return size of DTLS Capwap Preamble */
	return length;
}

/* */
int capwap_crypt_init() {
	int result;

	/* Init library */
	result = CyaSSL_Init();
	if (result != SSL_SUCCESS) {
		return -1;
	}

	return 0;
}

/* */
void capwap_crypt_free() {
	CyaSSL_Cleanup();
}

/* */
static int capwap_crypt_verifycertificate(int preverify_ok, CYASSL_X509_STORE_CTX* ctx) {
	return preverify_ok;
}

/* */
static unsigned int capwap_crypt_psk_client(CYASSL* ssl, const char* hint, char* identity, unsigned int max_identity_len, unsigned char* psk, unsigned int max_psk_len) {
	struct capwap_dtls* dtls = (struct capwap_dtls*)CyaSSL_GetIOReadCtx(ssl);

	ASSERT(dtls != NULL);
	ASSERT(dtls->dtlscontext != NULL);

	/* */
	if ((max_identity_len < strlen(dtls->dtlscontext->presharedkey.identity)) || (max_psk_len < dtls->dtlscontext->presharedkey.pskkeylength)) {
		return 0;
	}

	/* */
	strcpy(identity, dtls->dtlscontext->presharedkey.identity);
	memcpy(psk, dtls->dtlscontext->presharedkey.pskkey, dtls->dtlscontext->presharedkey.pskkeylength);
	return dtls->dtlscontext->presharedkey.pskkeylength;
}

/* */
static unsigned int capwap_crypt_psk_server(CYASSL* ssl, const char* identity, unsigned char* psk, unsigned int max_psk_len) {
	struct capwap_dtls* dtls = (struct capwap_dtls*)CyaSSL_GetIOReadCtx(ssl);

	ASSERT(dtls != NULL);
	ASSERT(dtls->dtlscontext != NULL);

	/* */
	if (strcmp(identity, dtls->dtlscontext->presharedkey.identity) || (max_psk_len < dtls->dtlscontext->presharedkey.pskkeylength)) {
		return 0;
	}

	/* */
	memcpy(psk, dtls->dtlscontext->presharedkey.pskkey, dtls->dtlscontext->presharedkey.pskkeylength);
	return dtls->dtlscontext->presharedkey.pskkeylength;
}

/* */
static unsigned int capwap_crypt_psk_to_bin(char* pskkey, unsigned char** pskbin) {
	int i, j;
	int length;
	int result;
	unsigned char* buffer;

	/* Convert string to hex */
	length = strlen(pskkey);
	if (!length || (length % 2)) {
		return 0;
	}

	/* */
	result = length / 2;
	buffer = (unsigned char*)capwap_alloc(result);
	for (i = 0, j = 0; i < length; i += 2, j++) {
		char valuehi = pskkey[i] - 48;
		char valuelo = pskkey[i + 1] - 48;

		/* Check value */
		if ((valuehi < 0) || (valuehi >= g_char2hex_length) || (valuelo < 0) || (valuelo >= g_char2hex_length)) {
			capwap_free(buffer);
			return 0;
		}

		/* */
		valuehi  = g_char2hex[(int)valuehi];
		valuelo = g_char2hex[(int)valuelo];

		/* Check value */
		if ((valuehi < 0) || (valuelo < 0)) {
			capwap_free(buffer);
			return 0;
		}

		/* */
		buffer[j] = (unsigned char)(((unsigned char)valuehi << 4) | (unsigned char)valuelo);
	}

	/* */
	*pskbin = buffer;
	return result;
}

/* */
static int capwap_crypt_createcookie(CYASSL* ssl, unsigned char* buffer, int size, void* context) {
	int length;
	unsigned char temp[32];
    Sha sha;
    byte digest[SHA_DIGEST_SIZE];
	struct capwap_dtls* dtls = (struct capwap_dtls*)context;

	if (size != SHA_DIGEST_SIZE) {
		return -1;
	}

	/* Create buffer with peer's address and port */
	if (dtls->peeraddr.ss.ss_family == AF_INET) {
		length = sizeof(struct in_addr) + sizeof(in_port_t);
		memcpy(temp, &dtls->peeraddr.sin.sin_port, sizeof(in_port_t));
		memcpy(temp + sizeof(in_port_t), &dtls->peeraddr.sin.sin_addr, sizeof(struct in_addr));
	} else if (dtls->peeraddr.ss.ss_family == AF_INET6) {
		length = sizeof(struct in6_addr) + sizeof(in_port_t);
		memcpy(temp, &dtls->peeraddr.sin6.sin6_port, sizeof(in_port_t));
		memcpy(temp + sizeof(in_port_t), &dtls->peeraddr.sin6.sin6_addr, sizeof(struct in6_addr));
	} else {
		return -1;
	}

	/* */
	if (InitSha(&sha)) {
		return -1;
	}

	ShaUpdate(&sha, temp, length);
	ShaFinal(&sha, digest);

	/* */
	memcpy(buffer, digest, SHA_DIGEST_SIZE);
	return SHA_DIGEST_SIZE;
}

/* */
int capwap_crypt_createcontext(struct capwap_dtls_context* dtlscontext, struct capwap_dtls_param* param) {
	ASSERT(dtlscontext != NULL);
	ASSERT(param != NULL);

	memset(dtlscontext, 0, sizeof(struct capwap_dtls_context));
	dtlscontext->type = param->type;
	dtlscontext->mode = param->mode;

	/* Alloc context */
	dtlscontext->sslcontext = (void*)CyaSSL_CTX_new(((param->type == CAPWAP_DTLS_SERVER) ? CyaDTLSv1_server_method() : CyaDTLSv1_client_method()));
	if (!dtlscontext->sslcontext) {
		capwap_logging_debug("Error to initialize dtls context");
		return 0;
	}

	/* Set context IO */
	CyaSSL_SetIORecv((CYASSL_CTX*)dtlscontext->sslcontext, capwap_bio_method_recv);
	CyaSSL_SetIOSend((CYASSL_CTX*)dtlscontext->sslcontext, capwap_bio_method_send);
	CyaSSL_CTX_SetGenCookie((CYASSL_CTX*)dtlscontext->sslcontext, capwap_crypt_createcookie);

	/* */
	if (dtlscontext->mode == CAPWAP_DTLS_MODE_CERTIFICATE) {
		/* Check context */
		if (!param->cert.filecert || !strlen(param->cert.filecert)) {
			capwap_logging_debug("Error, request certificate file");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		} else if (!param->cert.filekey || !strlen(param->cert.filekey)) {
			capwap_logging_debug("Error, request privatekey file");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		} else if (!param->cert.fileca || !strlen(param->cert.fileca)) {
			capwap_logging_debug("Error, request ca file");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		}

		/* Public certificate */
		if (!CyaSSL_CTX_use_certificate_file((CYASSL_CTX*)dtlscontext->sslcontext, param->cert.filecert, SSL_FILETYPE_PEM)) {
			capwap_logging_debug("Error to load certificate file");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		}

		/* Private key */
		if (!CyaSSL_CTX_use_PrivateKey_file((CYASSL_CTX*)dtlscontext->sslcontext, param->cert.filekey, SSL_FILETYPE_PEM)) {
			capwap_logging_debug("Error to load private key file");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		}

		if (!CyaSSL_CTX_check_private_key((CYASSL_CTX*)dtlscontext->sslcontext)) {
			capwap_logging_debug("Error to check private key");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		}

		/* Certificate Authority */
		if (!CyaSSL_CTX_load_verify_locations((CYASSL_CTX*)dtlscontext->sslcontext, param->cert.fileca, NULL)) {
			capwap_logging_debug("Error to load ca file");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		}

		/* Verify certificate callback */
		CyaSSL_CTX_set_verify((CYASSL_CTX*)dtlscontext->sslcontext, ((param->type == CAPWAP_DTLS_SERVER) ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT : SSL_VERIFY_PEER), capwap_crypt_verifycertificate);

		/* 	Cipher list: 
				TLS_RSA_WITH_AES_128_CBC_SHA
				TLS_DHE_RSA_WITH_AES_128_CBC_SHA
				TLS_RSA_WITH_AES_256_CBC_SHA
				TLS_DHE_RSA_WITH_AES_256_CBC_SHA
		*/
		if (!CyaSSL_CTX_set_cipher_list((CYASSL_CTX*)dtlscontext->sslcontext, "AES128-SHA:DHE-RSA-AES128-SHA:AES256-SHA:DHE-RSA-AES256-SHA")) {
			capwap_logging_debug("Error to select cipher list");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		}
	} else if (dtlscontext->mode == CAPWAP_DTLS_MODE_PRESHAREDKEY) {
		/* 	Cipher list: 
				TLS_PSK_WITH_AES_128_CBC_SHA
				TLS_DHE_PSK_WITH_AES_128_CBC_SHA
				TLS_PSK_WITH_AES_256_CBC_SHA
				TLS_DHE_PSK_WITH_AES_256_CBC_SHA
		*/
		if (!CyaSSL_CTX_set_cipher_list((CYASSL_CTX*)dtlscontext->sslcontext, "PSK-AES128-CBC-SHA:PSK-AES256-CBC-SHA")) {
			capwap_logging_debug("Error to select cipher list");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		}

		/* */
		if (dtlscontext->type == CAPWAP_DTLS_SERVER) {
			if (param->presharedkey.hint) {
				CyaSSL_CTX_use_psk_identity_hint((CYASSL_CTX*)dtlscontext->sslcontext, param->presharedkey.hint);
			} else {
				capwap_logging_debug("Error to presharedkey hint");
				capwap_crypt_freecontext(dtlscontext);
				return 0;
			}
		}

		/* */
		dtlscontext->presharedkey.identity = capwap_duplicate_string(param->presharedkey.identity);
		dtlscontext->presharedkey.pskkeylength = capwap_crypt_psk_to_bin(param->presharedkey.pskkey, &dtlscontext->presharedkey.pskkey);
		if (!dtlscontext->presharedkey.pskkeylength) {
			capwap_logging_debug("Error to presharedkey");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		}

		/* */
		if (dtlscontext->type == CAPWAP_DTLS_SERVER) {
			CyaSSL_CTX_set_psk_server_callback((CYASSL_CTX*)dtlscontext->sslcontext, capwap_crypt_psk_server);
		} else {
			CyaSSL_CTX_set_psk_client_callback((CYASSL_CTX*)dtlscontext->sslcontext, capwap_crypt_psk_client);
		}
	} else {
		capwap_logging_debug("Invalid DTLS mode");
		capwap_crypt_freecontext(dtlscontext);
		return 0;
	}

	return 1;
}

/* */
void capwap_crypt_freecontext(struct capwap_dtls_context* dtlscontext) {
	ASSERT(dtlscontext != NULL);

	/* */
	if (dtlscontext->mode == CAPWAP_DTLS_MODE_PRESHAREDKEY) {
		if (dtlscontext->presharedkey.identity) {
			capwap_free(dtlscontext->presharedkey.identity);
		}

		if (dtlscontext->presharedkey.pskkey) {
			capwap_free(dtlscontext->presharedkey.pskkey);
		}
	}

	/* Free context */	
	if (dtlscontext->sslcontext) {
		CyaSSL_CTX_free((CYASSL_CTX*)dtlscontext->sslcontext);
	}

	memset(dtlscontext, 0, sizeof(struct capwap_dtls_context));
}

/* */
int capwap_crypt_createsession(struct capwap_dtls* dtls, struct capwap_dtls_context* dtlscontext) {
	ASSERT(dtls != NULL);
	ASSERT(dtlscontext != NULL);
	ASSERT(dtlscontext->sslcontext != NULL);

	/* Create ssl session */
	dtls->sslsession = (void*)CyaSSL_new((CYASSL_CTX*)dtlscontext->sslcontext);
	if (!dtls->sslsession) {
		capwap_logging_debug("Error to initialize dtls session");
		return 0;
	}

	/* */
	CyaSSL_set_using_nonblock((CYASSL*)dtls->sslsession, 1);
	CyaSSL_SetIOReadCtx((CYASSL*)dtls->sslsession, (void*)dtls);
	CyaSSL_SetIOWriteCtx((CYASSL*)dtls->sslsession, (void*)dtls);
	CyaSSL_SetCookieCtx((CYASSL*)dtls->sslsession, (void*)dtls);

	/* */
	dtls->action = CAPWAP_DTLS_ACTION_NONE;
	dtls->dtlscontext = dtlscontext;
	dtls->enable = 1;
	dtls->buffer = NULL;
	dtls->length = 0;

	return 1;
}

/* */
static int capwap_crypt_handshake(struct capwap_dtls* dtls) {
	int result;
	
	ASSERT(dtls != NULL);
	ASSERT(dtls->enable != 0);
	ASSERT((dtls->action == CAPWAP_DTLS_ACTION_NONE) || (dtls->action == CAPWAP_DTLS_ACTION_HANDSHAKE));

	/* */
	if (dtls->dtlscontext->type == CAPWAP_DTLS_SERVER) {
		result = CyaSSL_accept((CYASSL*)dtls->sslsession);
	} else {
		result = CyaSSL_connect((CYASSL*)dtls->sslsession);
	}

	/* */
	if (result != SSL_SUCCESS) {
		result = CyaSSL_get_error((CYASSL*)dtls->sslsession, 0);
		if ((result == SSL_ERROR_WANT_READ) || (result == SSL_ERROR_WANT_WRITE)) {
			/* Incomplete handshake */
			dtls->action = CAPWAP_DTLS_ACTION_HANDSHAKE;
			return CAPWAP_HANDSHAKE_CONTINUE;
		}

		/* Handshake error */
		dtls->action = CAPWAP_DTLS_ACTION_ERROR;
		return CAPWAP_HANDSHAKE_ERROR;
	}

	/* Handshake complete */
	dtls->action = CAPWAP_DTLS_ACTION_DATA;
	return CAPWAP_HANDSHAKE_COMPLETE;
}

/* */
void capwap_crypt_setconnection(struct capwap_dtls* dtls, int sock, union sockaddr_capwap* localaddr, union sockaddr_capwap* peeraddr) {
	ASSERT(sock >= 0);
	ASSERT(localaddr != NULL);
	ASSERT(peeraddr != NULL);

	dtls->sock = sock;

	/* */
	memcpy(&dtls->localaddr, localaddr, sizeof(union sockaddr_capwap));
	if (dtls->localaddr.ss.ss_family == AF_INET6) {
		capwap_ipv4_mapped_ipv6(&dtls->localaddr);
	}

	/* */
	memcpy(&dtls->peeraddr, peeraddr, sizeof(union sockaddr_capwap));
	if (dtls->peeraddr.ss.ss_family == AF_INET6) {
		capwap_ipv4_mapped_ipv6(&dtls->peeraddr);
	}
}

/* */
int capwap_crypt_open(struct capwap_dtls* dtls) {
	return capwap_crypt_handshake(dtls);
}

/* */
void capwap_crypt_close(struct capwap_dtls* dtls) {
	ASSERT(dtls != NULL);
	ASSERT(dtls->enable != 0);

	if (dtls->sslsession) {
		CyaSSL_shutdown((CYASSL*)dtls->sslsession);
	}
}

/* */
void capwap_crypt_freesession(struct capwap_dtls* dtls) {
	ASSERT(dtls != NULL);

	/* Free SSL session */
	if (dtls->sslsession) {
		CyaSSL_free((CYASSL*)dtls->sslsession);
	}

	/* */
	memset(dtls, 0, sizeof(struct capwap_dtls));
}

/* */
int capwap_crypt_sendto(struct capwap_dtls* dtls, void* buffer, int size) {
	ASSERT(dtls != NULL);
	ASSERT(dtls->sock >= 0);
	ASSERT(buffer != NULL);
	ASSERT(size > 0);

	if (!dtls->enable) {
		return capwap_sendto(dtls->sock, buffer, size, &dtls->peeraddr);
	}

	/* Valid DTLS status */
	if (dtls->action != CAPWAP_DTLS_ACTION_DATA) {
		return 0;
	}

	return CyaSSL_write((CYASSL*)dtls->sslsession, buffer, size);
}

/* */
int capwap_crypt_sendto_fragmentpacket(struct capwap_dtls* dtls, struct capwap_list* fragmentlist) {
	struct capwap_list_item* item;

	ASSERT(dtls != NULL);
	ASSERT(dtls->sock >= 0);
	ASSERT(fragmentlist != NULL);

	item = fragmentlist->first;
	while (item) {
		struct capwap_fragment_packet_item* fragmentpacket = (struct capwap_fragment_packet_item*)item->item;
		ASSERT(fragmentpacket != NULL);
		ASSERT(fragmentpacket->offset > 0);

		if (!capwap_crypt_sendto(dtls, fragmentpacket->buffer, fragmentpacket->offset)) {
			return 0;
		}

		/* */
		item = item->next;
	}

	return 1;
}

/* */
int capwap_decrypt_packet(struct capwap_dtls* dtls, void* encrybuffer, int size, void* plainbuffer, int maxsize) {
	int sslerror;
	int result = -1;
	char* clone = NULL;
	
	ASSERT(dtls != NULL);
	ASSERT(dtls->enable != 0);
	ASSERT((dtls->action == CAPWAP_DTLS_ACTION_HANDSHAKE) || (dtls->action == CAPWAP_DTLS_ACTION_DATA));
	ASSERT(dtls->buffer == NULL);
	ASSERT(dtls->length == 0);
	ASSERT(encrybuffer != NULL);
	ASSERT(size > 0);
	ASSERT(maxsize > 0);

	/* */
	if (!plainbuffer) {
		clone = capwap_clone(encrybuffer, size);
	}

	dtls->buffer = (clone ? clone : encrybuffer);
	dtls->length = size;

	/* */	
	if (dtls->action == CAPWAP_DTLS_ACTION_HANDSHAKE) {
		if (capwap_crypt_handshake(dtls) == CAPWAP_HANDSHAKE_ERROR) {
			capwap_logging_debug("Error in DTLS handshake");
			result = CAPWAP_ERROR_CLOSE;			/* Error handshake */
		} else {
			result = CAPWAP_ERROR_AGAIN;			/* Don't parsing DTLS packet */
		}
	} else if (dtls->action == CAPWAP_DTLS_ACTION_DATA) {
		result = CyaSSL_read((CYASSL*)dtls->sslsession, (plainbuffer ? plainbuffer : encrybuffer), maxsize);
		if (!result) {
			dtls->action = CAPWAP_DTLS_ACTION_SHUTDOWN;
			result = CAPWAP_ERROR_SHUTDOWN;
		} else if (result < 0) {
			/* Check error */
			sslerror = CyaSSL_get_error((CYASSL*)dtls->sslsession, 0);
			if ((sslerror == SSL_ERROR_WANT_READ) || (sslerror == SSL_ERROR_WANT_WRITE)) {
				result = CAPWAP_ERROR_AGAIN;			/* DTLS Renegotiation */
			} else {
				result = CAPWAP_ERROR_CLOSE;
			}
		}
	}

	/* Verify BIO read */
	ASSERT(dtls->buffer == NULL);
	ASSERT(dtls->length == 0);

	/* Free clone */
	if (clone) {
		capwap_free(clone);
	}
	
	return result;
}

/* */
#define SIZEOF_DTLS_LAYERS										14
#define DTLS_RECORD_LAYER_HANDSHAKE_CONTENT_TYPE				22
#define DTLS_1_0_VERSION										0xfeff
#define DTLS_1_2_VERSION										0xfefd
#define DTLS_HANDSHAKE_LAYER_CLIENT_HELLO						1

/* */
int capwap_crypt_has_dtls_clienthello(void* buffer, int buffersize) {
	unsigned char* dtlsdata = (unsigned char*)buffer;

	/* Read DTLS packet in RAW mode */
	if ((buffer != NULL) && (buffersize > SIZEOF_DTLS_LAYERS)) {
		if (dtlsdata[0] == DTLS_RECORD_LAYER_HANDSHAKE_CONTENT_TYPE) {
			uint16_t version = ntohs(*(uint16_t*)(dtlsdata + 1));
			if (((version == DTLS_1_0_VERSION) || (version == DTLS_1_2_VERSION)) && (dtlsdata[13] == DTLS_HANDSHAKE_LAYER_CLIENT_HELLO)) {
				return 1;
			}
		}
	}

	return 0;
}
