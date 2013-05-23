#include "capwap.h"
#include "capwap_dtls.h"
#include "capwap_protocol.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

#ifdef CAPWAP_MULTITHREADING_ENABLE
#include <pthread.h>

static pthread_mutex_t* l_mutex_buffer = NULL;
#endif

#define CAPWAP_DTLS_CERT_VERIFY_DEPTH		1
#define	CAPWAP_DTLS_MTU_SIZE				16384

/* */
static int capwap_bio_method_new(BIO* bio);
static int capwap_bio_method_free(BIO* bio);
static int capwap_bio_method_puts(BIO* bio, const char* str);
static int capwap_bio_method_read(BIO* bio, char* str, int length);
static int capwap_bio_method_write(BIO* bio, const char* str, int length);
static long capwap_bio_method_ctrl(BIO* bio, int cmd, long num, void* ptr);

/* OpenSSL BIO methods */
static BIO_METHOD bio_methods_memory = {
	BIO_TYPE_DGRAM,
	"dtls capwap packet",
	capwap_bio_method_write,
	capwap_bio_method_read,
	capwap_bio_method_puts,
	NULL,
	capwap_bio_method_ctrl,
	capwap_bio_method_new,
	capwap_bio_method_free,
	NULL,
};

/* OpenSSL BIO custom data */
struct bio_capwap_data {
	int mtu;
	struct sockaddr_storage peer;
	struct capwap_dtls* dtls;
	capwap_bio_send send;
	void* param;
};

/* */
static BIO* capwap_bio_new() {
	BIO* result;

	result = BIO_new(&bio_methods_memory);
	if (result) {
		memset(result->ptr, 0, sizeof(struct bio_capwap_data));
	}

	return result;
}

/* */
static int capwap_bio_method_new(BIO* bio) {
	bio->init = 1;
	bio->num = 0;
	bio->flags = 0;
	bio->ptr = (char*)capwap_alloc(sizeof(struct bio_capwap_data));

	return 1;
}

/* */
static int capwap_bio_method_free(BIO* bio) {
	if (bio == NULL) {
		return 0;
	} else if (bio->ptr) {
		capwap_free(bio->ptr);
	}

	return 1;
}

/* */
static int capwap_bio_method_puts(BIO* bio, const char* str) {
	return capwap_bio_method_write(bio, str, strlen(str));
}

/* */
static int capwap_bio_method_read(BIO* bio, char* str, int length) {
	struct bio_capwap_data* data = (struct bio_capwap_data*)bio->ptr;
	struct capwap_dtls_header* dtlspreamble;
	int size;

	/* Check read packet */	
	if ((data->dtls->length < sizeof(struct capwap_dtls_header)) || !data->dtls->buffer) {
		if (!data->dtls->length && !data->dtls->buffer) {
			BIO_set_retry_read(bio);		/* Notify empty buffer */
		}

		return -1;
	}
	
	/* Check DTLS Capwap Preamble */
	dtlspreamble = (struct capwap_dtls_header*)data->dtls->buffer;
	if ((dtlspreamble->preamble.version != CAPWAP_PROTOCOL_VERSION) || (dtlspreamble->preamble.type != CAPWAP_PREAMBLE_DTLS_HEADER)) {
		capwap_logging_debug("Wrong DTLS Capwap Preamble");
		return -1;		/* Wrong DTLS Capwap Preamble */
	}

	/* */
	size = data->dtls->length - sizeof(struct capwap_dtls_header);
	data->dtls->length = 0;

	data->dtls->buffer += sizeof(struct capwap_dtls_header);
	if (size > length) {
		data->dtls->buffer = NULL;
		return -1;
	}
	
	/* Copy DTLS packet */
	memcpy(str, data->dtls->buffer, size);
	data->dtls->buffer = NULL;

	return size;
}

/* */
static int capwap_bio_method_write(BIO* bio, const char* str, int length) {
	struct bio_capwap_data* data = (struct bio_capwap_data*)bio->ptr;
	char buffer[CAPWAP_MAX_PACKET_SIZE];
	struct capwap_dtls_header* dtlspreamble = (struct capwap_dtls_header*)&buffer[0];

	/* Check for maxium size of packet */
	if (length > (CAPWAP_MAX_PACKET_SIZE - sizeof(struct capwap_dtls_header))) {
		return -1;
	}
		
	/* Create DTLS Capwap Preamble */
	dtlspreamble->preamble.version = CAPWAP_PROTOCOL_VERSION;
	dtlspreamble->preamble.type = CAPWAP_PREAMBLE_DTLS_HEADER;
	dtlspreamble->reserved1 = dtlspreamble->reserved2 = dtlspreamble->reserved3 = 0;
	memcpy(&buffer[0] + sizeof(struct capwap_dtls_header), str, length);

	/* Send packet */
	if (!data->send(data->dtls, buffer, length + sizeof(struct capwap_dtls_header), data->param)) {
		return -1;
	}
	
	/* Don't return size of DTLS Capwap Preamble */
	return length;
}

/* */
static long capwap_bio_method_ctrl(BIO* bio, int cmd, long num, void* ptr) {
	long result = 1;
	struct bio_capwap_data* data = (struct bio_capwap_data*)bio->ptr;

	switch (cmd) {
		case BIO_CTRL_RESET: {
			result = 0;
			break;
		}

		case BIO_CTRL_EOF: {
			result = 0;
			break;
		}

		case BIO_CTRL_INFO: {
			result = 0;
			break;
		}

		case BIO_CTRL_GET_CLOSE: {
			result = bio->shutdown;
			break;
		}

		case BIO_CTRL_SET_CLOSE: {
			bio->shutdown = (int)num;
			break;
		}

		case BIO_CTRL_WPENDING:
		case BIO_CTRL_PENDING: {
			result = 0;
			break;
		}

		case BIO_CTRL_DUP:
		case BIO_CTRL_FLUSH: {
			result = 1;
			break;
		}

		case BIO_CTRL_PUSH: {
			result = 0;
			break;
		}

		case BIO_CTRL_POP: {
			result = 0;
			break;
		}

		case BIO_CTRL_DGRAM_QUERY_MTU: {
			data->mtu = CAPWAP_DTLS_MTU_SIZE;
			result = data->mtu;
			break;
		}

		case BIO_CTRL_DGRAM_GET_MTU: {
			result = data->mtu;
			break;
		}
		
		case BIO_CTRL_DGRAM_SET_MTU: {
			data->mtu = (int)num;
			result = data->mtu;
			break;
		}

		case BIO_CTRL_DGRAM_SET_PEER: {
			memcpy(&data->peer, ptr, sizeof(struct sockaddr_storage));
			break;
		}

		case BIO_CTRL_DGRAM_GET_PEER: {
			memcpy(ptr, &data->peer, sizeof(struct sockaddr_storage));
			break;
		}
		
		case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT: {
			break;
		}

		default: {
			result = 0;
			break;
		}
	}

	return result;
}

#ifdef CAPWAP_MULTITHREADING_ENABLE
/* */
unsigned long capwap_openssl_idcallback(void) {
	return (unsigned long)pthread_self();
}

/* */
void capwap_openssl_lockingcallback(int mode, int n, const char* file, int line) {
	ASSERT(l_mutex_buffer != NULL);

	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&l_mutex_buffer[n]);
	} else {
		pthread_mutex_unlock(&l_mutex_buffer[n]);
	}
}
#endif

/* */
int capwap_crypt_init() {
#ifdef CAPWAP_MULTITHREADING_ENABLE
	int i;
	int numlocks;
#endif

	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

#ifdef CAPWAP_MULTITHREADING_ENABLE
	/* Configure OpenSSL thread-safe */
	numlocks = CRYPTO_num_locks();
	l_mutex_buffer = (pthread_mutex_t*)capwap_alloc(numlocks * sizeof(pthread_mutex_t));
	if (!l_mutex_buffer) {
		capwap_outofmemory();
	}

	for (i = 0;  i < numlocks; i++) {
		pthread_mutex_init(&l_mutex_buffer[i], NULL);
	}

	/* OpenSSL thread-safe callbacks */
	CRYPTO_set_id_callback(capwap_openssl_idcallback);
	CRYPTO_set_locking_callback(capwap_openssl_lockingcallback);
#endif

	return 1;
}

/* */
void capwap_crypt_free() {
#ifdef CAPWAP_MULTITHREADING_ENABLE
	int i;
	int numlocks;

	ASSERT(l_mutex_buffer != NULL);

	/* */
	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);

	/* */
	numlocks = CRYPTO_num_locks();
	for (i = 0;  i < numlocks; i++) {
		pthread_mutex_destroy(&l_mutex_buffer[i]);
	}

	capwap_free(l_mutex_buffer);
	l_mutex_buffer = NULL;

#endif

	/* */
	ERR_remove_state(0);
	ERR_free_strings();
	
	ENGINE_cleanup();
	EVP_cleanup();
	
	CONF_modules_finish();
	CONF_modules_free();
	CONF_modules_unload(1);
	
	CRYPTO_cleanup_all_ex_data();
	sk_SSL_COMP_free (SSL_COMP_get_compression_methods()); 
}

/* */
static int check_passwd(char* buffer, int size, int rwflag, void* userdata) {
	int length;
	struct capwap_dtls_context* dtlscontext = (struct capwap_dtls_context*)userdata;
	
	ASSERT(dtlscontext != NULL);
	ASSERT(dtlscontext->mode == CAPWAP_DTLS_MODE_CERTIFICATE);
	ASSERT(dtlscontext->cert.pwdprivatekey != NULL);

	length = strlen(dtlscontext->cert.pwdprivatekey);
	if (!buffer || (size < (length + 1))) {
		return 0;
	}

	strcpy(buffer, dtlscontext->cert.pwdprivatekey);
	return length;
}

/* */
static int verify_certificate(int ok, X509_STORE_CTX* ctx) {
	int err;
	int depth;
	X509* err_cert;
	char buf[256];
	int preverify_ok = 1;

	err_cert = X509_STORE_CTX_get_current_cert(ctx);

	err = X509_STORE_CTX_get_error(ctx);
	X509_verify_cert_error_string(err);

	depth = X509_STORE_CTX_get_error_depth(ctx);

	X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

	if (depth > CAPWAP_DTLS_CERT_VERIFY_DEPTH) {
		preverify_ok = 0;
		err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
		X509_STORE_CTX_set_error(ctx, err);
	}

	if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
		X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, 256);
	}

	return preverify_ok;
}

static int create_cookie(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len) {
	int length;
	unsigned char* buffer;
	struct sockaddr_storage peer;
	struct capwap_app_data* appdata;

	/* */
	appdata = (struct capwap_app_data*)SSL_get_app_data(ssl);
	if (!appdata) {
		return 0;
	}

	/* Read peer information */
	BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	if (peer.ss_family == AF_INET) {
		length = sizeof(struct in_addr) + sizeof(in_port_t);
	} else if (peer.ss_family == AF_INET6) {
		length = sizeof(struct in6_addr) + sizeof(in_port_t);
	} else {
		return 0;
	}

	/* */
	buffer = capwap_alloc(length);
	if (!buffer) {
		capwap_outofmemory();
	}

	if (peer.ss_family == AF_INET) {
		struct sockaddr_in* peeripv4 = (struct sockaddr_in*)&peer;

		memcpy(buffer, &peeripv4->sin_port, sizeof(in_port_t));
		memcpy(buffer + sizeof(in_port_t), &peeripv4->sin_addr, sizeof(struct in_addr));
	} else if (peer.ss_family == AF_INET6) {
		struct sockaddr_in6* peeripv6 = (struct sockaddr_in6*)&peer;

		memcpy(buffer, &peeripv6->sin6_port, sizeof(in_port_t));
		memcpy(buffer + sizeof(in_port_t), &peeripv6->sin6_addr, sizeof(struct in6_addr));
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), appdata->cookie, CAPWAP_COOKIE_SECRET_LENGTH, buffer, length, cookie, cookie_len);
	capwap_free(buffer);

	return 1;
}

/* */
static int generate_cookie(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len) {
	unsigned int resultlength;
	unsigned char result[EVP_MAX_MD_SIZE];

	if (!create_cookie(ssl, &result[0], &resultlength)) {
		return 0;
	}

	/* Cookie generated */
	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

/* */
static int verify_cookie(SSL* ssl, unsigned char* cookie, unsigned int cookie_len) {
	unsigned int resultlength;
	unsigned char result[EVP_MAX_MD_SIZE];

	if (!create_cookie(ssl, &result[0], &resultlength)) {
		return 0;
	}

	/* Check cookie */
	if ((cookie_len != resultlength) || (memcmp(result, cookie, resultlength) != 0)) {
		return 0;
	}

	return 1;
}

/* */
int capwap_crypt_createcontext(struct capwap_dtls_context* dtlscontext, struct capwap_dtls_param* param) {
	int length;
	
	ASSERT(dtlscontext != NULL);
	ASSERT(param != NULL);
	
	memset(dtlscontext, 0, sizeof(struct capwap_dtls_context));
	dtlscontext->type = param->type;
	dtlscontext->mode = param->mode;
	
	/* Alloc context */
	dtlscontext->sslcontext = (void*)SSL_CTX_new(((param->type == CAPWAP_DTLS_SERVER) ? DTLSv1_server_method() : DTLSv1_client_method()));
	if (!dtlscontext->sslcontext) {
		capwap_logging_debug("Error to initialize dtls context");
		return 0;
	}
	
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
		if (!SSL_CTX_use_certificate_file((SSL_CTX*)dtlscontext->sslcontext, param->cert.filecert, SSL_FILETYPE_PEM)) {
			capwap_logging_debug("Error to load certificate file");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		}
		
		/* Passwork decrypt privatekey */
		length = (param->cert.pwdprivatekey ? strlen(param->cert.pwdprivatekey) : 0);
		dtlscontext->cert.pwdprivatekey = (char*)capwap_alloc(sizeof(char) * (length + 1));
		if (length > 0) {
			strcpy(dtlscontext->cert.pwdprivatekey, param->cert.pwdprivatekey);
		}
		dtlscontext->cert.pwdprivatekey[length] = 0;
		
		SSL_CTX_set_default_passwd_cb((SSL_CTX*)dtlscontext->sslcontext, check_passwd);
		SSL_CTX_set_default_passwd_cb_userdata((SSL_CTX*)dtlscontext->sslcontext, dtlscontext);
		
		/* Private key */
		if (!SSL_CTX_use_PrivateKey_file((SSL_CTX*)dtlscontext->sslcontext, param->cert.filekey, SSL_FILETYPE_PEM)) {
			capwap_logging_debug("Error to load private key file");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		}
		
		if (!SSL_CTX_check_private_key((SSL_CTX*)dtlscontext->sslcontext)) {
			capwap_logging_debug("Error to check private key");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		}
		
		/* Certificate Authority */
		if (!SSL_CTX_load_verify_locations((SSL_CTX*)dtlscontext->sslcontext, param->cert.fileca, NULL)) {
			capwap_logging_debug("Error to load ca file");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		}
		
		if (!SSL_CTX_set_default_verify_paths((SSL_CTX*)dtlscontext->sslcontext)) {
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		}
		
		/* Verify certificate callback */
		SSL_CTX_set_verify((SSL_CTX*)dtlscontext->sslcontext, ((param->type == CAPWAP_DTLS_SERVER) ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT : SSL_VERIFY_PEER), verify_certificate);

		/* 	Cipher list: 
				TLS_RSA_WITH_AES_128_CBC_SHA
				TLS_DHE_RSA_WITH_AES_128_CBC_SHA
				TLS_RSA_WITH_AES_256_CBC_SHA
				TLS_DHE_RSA_WITH_AES_256_CBC_SHA
		*/
		if (!SSL_CTX_set_cipher_list((SSL_CTX*)dtlscontext->sslcontext, "AES128-SHA:DHE-RSA-AES128-SHA:AES256-SHA:DHE-RSA-AES256-SHA")) {
			capwap_logging_debug("Error to select cipher list");
			capwap_crypt_freecontext(dtlscontext);
			return 0;
		}
	} else if (dtlscontext->mode == CAPWAP_DTLS_MODE_PRESHAREDKEY) {
		/* TODO */
	} else {
		capwap_logging_debug("Invalid DTLS mode");
		capwap_crypt_freecontext(dtlscontext);
		return 0;
	}

	/* Cookie callback */
	RAND_bytes(dtlscontext->cookie, CAPWAP_COOKIE_SECRET_LENGTH);
	SSL_CTX_set_cookie_generate_cb((SSL_CTX*)dtlscontext->sslcontext, generate_cookie);
	SSL_CTX_set_cookie_verify_cb((SSL_CTX*)dtlscontext->sslcontext, verify_cookie);

	/* */
	SSL_CTX_set_read_ahead((SSL_CTX*)dtlscontext->sslcontext, 1);
	return 1;
}

/* */
void capwap_crypt_freecontext(struct capwap_dtls_context* dtlscontext) {
	ASSERT(dtlscontext != NULL);

	/* */
	if (dtlscontext->mode == CAPWAP_DTLS_MODE_CERTIFICATE) {
		if (dtlscontext->cert.pwdprivatekey) {
			capwap_free(dtlscontext->cert.pwdprivatekey);
		}
	}

	/* Free context */	
	if (dtlscontext->sslcontext) {
		SSL_CTX_free((SSL_CTX*)dtlscontext->sslcontext);
	}

	memset(dtlscontext, 0, sizeof(struct capwap_dtls));
}

/* */
int capwap_crypt_createsession(struct capwap_dtls* dtls, int sessiontype, struct capwap_dtls_context* dtlscontext, capwap_bio_send biosend, void* param) {
	BIO* bio;
	struct capwap_app_data* appdata;
	
	ASSERT(dtls != NULL);
	ASSERT(dtlscontext != NULL);
	ASSERT(biosend != NULL);

	memset(dtls, 0, sizeof(struct capwap_dtls));
	
	/* Create ssl session */
	dtls->sslsession = (void*)SSL_new((SSL_CTX*)dtlscontext->sslcontext);
	if (!dtls->sslsession) {
		capwap_logging_debug("Error to initialize dtls session");
		return 0;
	}

	/* Create BIO */
	bio = capwap_bio_new();
	if (!bio) {
		capwap_logging_debug("Error to initialize bio");
		capwap_crypt_free(dtls);
		return 0;
	} else {
		struct bio_capwap_data* data = (struct bio_capwap_data*)bio->ptr;
		data->dtls = dtls;
		data->send = biosend;
		data->param = param;
	}

	/* Configure BIO */
	SSL_set_bio((SSL*)dtls->sslsession, bio, bio);

	/* In server mode enable cookie exchange */
	if (dtlscontext->type == CAPWAP_DTLS_SERVER) {
		SSL_set_options((SSL*)dtls->sslsession, SSL_OP_COOKIE_EXCHANGE);
	}

	/* Set static MTU size */
	SSL_set_options((SSL*)dtls->sslsession, SSL_OP_NO_QUERY_MTU);
	SSL_set_mtu((SSL*)dtls->sslsession, CAPWAP_DTLS_MTU_SIZE);

	/* */
	SSL_set_verify_depth((SSL*)dtls->sslsession, CAPWAP_DTLS_CERT_VERIFY_DEPTH + 1);

	/* */
	SSL_set_read_ahead((SSL*)dtls->sslsession, 1);
	
	if (dtlscontext->type == CAPWAP_DTLS_SERVER) {
		SSL_set_accept_state((SSL*)dtls->sslsession);
	} else {
		SSL_set_connect_state((SSL*)dtls->sslsession);
	}

	/* SSL session app data */
	appdata = (struct capwap_app_data*)capwap_alloc(sizeof(struct capwap_app_data));
	if (!appdata) {
		capwap_outofmemory();
	}

	appdata->cookie = &dtlscontext->cookie[0];
	SSL_set_ex_data((SSL*)dtls->sslsession, 0, (void*)appdata);

	/* */
	dtls->action = CAPWAP_DTLS_ACTION_NONE;
	dtls->session = sessiontype;
	dtls->enable = 1;
	
	return 1;
}

/* */
static int capwap_crypt_handshake(struct capwap_dtls* dtls) {
	int result;
	
	ASSERT(dtls != NULL);
	ASSERT(dtls->enable != 0);
	ASSERT((dtls->action == CAPWAP_DTLS_ACTION_NONE) || (dtls->action == CAPWAP_DTLS_ACTION_HANDSHAKE));

	ERR_clear_error();
	result = SSL_do_handshake((SSL*)dtls->sslsession);
	if (result <= 0) {
		result = SSL_get_error((SSL*)dtls->sslsession, result);
		if ((result == SSL_ERROR_WANT_READ) || (result == SSL_ERROR_WANT_WRITE)) {
			/* Incomplete handshake */
			dtls->action = CAPWAP_DTLS_ACTION_HANDSHAKE;
			return CAPWAP_HANDSHAKE_CONTINUE;
		}

		/* Handshake error */
		dtls->action = CAPWAP_DTLS_ACTION_ERROR;
		return CAPWAP_HANDSHAKE_ERROR;
	}
	
	/* Check certificate */
	result = SSL_get_verify_result((SSL*)dtls->sslsession);
	if (result != X509_V_OK) {
		dtls->action = CAPWAP_DTLS_ACTION_ERROR;
		return CAPWAP_HANDSHAKE_ERROR;
	}
	
	/* Handshake complete */
	dtls->action = CAPWAP_DTLS_ACTION_DATA;
	return CAPWAP_HANDSHAKE_COMPLETE;
}

/* */
int capwap_crypt_open(struct capwap_dtls* dtls, struct sockaddr_storage* peeraddr) {
	BIO_dgram_set_peer(SSL_get_rbio((SSL*)dtls->sslsession), peeraddr);
	return capwap_crypt_handshake(dtls);
}

/* */
void capwap_crypt_close(struct capwap_dtls* dtls) {
	ASSERT(dtls != NULL);
	ASSERT(dtls->enable != 0);
	
	if ((dtls->action == CAPWAP_DTLS_ACTION_DATA) || (dtls->action == CAPWAP_DTLS_ACTION_SHUTDOWN)) {
		SSL_shutdown((SSL*)dtls->sslsession);
	}
}

/* Change bio send */
void capwap_crypt_change_bio_send(struct capwap_dtls* dtls, capwap_bio_send biosend, void* param) {
	BIO* bio;

	ASSERT(dtls != NULL);
	ASSERT(dtls->enable != 0);
	ASSERT(biosend != NULL);

	bio = SSL_get_wbio((SSL*)dtls->sslsession);
	if ((bio != NULL) && (bio->ptr != NULL)) {
		struct bio_capwap_data* data = (struct bio_capwap_data*)bio->ptr;

		data->send = biosend;
		data->param = param;
	}
}

/* Change DTLS */
void capwap_crypt_change_dtls(struct capwap_dtls* dtls, struct capwap_dtls* newdtls) {
	BIO* bio;

	ASSERT(dtls != NULL);
	ASSERT(dtls->enable != 0);
	ASSERT(newdtls != NULL);

	memcpy(newdtls, dtls, sizeof(struct capwap_dtls));

	/* Update DTLS into BIO */
	bio = SSL_get_rbio((SSL*)dtls->sslsession);
	if ((bio != NULL) && (bio->ptr != NULL)) {
		struct bio_capwap_data* data = (struct bio_capwap_data*)bio->ptr;

		data->dtls = newdtls;
	}
}

/* */
void capwap_crypt_freesession(struct capwap_dtls* dtls) {
	ASSERT(dtls != NULL);
	
	/* Free SSL session */
	if (dtls->sslsession) {
		struct capwap_app_data* appdata = (struct capwap_app_data*)SSL_get_ex_data(dtls->sslsession, 0);
		if (appdata) {
			capwap_free(appdata);
		}

		SSL_free((SSL*)dtls->sslsession);
	}
	
	memset(dtls, 0, sizeof(struct capwap_dtls));
}

/* TODO: con SSL vengono utilizzati gli indirizzi predefiniti invece quelli specificati nella funzione. Reingegnerizzarla basandosi sul concetto di connessione */
int capwap_crypt_sendto(struct capwap_dtls* dtls, int sock, void* buffer, int size, struct sockaddr_storage* sendfromaddr, struct sockaddr_storage* sendtoaddr) {
	ASSERT(sock >= 0);
	ASSERT(buffer != NULL);
	ASSERT(size > 0);
	ASSERT(sendtoaddr != NULL);

	if (!dtls || !dtls->enable) {
		return capwap_sendto(sock, buffer, size, sendfromaddr, sendtoaddr);
	}

	/* Valid DTLS status */
	if (dtls->action != CAPWAP_DTLS_ACTION_DATA) {
		return 0;
	}

	ERR_clear_error();
	return SSL_write((SSL*)dtls->sslsession, buffer, size);
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
		ERR_clear_error();
		result = SSL_read((SSL*)dtls->sslsession, (plainbuffer ? plainbuffer : encrybuffer), maxsize);
		if (!result) {
			int shutdown;

			/* Check shutdown status */
			shutdown = SSL_get_shutdown((SSL*)dtls->sslsession);
			if (shutdown & SSL_RECEIVED_SHUTDOWN) {
				dtls->action = CAPWAP_DTLS_ACTION_SHUTDOWN;
				result = CAPWAP_ERROR_SHUTDOWN;
			} else {
				result = CAPWAP_ERROR_AGAIN;
			}
		} else if (result < 0) {
			/* Check error */
			sslerror = SSL_get_error((SSL*)dtls->sslsession, result);
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
