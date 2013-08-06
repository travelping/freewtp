#include "capwap.h"
#include "capwap_socket.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

/* */
#define OPENSSL_EXDATA_PRIVATE_KEY_PASSWORD				1

/* */
static int capwap_socket_nonblocking(int sock, int nonblocking) {
	int flags;

	ASSERT(sock >= 0);

	/* Retrieve file descriptor flags */
	flags = fcntl(sock, F_GETFL, NULL);
	if (flags < 0) {
		return 0;
	}

	if (nonblocking) {
		flags |= O_NONBLOCK;
	} else {
		flags &= ~O_NONBLOCK;
	}

	if(fcntl(sock, F_SETFL, flags) < 0) {
		return 0;
	}

	return 1;
}

/* */
int capwap_socket_connect(int sock, struct sockaddr_storage* address, int timeout) {
	int result;
	struct pollfd fds;
	socklen_t size;

	ASSERT(sock >= 0);
	ASSERT(address != NULL);

	/* Non blocking socket */
	if (!capwap_socket_nonblocking(sock, 1)) {
		return 0;
	}

	/* */
	result = connect(sock, (struct sockaddr*)address, sizeof(struct sockaddr_storage));
	if (result < 0) {
		if (errno == EINPROGRESS) {
			/* Wait to connection complete */
			for (;;) {
				memset(&fds, 0, sizeof(struct pollfd));
				fds.fd = sock;
				fds.events = POLLOUT;

				result = poll(&fds, 1, timeout);
				if ((result < 0) && (errno != EINTR)) {
					return 0;
				} else if (result > 0) {
					/* Check connection status */
					size = sizeof(int);
					if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (void*)&result, &size) < 0) {
						return 0;
					}

					if (result) {
						return 0;
					}

					/* Connection complete */
					break;
				}
			}
		} else {
			/* Unable to connect to remote host */
			return 0;
		}
	}

	return 1;
}

/* */
static int capwap_socket_crypto_checkpasswd(char* buffer, int size, int rwflag, void* userdata) {
	if (!userdata) {
		return 0;
	}

	/* */
	strncpy(buffer, (char*)userdata, size);
	buffer[size - 1] = 0;
	return strlen(buffer);
}

/* */
static int capwap_socket_crypto_verifycertificate(int preverify_ok, X509_STORE_CTX* ctx) {
	int err;
	X509* err_cert;
	char buf[256];

	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	X509_verify_cert_error_string(err);

	X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

	if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
		X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, 256);
	}

	return preverify_ok;
}

/* */
void* capwap_socket_crypto_createcontext(char* calist, char* cert, char* privatekey, char* privatekeypasswd) {
	SSL_CTX* context = NULL;

	ASSERT(calist != NULL);
	ASSERT(cert != NULL);
	ASSERT(privatekey != NULL);

	/* Create SSL context */
	context = (void*)SSL_CTX_new(SSLv23_client_method());
	if (context) {
		char* privkey = NULL;

		/* Public certificate */
		if (!SSL_CTX_use_certificate_file(context, cert, SSL_FILETYPE_PEM)) {
			capwap_logging_debug("Error to load certificate file");
			capwap_socket_crypto_freecontext(context);
			return NULL;
		}

		/* Save private key */
		if (privatekeypasswd && *privatekeypasswd) {
			privkey = capwap_duplicate_string(privatekeypasswd);
			SSL_CTX_set_ex_data(context, OPENSSL_EXDATA_PRIVATE_KEY_PASSWORD, (void*)privkey);
		}

		/* */
		SSL_CTX_set_default_passwd_cb(context, capwap_socket_crypto_checkpasswd);
		SSL_CTX_set_default_passwd_cb_userdata(context, privkey);

		/* Private key */
		if (!SSL_CTX_use_PrivateKey_file(context, privatekey, SSL_FILETYPE_PEM)) {
			capwap_logging_debug("Error to load private key file");
			capwap_socket_crypto_freecontext(context);
			return NULL;
		}

		if (!SSL_CTX_check_private_key(context)) {
			capwap_logging_debug("Error to check private key");
			capwap_socket_crypto_freecontext(context);
			return NULL;
		}

		/* Certificate Authority */
		if (!SSL_CTX_load_verify_locations(context, calist, NULL)) {
			capwap_logging_debug("Error to load ca file");
			capwap_socket_crypto_freecontext(context);
			return NULL;
		}

		/* Verify certificate callback */
		SSL_CTX_set_verify(context, SSL_VERIFY_PEER, capwap_socket_crypto_verifycertificate);

		/* Set only high security cipher list */
		if (!SSL_CTX_set_cipher_list(context, "HIGH:!DSS:!aNULL@STRENGTH")) {
			capwap_logging_debug("Error to select cipher list");
			capwap_socket_crypto_freecontext(context);
			return NULL;
		}

		/* */
		SSL_CTX_set_mode(context, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	}

	return (void*)context;
}

/* */
void capwap_socket_crypto_freecontext(void* context) {
	char* privkey;
	SSL_CTX* sslcontext = (SSL_CTX*)context;

	if (sslcontext) {
		privkey = (char*)SSL_CTX_get_ex_data(sslcontext, OPENSSL_EXDATA_PRIVATE_KEY_PASSWORD);
		if (privkey) {
			capwap_free(privkey);
		}

		SSL_CTX_free(sslcontext);
	}
}

/* */
struct capwap_socket_ssl* capwap_socket_ssl_connect(int sock, void* sslcontext, int timeout) {
	int result;
	struct pollfd fds;
	struct capwap_socket_ssl* sslsock;

	ASSERT(sock >= 0);
	ASSERT(sslcontext != NULL);

	/* */
	sslsock = capwap_alloc(sizeof(struct capwap_socket_ssl));
	if (!sslsock) {
		capwap_outofmemory();
	}

	/* Create SSL session */
	sslsock->sock = sock;
	sslsock->sslcontext = sslcontext;
	sslsock->sslsession = (void*)SSL_new((SSL_CTX*)sslcontext);
	if (!sslsock->sslsession) {
		capwap_free(sslsock);
		return NULL;
	}

	/* Set socket to SSL session */
	if (!SSL_set_fd((SSL*)sslsock->sslsession, sock)) {
		SSL_free((SSL*)sslsock->sslsession);
		capwap_free(sslsock);
		return NULL;
	}

	/* Establish SSL connection */
	for (;;) {
		ERR_clear_error();
		result = SSL_connect((SSL*)sslsock->sslsession);
		if (result == 1) {
			break;		/* Connection complete */
		} else {
			int error = SSL_get_error((SSL*)sslsock->sslsession, result);
			if ((error == SSL_ERROR_WANT_READ) || (error == SSL_ERROR_WANT_WRITE)) {
				memset(&fds, 0, sizeof(struct pollfd));
				fds.fd = sock;
				fds.events = ((error == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT);

				result = poll(&fds, 1, timeout);
				if (((result < 0) && (errno != EINTR)) || ((result > 0) && (fds.events != fds.revents))) {
					SSL_free((SSL*)sslsock->sslsession);
					capwap_free(sslsock);
					return NULL;
				}
			} else {
				SSL_free((SSL*)sslsock->sslsession);
				capwap_free(sslsock);
				return NULL;
			}
		}
	}

	return sslsock;
}

/* */
int capwap_socket_crypto_send(struct capwap_socket_ssl* sslsock, void* buffer, size_t length, int timeout) {
	int result;
	struct pollfd fds;
	size_t sendlength;

	ASSERT(sslsock != NULL);
	ASSERT(sslsock->sslsession != NULL);
	ASSERT(sslsock->sock >= 0);
	ASSERT(buffer != NULL);
	ASSERT(length > 0);

	sendlength = 0;
	while (sendlength < length) {
		size_t leftlength = length - sendlength;

		ERR_clear_error();
		result = SSL_write((SSL*)sslsock->sslsession, &((char*)buffer)[sendlength], leftlength);
		if (result > 0) {
			sendlength += result;
		} else {
			int error = SSL_get_error((SSL*)sslsock->sslsession, result);
			if ((error == SSL_ERROR_WANT_READ) || (error == SSL_ERROR_WANT_WRITE)) {
				memset(&fds, 0, sizeof(struct pollfd));
				fds.fd = sslsock->sock;
				fds.events = ((error == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT);

				result = poll(&fds, 1, timeout);
				if (((result < 0) && (errno != EINTR)) || ((result > 0) && (fds.events != fds.revents))) {
					return -1;
				}
			} else {
				return -1;
			}
		}
	}

	return sendlength;
}

/* */
int capwap_socket_crypto_recv(struct capwap_socket_ssl* sslsock, void* buffer, size_t length, int timeout) {
	int result;
	struct pollfd fds;

	ASSERT(sslsock != NULL);
	ASSERT(sslsock->sslsession != NULL);
	ASSERT(sslsock->sock >= 0);
	ASSERT(buffer != NULL);
	ASSERT(length > 0);

	for (;;) {
		ERR_clear_error();
		result = SSL_read((SSL*)sslsock->sslsession, buffer, length);
		if (result >= 0) {
			return result;
		} else {
			int error = SSL_get_error((SSL*)sslsock->sslsession, result);
			if ((error == SSL_ERROR_WANT_READ) || (error == SSL_ERROR_WANT_WRITE)) {
				memset(&fds, 0, sizeof(struct pollfd));
				fds.fd = sslsock->sock;
				fds.events = ((error == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT);

				result = poll(&fds, 1, timeout);
				if (((result < 0) && (errno != EINTR)) || ((result > 0) && (fds.events != fds.revents))) {
					break;
				}
			} else {
				break;
			}
		}
	}

	return -1;
}

/* */
void capwap_socket_ssl_shutdown(struct capwap_socket_ssl* sslsock, int timeout) {
	int result;
	struct pollfd fds;

	ASSERT(sslsock != NULL);
	ASSERT(sslsock->sslsession != NULL);
	ASSERT(sslsock->sock >= 0);

	/* */
	for (;;) {
		ERR_clear_error();
		result = SSL_shutdown((SSL*)sslsock->sslsession);
		if (result >= 0) {
			break;		/* Shutdown complete */
		} else {
			int error = SSL_get_error((SSL*)sslsock->sslsession, result);
			if ((error == SSL_ERROR_WANT_READ) || (error == SSL_ERROR_WANT_WRITE)) {
				memset(&fds, 0, sizeof(struct pollfd));
				fds.fd = sslsock->sock;
				fds.events = ((error == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT);

				result = poll(&fds, 1, timeout);
				if (((result < 0) && (errno != EINTR)) || ((result > 0) && (fds.events != fds.revents))) {
					break;		/* Shutdown error */
				}
			} else {
				break;		/* Shutdown error */
			}
		}
	}
}

/* */
void capwap_socket_ssl_close(struct capwap_socket_ssl* sslsock) {
	ASSERT(sslsock != NULL);
	ASSERT(sslsock->sslsession != NULL);

	SSL_free((SSL*)sslsock->sslsession);
	sslsock->sslsession = NULL;
}

/* */
void capwap_socket_shutdown(int sock) {
	ASSERT(sock >= 0);

	shutdown(sock, SHUT_RDWR);
}

/* */
void capwap_socket_close(int sock) {
	ASSERT(sock >= 0);

	capwap_socket_shutdown(sock);
	capwap_socket_nonblocking(sock, 0);
	close(sock);

	/* */
	ERR_clear_error();
	ERR_remove_state(0);
}

/* */
int capwap_socket_send(int sock, void* buffer, size_t length, int timeout) {
	int result;
	struct pollfd fds;
	size_t sendlength;

	ASSERT(sock >= 0);
	ASSERT(buffer != NULL);
	ASSERT(length > 0);

	sendlength = 0;
	while (sendlength < length) {
		memset(&fds, 0, sizeof(struct pollfd));
		fds.fd = sock;
		fds.events = POLLOUT;

		result = poll(&fds, 1, timeout);
		if ((result < 0) && (errno != EINTR)) {
			return -1;
		} else if (result > 0) {
			if (fds.revents == POLLOUT) {
				size_t leftlength = length - sendlength;

				result = send(sock, &((char*)buffer)[sendlength], leftlength, 0);
				if ((result < 0) && (errno != EINTR)) {
					return -1;
				} else if (result > 0) {
					sendlength += result;
				}
			} else {
				return -1;
			}
		}
	}

	return sendlength;
}

/* */
int capwap_socket_recv(int sock, void* buffer, size_t length, int timeout) {
	int result;
	struct pollfd fds;

	ASSERT(sock >= 0);
	ASSERT(buffer != NULL);
	ASSERT(length > 0);

	for (;;) {
		memset(&fds, 0, sizeof(struct pollfd));
		fds.fd = sock;
		fds.events = POLLIN;

		result = poll(&fds, 1, timeout);
		if ((result < 0) && (errno != EINTR)) {
			break;
		} else if (result > 0) {
			if (fds.revents == POLLIN) {
				result = recv(sock, buffer, length, 0);
				if ((result < 0) && (errno != EINTR)) {
					break;
				} else if (result >= 0) {
					return result;
				}
			} else {
				break;
			}
		}
	}

	return -1;
}
