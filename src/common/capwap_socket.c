#include "capwap.h"
#include "capwap_network.h"
#include "capwap_socket.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

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
int capwap_socket_connect(int sock, union sockaddr_capwap* address, int timeout) {
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
	result = connect(sock, &address->sa, sizeof(union sockaddr_capwap));
	if (result < 0) {
		if (errno == EINPROGRESS) {
			/* Wait to connection complete */
			for (;;) {
				memset(&fds, 0, sizeof(struct pollfd));
				fds.fd = sock;
				fds.events = POLLOUT;

				result = poll(&fds, 1, timeout);
				if (!result || ((result < 0) && (errno != EINTR))) {
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
static int capwap_socket_crypto_verifycertificate(int preverify, WOLFSSL_X509_STORE_CTX* store) {
	return preverify;
}

/* */
void* capwap_socket_crypto_createcontext(char* calist, char* cert, char* privatekey) {
	WOLFSSL_CTX* context = NULL;

	ASSERT(calist != NULL);
	ASSERT(cert != NULL);
	ASSERT(privatekey != NULL);

	/* Create SSL context */
	context = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
	if (context) {
		/* Public certificate */
		if (!wolfSSL_CTX_use_certificate_file(context, cert, SSL_FILETYPE_PEM)) {
			capwap_logging_debug("Error to load certificate file");
			capwap_socket_crypto_freecontext(context);
			return NULL;
		}

		/* Private key */
		if (!wolfSSL_CTX_use_PrivateKey_file(context, privatekey, SSL_FILETYPE_PEM)) {
			capwap_logging_debug("Error to load private key file");
			capwap_socket_crypto_freecontext(context);
			return NULL;
		}

		if (!wolfSSL_CTX_check_private_key(context)) {
			capwap_logging_debug("Error to check private key");
			capwap_socket_crypto_freecontext(context);
			return NULL;
		}

		/* Certificate Authority */
		if (!wolfSSL_CTX_load_verify_locations(context, calist, NULL)) {
			capwap_logging_debug("Error to load ca file");
			capwap_socket_crypto_freecontext(context);
			return NULL;
		}

		/* Verify certificate callback */
		wolfSSL_CTX_set_verify(context, SSL_VERIFY_PEER, capwap_socket_crypto_verifycertificate);

		/* Set only high security cipher list */
		if (!wolfSSL_CTX_set_cipher_list(context, "AES256-SHA")) {
			capwap_logging_debug("Error to select cipher list");
			capwap_socket_crypto_freecontext(context);
			return NULL;
		}
	}

	return (void*)context;
}

/* */
void capwap_socket_crypto_freecontext(void* context) {
	WOLFSSL_CTX* sslcontext = (WOLFSSL_CTX*)context;

	if (sslcontext) {
		wolfSSL_CTX_free(sslcontext);
	}
}

/* */
struct capwap_socket_ssl* capwap_socket_ssl_connect(int sock, void* sslcontext, int timeout) {
	int result;
	struct pollfd fds;
	struct capwap_socket_ssl* sslsock;

	ASSERT(sock >= 0);
	ASSERT(sslcontext != NULL);

	/* Create SSL session */
	sslsock = capwap_alloc(sizeof(struct capwap_socket_ssl));
	sslsock->sock = sock;
	sslsock->sslcontext = sslcontext;
	sslsock->sslsession = (void*)wolfSSL_new((WOLFSSL_CTX*)sslcontext);
	if (!sslsock->sslsession) {
		capwap_free(sslsock);
		return NULL;
	}

	/* Set socket to SSL session */
	if (!wolfSSL_set_fd((WOLFSSL*)sslsock->sslsession, sock)) {
		wolfSSL_free((WOLFSSL*)sslsock->sslsession);
		capwap_free(sslsock);
		return NULL;
	}

	/* */
	wolfSSL_set_using_nonblock((WOLFSSL*)sslsock->sslsession, 1);

	/* Establish SSL connection */
	for (;;) {
		result = wolfSSL_connect((WOLFSSL*)sslsock->sslsession);
		if (result == SSL_SUCCESS) {
			break;		/* Connection complete */
		} else {
			int error = wolfSSL_get_error((WOLFSSL*)sslsock->sslsession, 0);
			if ((error == SSL_ERROR_WANT_READ) || (error == SSL_ERROR_WANT_WRITE)) {
				memset(&fds, 0, sizeof(struct pollfd));
				fds.fd = sock;
				fds.events = ((error == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT);

				result = poll(&fds, 1, timeout);
				if (((result < 0) && (errno != EINTR)) || ((result > 0) && (fds.events != fds.revents))) {
					wolfSSL_free((WOLFSSL*)sslsock->sslsession);
					capwap_free(sslsock);
					return NULL;
				}
			} else {
				wolfSSL_free((WOLFSSL*)sslsock->sslsession);
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

	ASSERT(sslsock != NULL);
	ASSERT(sslsock->sslsession != NULL);
	ASSERT(sslsock->sock >= 0);
	ASSERT(buffer != NULL);
	ASSERT(length > 0);

	result = wolfSSL_write((WOLFSSL*)sslsock->sslsession, buffer, length);
	if (result != length) {
		return -1;
	}

	return length;
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
		result = wolfSSL_read((WOLFSSL*)sslsock->sslsession, buffer, length);
		if (result >= 0) {
			return result;
		} else {
			int error = wolfSSL_get_error((WOLFSSL*)sslsock->sslsession, 0);
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
		result = wolfSSL_shutdown((WOLFSSL*)sslsock->sslsession);
		if (result >= 0) {
			break;		/* Shutdown complete */
		} else {
			int error = wolfSSL_get_error((WOLFSSL*)sslsock->sslsession, 0);
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

	wolfSSL_free((WOLFSSL*)sslsock->sslsession);
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
