#ifndef __CAPWAP_SOCKET_HEADER__
#define __CAPWAP_SOCKET_HEADER__

/* */
int capwap_socket_connect(int sock, union sockaddr_capwap* address, int timeout);
void capwap_socket_shutdown(int sock);
void capwap_socket_close(int sock);

/* Plain send/recv */
int capwap_socket_send(int sock, void* buffer, size_t length, int timeout);
int capwap_socket_recv(int sock, void* buffer, size_t length, int timeout);

/* SSL send/recv */
struct capwap_socket_ssl {
	int sock;
	void* sslcontext;
	void* sslsession;
};

void* capwap_socket_crypto_createcontext(char* calist, char* cert, char* privatekey);
void capwap_socket_crypto_freecontext(void* context);

int capwap_socket_crypto_send(struct capwap_socket_ssl* sslsock, void* buffer, size_t length, int timeout);
int capwap_socket_crypto_recv(struct capwap_socket_ssl* sslsock, void* buffer, size_t length, int timeout);

struct capwap_socket_ssl* capwap_socket_ssl_connect(int sock, void* sslcontext, int timeout);
void capwap_socket_ssl_shutdown(struct capwap_socket_ssl* sslsock, int timeout);
void capwap_socket_ssl_close(struct capwap_socket_ssl* sslsock);

#endif /* __CAPWAP_SOCKET_HEADER__ */
