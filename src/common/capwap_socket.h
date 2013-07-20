#ifndef __CAPWAP_SOCKET_HEADER__
#define __CAPWAP_SOCKET_HEADER__

/* */
int capwap_socket_nonblocking(int sock, int nonblocking);

/* */
int capwap_socket_connect_timeout(int sock, struct sockaddr_storage* address, int timeout);
int capwap_socket_send_timeout(int sock, void* buffer, size_t length, int timeout);
int capwap_socket_recv_timeout(int sock, void* buffer, size_t length, int timeout);


#endif /* __CAPWAP_SOCKET_HEADER__ */
