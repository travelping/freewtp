#ifndef __CAPWAP_NETWORK_HEADER__
#define __CAPWAP_NETWORK_HEADER__

#include "capwap_array.h"
#include "capwap_list.h"

/* Standard Configuration */
#define CAPWAP_CONTROL_PORT					5246
#define CAPWAP_MAX_PACKET_SIZE				65535

/* */
#define CAPWAP_MACADDRESS_EUI48_BUFFER		18
#define CAPWAP_MACADDRESS_EUI64_BUFFER		24
#define CAPWAP_MAX_FQDN_SIZE                256

/* */
union sockaddr_capwap {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr_storage ss;
};

struct addr_capwap {
	char fqdn[CAPWAP_MAX_FQDN_SIZE];
	union sockaddr_capwap sockaddr;
	char resolved;
};

/* Helper */
#define CAPWAP_GET_NETWORK_PORT(addr)						ntohs((((addr)->ss.ss_family == AF_INET) ? (addr)->sin.sin_port : (((addr)->ss.ss_family == AF_INET6) ? (addr)->sin6.sin6_port : 0)))
#define CAPWAP_SET_NETWORK_PORT(addr, port)					if ((addr)->ss.ss_family == AF_INET) {							\
																(addr)->sin.sin_port = htons(port);							\
															} else if ((addr)->ss.ss_family == AF_INET6) {					\
																(addr)->sin6.sin6_port = htons(port);						\
															}
#define CAPWAP_COPY_NETWORK_PORT(addr1, addr2)				if ((addr1)->ss.ss_family == (addr2)->ss.ss_family) {			\
																if ((addr1)->ss.ss_family == AF_INET) {						\
																	(addr1)->sin.sin_port = (addr2)->sin.sin_port;			\
																} else if ((addr1)->ss.ss_family == AF_INET6) {				\
																	(addr1)->sin6.sin6_port = (addr2)->sin6.sin6_port;		\
																}															\
															}

/* */
#define CAPWAP_RECV_ERROR_SOCKET		-1
#define CAPWAP_RECV_ERROR_TIMEOUT		-2
#define CAPWAP_RECV_ERROR_INTR			-3

/* Network struct */
struct capwap_network {
	union sockaddr_capwap localaddr;
	char bindiface[IFNAMSIZ];
	int socket;
};

void capwap_network_init(struct capwap_network* net);

int capwap_network_set_pollfd(struct capwap_network* net, struct pollfd* fds, int fdscount);
void capwap_interface_list(struct capwap_network* net, struct capwap_list* list);

int capwap_get_macaddress_from_interface(const char* interface, char* macaddress);
int capwap_network_get_localaddress(union sockaddr_capwap* localaddr, union sockaddr_capwap* peeraddr, char* iface);

int capwap_bind_sockets(struct capwap_network* net);
int capwap_connect_socket(struct capwap_network* net, union sockaddr_capwap *peeraddr);
void capwap_close_sockets(struct capwap_network* net);

int capwap_getsockname(struct capwap_network* net, union sockaddr_capwap *addr);

int capwap_ipv4_mapped_ipv6(union sockaddr_capwap* addr);
int capwap_compare_ip(union sockaddr_capwap* addr1, union sockaddr_capwap* addr2);

int capwap_sendto(int sock, void* buffer, int size, union sockaddr_capwap* toaddr);
int capwap_sendto_fragmentpacket(int sock, struct capwap_list* fragmentlist, union sockaddr_capwap* toaddr);

int capwap_wait_recvready(struct pollfd* fds, int fdscount, struct capwap_timeout* timeout);
int capwap_recvfrom(int sock, void* buffer, int* size, union sockaddr_capwap* fromaddr, union sockaddr_capwap* toaddr);

int capwap_address_from_string(const char* ip, union sockaddr_capwap* sockaddr);
const char* capwap_address_to_string(union sockaddr_capwap* sockaddr, char* ip, int len);

char* capwap_printf_macaddress(char* buffer, const uint8_t* macaddress, int type);
int capwap_scanf_macaddress(uint8_t* macaddress, const char* buffer, int type);

#endif /* __CAPWAP_NETWORK_HEADER__ */
