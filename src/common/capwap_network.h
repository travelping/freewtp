#ifndef __CAPWAP_NETWORK_HEADER__
#define __CAPWAP_NETWORK_HEADER__

#include "capwap_array.h"
#include "capwap_list.h"

/* Standard Configuration */
#define CAPWAP_CONTROL_PORT					5246
#define CAPWAP_MAX_PACKET_SIZE				65535

#define CAPWAP_MACADDRESS_NONE				0
#define CAPWAP_MACADDRESS_EUI48				6
#define CAPWAP_MACADDRESS_EUI64				8
#define CAPWAP_MACADDRESS_MAX_SIZE			CAPWAP_MACADDRESS_EUI64

/* Helper */
#define CAPWAP_GET_NETWORK_PORT(address)					ntohs((((address)->ss_family == AF_INET) ? ((struct sockaddr_in*)(address))->sin_port : ((struct sockaddr_in6*)(address))->sin6_port))
#define CAPWAP_SET_NETWORK_PORT(address, port)				if ((address)->ss_family == AF_INET) {								\
																((struct sockaddr_in*)(address))->sin_port = htons(port);		\
															} else if ((address)->ss_family == AF_INET6) {						\
																((struct sockaddr_in6*)(address))->sin6_port = htons(port);		\
															}

/* */
#define CAPWAP_MAX_SOCKETS				4
#define CAPWAP_SOCKET_IPV4_UDP			0
#define CAPWAP_SOCKET_IPV4_UDPLITE		1
#define CAPWAP_SOCKET_IPV6_UDP			2
#define CAPWAP_SOCKET_IPV6_UDPLITE		3

/* */
#define CAPWAP_RECV_ERROR_SOCKET		-1
#define CAPWAP_RECV_ERROR_TIMEOUT		-2
#define CAPWAP_RECV_ERROR_INTR			-3

/* Socket Flags */
#define CAPWAP_IPV6ONLY_FLAG			0x00000001

/* Network struct */
struct capwap_network {
	int sock_family;							/* Address family used by the server. */
	unsigned short bind_sock_ctrl_port;			/* Port number to listen control protocol. */
	char bind_interface[IFNAMSIZ];
	
	int sock_ctrl[CAPWAP_MAX_SOCKETS];
	int bind_ctrl_flags;
	
	int sock_data[CAPWAP_MAX_SOCKETS];
	int bind_data_flags;
};

#define CAPWAP_SOCKET_UDP				0
#define CAPWAP_SOCKET_UDPLITE			1

/* Network socket */
struct capwap_socket {
	int type;
	int family;
	int socket[2];
	int isctrlsocket;
};

void capwap_network_init(struct capwap_network* net);
int capwap_network_set_pollfd(struct capwap_network* net, struct pollfd* fds, int fdscount);
void capwap_interface_list(struct capwap_network* net, struct capwap_list* list);

int capwap_get_macaddress_from_interface(const char* interface, char* macaddress);

#define CAPWAP_DATA_SOCKET			0
#define CAPWAP_CTRL_SOCKET			1
int capwap_get_socket(struct capwap_network* net, int socketfamily, int socketprotocol, int isctrlsocket);
void capwap_get_network_socket(struct capwap_network* net, struct capwap_socket* sock, int fd);

int capwap_bind_sockets(struct capwap_network* net);
void capwap_close_sockets(struct capwap_network* net);

int capwap_compare_ip(struct sockaddr_storage* addr1, struct sockaddr_storage* addr2);

int capwap_sendto(int sock, void* buffer, int size, struct sockaddr_storage* sendfromaddr, struct sockaddr_storage* sendtoaddr);
int capwap_recvfrom(struct pollfd* fds, int fdscount, void* buffer, int* size, struct sockaddr_storage* recvfromaddr, struct sockaddr_storage* recvtoaddr, struct timeout_control* timeout);

int capwap_ipv4_mapped_ipv6(struct sockaddr_storage* source, struct sockaddr_storage* dest);
int capwap_address_from_string(const char* ip, struct sockaddr_storage* address);

int capwap_get_localaddress_by_remoteaddress(struct sockaddr_storage* local, struct sockaddr_storage* remote, char* oif, int ipv6dualstack);

#endif /* __CAPWAP_NETWORK_HEADER__ */
