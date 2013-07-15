#include "capwap.h"
#include "capwap_list.h"
#include "capwap_array.h"
#include "capwap_network.h"
#include "capwap_protocol.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <ifaddrs.h>

#define CAPWAP_ROUTE_NOT_FOUND			0
#define CAPWAP_ROUTE_LOCAL_ADDRESS		1
#define CAPWAP_ROUTE_VIA_ADDRESS		2

#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

/* Prepare socket to bind */
static int capwap_configure_socket(int sock, int socketfamily, int socketprotocol, int usebroadcast, char* bindinterface, int flags) {
	int flag;

	ASSERT(sock >= 0);
	ASSERT((socketfamily == AF_INET) || (socketfamily == AF_INET6));
	ASSERT((socketprotocol == IPPROTO_UDP) || (socketprotocol == IPPROTO_UDPLITE));

	/* Set correct value for IPv6 if dualstack is disabled */
	if ((socketfamily == AF_INET6) && ((flags & CAPWAP_IPV6ONLY_FLAG) != 0)) {
		int on = 1;
		int result;

		usebroadcast = 0;
		result = setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&on, sizeof(int));
		if (result) {
			capwap_logging_debug("Unable set IPV6_V6ONLY to socket");
			return -1;
		}
	}

	/* Reuse address */
	flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int))) {
		capwap_logging_debug("Unable set SO_REUSEADDR to socket");
		return -1;
	}

	/* Broadcast */
	if (usebroadcast) {
		flag = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &flag, sizeof(int))) {
			capwap_logging_debug("Unable set SO_BROADCAST to socket");
			return -1;
		}
	}

	/* Bind to interface */
	if ((bindinterface != NULL) && (bindinterface[0] != 0)) {
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, bindinterface, strlen(bindinterface) + 1)) {
			capwap_logging_debug("Unable set SO_BINDTODEVICE to socket %d", errno);	
			return -1;
		}
	}

	/* Disable checksum */
	if (socketprotocol == IPPROTO_UDPLITE) {
  		flag = 8;
  		if (setsockopt(sock, SOL_UDPLITE, UDPLITE_SEND_CSCOV, &flag, sizeof(int))) {
  			capwap_logging_debug("Unable set UDPLITE_SEND_CSCOV to socket");
  			return -1;
  		}
	} else if (socketfamily == AF_INET) {
		flag = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_NO_CHECK, &flag, sizeof(int))) {
			capwap_logging_debug("Unable set SO_NO_CHECK to socket");
			return -1;
		}
	}

	/* Retrieve information into sendto/recvfrom local address */
	if (socketfamily == AF_INET) {
#ifdef IP_PKTINFO
		flag = 1;
		if (setsockopt(sock, SOL_IP, IP_PKTINFO, &flag, sizeof(int))) {
			capwap_logging_debug("Unable set IP_PKTINFO to socket '%d'", errno);
			return -1;
		}
#elif defined IP_RECVDSTADDR
		flag = 1;
		if (setsockopt(sock, IPPROTO_IP, IP_RECVDSTADDR, &flag, sizeof(int))) {
			capwap_logging_debug("Unable set IP_RECVDSTADDR to socket '%d'", errno);
			return -1;
		}
#else
		#error "No method of getting the destination ip address supported"
#endif
	} else if (socketfamily == AF_INET6) {
		flag = 1;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &flag, sizeof(int))) {
			capwap_logging_debug("Unable set IPV6_RECVPKTINFO to socket '%d'", errno);
			return -1;
		}
	}

	return 0;
}

/* */
static void capwap_save_socket(struct capwap_network* net, int socketfamily, int socketprotocol, int sock_ctrl, int sock_data) {
	int index;
	
	ASSERT(net != NULL);
	ASSERT((socketfamily == AF_INET) || (socketfamily == AF_INET6));
	ASSERT((socketprotocol == IPPROTO_UDP) || (socketprotocol == IPPROTO_UDPLITE));
	ASSERT(sock_ctrl >= 0);
	ASSERT(sock_data >= 0);
	
	if (socketfamily == AF_INET) {
		if (socketprotocol == IPPROTO_UDP) {
			index = CAPWAP_SOCKET_IPV4_UDP;
		} else if (socketprotocol == IPPROTO_UDPLITE) {
			index = CAPWAP_SOCKET_IPV4_UDPLITE;
		}
	} else if (socketfamily == AF_INET6) {
		if (socketprotocol == IPPROTO_UDP) {
			index = CAPWAP_SOCKET_IPV6_UDP;
		} else if (socketprotocol == IPPROTO_UDPLITE) {
			index = CAPWAP_SOCKET_IPV6_UDPLITE;
		}
	}
	
	net->sock_ctrl[index] = sock_ctrl;
	net->sock_data[index] = sock_data;
}

/* Listen socket */
static int capwap_prepare_bind_socket(struct capwap_network* net, int socketfamily, int socketprotocol) {
	int result = 0;
	int sock_ctrl = -1;
	int sock_data = -1;
	struct sockaddr_storage bindaddr;

	ASSERT(net != NULL);
	ASSERT((socketfamily == AF_INET) || (socketfamily == AF_INET6));
	ASSERT((socketprotocol == IPPROTO_UDP) || (socketprotocol == IPPROTO_UDPLITE));
	
	/* */
	memset(&bindaddr, 0, sizeof(struct sockaddr_storage));
	bindaddr.ss_family = socketfamily;
	if (socketfamily == AF_INET) {
		((struct sockaddr_in*)(&bindaddr))->sin_addr.s_addr = INADDR_ANY;
	} else if (socketfamily == AF_INET6) {
		memset(&((struct sockaddr_in6*)(&bindaddr))->sin6_addr, 0, sizeof(struct in6_addr));
	}
	
	/* Control socket */
	sock_ctrl = socket(socketfamily, SOCK_DGRAM, socketprotocol);
	if (sock_ctrl >= 0) {
		if (!capwap_configure_socket(sock_ctrl, socketfamily, socketprotocol, 1, net->bind_interface, net->bind_ctrl_flags)) {
			/* Bind address */
			CAPWAP_SET_NETWORK_PORT(&bindaddr, net->bind_sock_ctrl_port);
			if (!bind(sock_ctrl, (struct sockaddr*)&bindaddr, sizeof(struct sockaddr_storage))) {
				/* Data socket */
				sock_data = socket(socketfamily, SOCK_DGRAM, socketprotocol);
				if (sock_data >= 0) {
					if (!capwap_configure_socket(sock_data, socketfamily, socketprotocol, 0, net->bind_interface, net->bind_data_flags)) {
						/* Bind address */
						CAPWAP_SET_NETWORK_PORT(&bindaddr, (!net->bind_sock_ctrl_port ? 0 : net->bind_sock_ctrl_port + 1));
						if (!bind(sock_data, (struct sockaddr*)&bindaddr, sizeof(struct sockaddr_storage))) {
							result = 1;
							capwap_save_socket(net, socketfamily, socketprotocol, sock_ctrl, sock_data);
						} else {
							close(sock_data);
							close(sock_ctrl);
						}
					} else {
						close(sock_data);
						close(sock_ctrl);
					}
				} else {
					close(sock_ctrl);
				}
			} else {
				close(sock_ctrl);
			}
		} else {
			close(sock_ctrl);
		}
	}
	
	
	return result;
}

/* */
int capwap_bind_sockets(struct capwap_network* net) {
	int bindipv4 = 1;
	
	ASSERT(net != NULL);
	
	if ((net->sock_family == AF_UNSPEC) || (net->sock_family == AF_INET6)) {
		/* UDP protocol */
		if (!capwap_prepare_bind_socket(net, AF_INET6, IPPROTO_UDP)) {
			return 0;
		}

		/* UDPLITE protocol */
		if (!capwap_prepare_bind_socket(net, AF_INET6, IPPROTO_UDPLITE)) {
			return 0;
		}
	
		/* Verify can use dual stack protocol */
		if ((net->bind_ctrl_flags & CAPWAP_IPV6ONLY_FLAG) == 0) {
			bindipv4 = 0;
		}
	}

	if (bindipv4 && ((net->sock_family == AF_UNSPEC) || (net->sock_family == AF_INET))) {
		if (!capwap_prepare_bind_socket(net, AF_INET, IPPROTO_UDP)) {
			return 0;
		}

		if (!capwap_prepare_bind_socket(net, AF_INET, IPPROTO_UDPLITE)) {
			return 0;
		}
	}
	
	return 1;
}

/* Get socket */
int capwap_get_socket(struct capwap_network* net, int socketfamily, int socketprotocol, int isctrlsocket) {
	int index;

	ASSERT(net != NULL);
	ASSERT((socketfamily == AF_INET) || (socketfamily == AF_INET6));
	ASSERT((socketprotocol == IPPROTO_UDP) || (socketprotocol == IPPROTO_UDPLITE));
	
	if (socketfamily == AF_INET) {
		if (socketprotocol == IPPROTO_UDP) {
			index = CAPWAP_SOCKET_IPV4_UDP;
		} else if (socketprotocol == IPPROTO_UDPLITE) {
			index = CAPWAP_SOCKET_IPV4_UDPLITE;
		}
	} else if (socketfamily == AF_INET6) {
		if (socketprotocol == IPPROTO_UDP) {
			index = CAPWAP_SOCKET_IPV6_UDP;
		} else if (socketprotocol == IPPROTO_UDPLITE) {
			index = CAPWAP_SOCKET_IPV6_UDPLITE;
		}
	}

	return (isctrlsocket ? net->sock_ctrl[index] : net->sock_data[index]);
}

/* Close socket */
void capwap_close_sockets(struct capwap_network* net) {
	int i;
	
	ASSERT(net != NULL);
		
	for (i = 0; i < CAPWAP_MAX_SOCKETS; i++) {
		if (net->sock_ctrl[i] >= 0) {
			shutdown(net->sock_ctrl[i], SHUT_RDWR);
			close(net->sock_ctrl[i]);
			net->sock_ctrl[i] = -1;
		}
		
		if (net->sock_data[i] >= 0) {
			shutdown(net->sock_data[i], SHUT_RDWR);
			close(net->sock_data[i]);
			net->sock_data[i] = -1;
		}
	}
}

/* Compare ip address */
int capwap_compare_ip(struct sockaddr_storage* addr1, struct sockaddr_storage* addr2) {
	ASSERT(addr1 != NULL);
	ASSERT(addr2 != NULL);

	if (addr1->ss_family == addr2->ss_family) {
		if (addr1->ss_family == AF_INET) {
			struct sockaddr_in* addr1_in = (struct sockaddr_in*)addr1;
			struct sockaddr_in* addr2_in = (struct sockaddr_in*)addr2;
			
			if (addr1_in->sin_addr.s_addr == addr2_in->sin_addr.s_addr) {
				if (addr1_in->sin_port == addr2_in->sin_port) {
					return 0;
				}
			}
		} else if (addr1->ss_family == AF_INET6) {
			struct sockaddr_in6* addr1_in6 = (struct sockaddr_in6*)addr1;
			struct sockaddr_in6* addr2_in6 = (struct sockaddr_in6*)addr2;

			if (!memcmp(&addr1_in6->sin6_addr, &addr2_in6->sin6_addr, sizeof(struct in6_addr))) {
				if (addr1_in6->sin6_port == addr2_in6->sin6_port) {
					return 0;
				}
			}
		}
	}
		
	return 1;
}

/* Receive packet with timeout */
int capwap_recvfrom(struct pollfd* fds, int fdscount, void* buffer, int* size, struct sockaddr_storage* recvfromaddr, struct sockaddr_storage* recvtoaddr, struct timeout_control* timeout) {
	int i;
	int polltimeout = -1;
	int readysocket;
	int result = CAPWAP_RECV_ERROR_SOCKET;
	
	ASSERT(fds);
	ASSERT(fdscount > 0);
	ASSERT(buffer != NULL);
	ASSERT(size != NULL);
	ASSERT(*size > 0);
	ASSERT(recvfromaddr != NULL);
	ASSERT(recvtoaddr != NULL);

	memset(recvfromaddr, 0, sizeof(struct sockaddr_storage));
	if (recvtoaddr) {
		memset(recvtoaddr, 0, sizeof(struct sockaddr_storage));
	}

	/* Check timeout */
	if (timeout) {
		long indextimer;
		
		capwap_update_timeout(timeout);
		polltimeout = capwap_get_timeout(timeout, &indextimer);
		if ((polltimeout <= 0) && (indextimer != CAPWAP_TIMER_UNDEF)) {
			return CAPWAP_RECV_ERROR_TIMEOUT;
		}
	}

	for (i = 0; i < fdscount; i++) {
		fds[i].revents = 0;
	}

	/* Wait event */
	readysocket = poll(fds, fdscount, polltimeout);
	if (readysocket > 0) {
		/* Get packet from only one socket */
		for (i = 0; i < fdscount; i++) {
			if ((fds[i].revents & POLLIN) != 0) {
				int packetsize = -1;
				socklen_t sendaddresslen = sizeof(struct sockaddr_storage);
				struct sockaddr_storage sockinfo;
				socklen_t sockinfolen = sizeof(struct sockaddr_storage);
				struct iovec iov;
				struct msghdr msgh;
				struct cmsghdr* cmsg;
				char cbuf[256];
				
				/* Information socket */
				memset(&sockinfo, 0, sizeof(struct sockaddr_storage));
				if (getsockname(fds[i].fd, (struct sockaddr*)&sockinfo, &sockinfolen) < 0) {
					break; 
				}

				iov.iov_base = buffer;
				iov.iov_len = *size;
				
				memset(&msgh, 0, sizeof(struct msghdr));
				msgh.msg_control = cbuf;
				msgh.msg_controllen = sizeof(cbuf);
				msgh.msg_name = recvfromaddr;
				msgh.msg_namelen = sendaddresslen;
				msgh.msg_iov = &iov;
				msgh.msg_iovlen = 1;
				msgh.msg_flags = 0;
				
				/* Receive packet with recvmsg */
				do {
					packetsize = recvmsg(fds[i].fd, &msgh, 0);
				} while ((packetsize < 0) && ((errno == EAGAIN) || (errno == EINTR)));
					
				if (packetsize > 0) {
					for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL; cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
#ifdef IP_PKTINFO
						if ((cmsg->cmsg_level == SOL_IP) && (cmsg->cmsg_type == IP_PKTINFO)) {
							struct in_pktinfo* i = (struct in_pktinfo*)CMSG_DATA(cmsg);
							struct sockaddr_in* addr = (struct sockaddr_in*)recvtoaddr;
							
							addr->sin_family = AF_INET;
							memcpy(&addr->sin_addr, &i->ipi_addr, sizeof(struct in_addr));
							addr->sin_port = ((struct sockaddr_in*)&sockinfo)->sin_port;
							
							break;
						}
#elif defined IP_RECVDSTADDR
						if ((cmsg->cmsg_level == IPPROTO_IP) && (cmsg->cmsg_type == IP_RECVDSTADDR)) {
							struct in_addr* i = (struct in_addr*)CMSG_DATA(cmsg);
							struct sockaddr_in* addr = (struct sockaddr_in*)recvtoaddr;
							
							addr->sin_family = AF_INET;
							memcpy(&addr->sin_addr, i, sizeof(struct in_addr));
							addr->sin_port = ((struct sockaddr_in*)&sockinfo)->sin_port;
							
							break;
						}
#else
						#error "No method of getting the destination ip address supported"
#endif
						if ((cmsg->cmsg_level == IPPROTO_IPV6) && ((cmsg->cmsg_type == IPV6_PKTINFO) || (cmsg->cmsg_type == IPV6_RECVPKTINFO))) {
							struct in6_pktinfo* i = (struct in6_pktinfo*)CMSG_DATA(cmsg);
							struct sockaddr_in6* addr = (struct sockaddr_in6*)recvtoaddr;
							
							addr->sin6_family = AF_INET6;
							memcpy(&addr->sin6_addr, &i->ipi6_addr, sizeof(struct in6_addr));
							addr->sin6_port = ((struct sockaddr_in6*)&sockinfo)->sin6_port;
							
							break;
						}
					}
				} else if (packetsize < 0) {
					break;
				}
				
				*size = packetsize;
				result = i;

				break;
			} else if ((fds[i].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
				break;
			}
		}
	} else if (readysocket == 0) {
		result = CAPWAP_RECV_ERROR_TIMEOUT;
		if (timeout) {
			/* Update timer for detect timeout */
			capwap_update_timeout(timeout);
		}
	} else {
		if (errno == EINTR) {
			result = CAPWAP_RECV_ERROR_INTR;
		}
	}

	return result;
}

/* */
void capwap_network_init(struct capwap_network* net) {
	int i;
	
	ASSERT(net != NULL);

	/* */
	memset(net, 0, sizeof(struct capwap_network));

	/* */
	net->sock_family = AF_UNSPEC;
	net->bind_sock_ctrl_port = INADDR_ANY;
	for (i = 0; i < CAPWAP_MAX_SOCKETS; i++) {
		net->sock_ctrl[i] = -1;
		net->sock_data[i] = -1;
	}
}

/* */
int capwap_network_set_pollfd(struct capwap_network* net, struct pollfd* fds, int fdscount) {
	int i;
	int j;
	int count = 0;
	
	ASSERT(net != NULL);
	ASSERT(fds != NULL);
	ASSERT(fdscount > 0);
	
	/* Count the socket */
	for (i = 0; i < CAPWAP_MAX_SOCKETS; i++) {
		if (net->sock_ctrl[i] >= 0) {
			ASSERT(net->sock_data[i] >= 0);
			count++;
		}
	}
	
	/* Check size of fds array */
	if (fdscount < (count * 2)) {
		return -1;
	}
		
	/* Configure fds array */
	for (i = 0, j = 0; i < CAPWAP_MAX_SOCKETS; i++) {
		if (net->sock_ctrl[i] >= 0) {
			fds[j].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
			fds[j].fd = net->sock_ctrl[i];
			fds[j + count].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
			fds[j + count].fd = net->sock_data[i];
			
			j++;
		}
	}
	
	return (count * 2);
}

/* */
void capwap_get_network_socket(struct capwap_network* net, struct capwap_socket* sock, int fd) {
	int i;
	
	ASSERT(net != NULL);
	ASSERT(sock != NULL);
	ASSERT(fd >= 0);

	for (i = 0; i < CAPWAP_MAX_SOCKETS; i++) {
		if (net->sock_ctrl[i] == fd) {
			sock->isctrlsocket = 1;
			switch (i) {
				case CAPWAP_SOCKET_IPV4_UDP: {
					sock->family = AF_INET;
					sock->type = CAPWAP_SOCKET_UDP;
					sock->socket[CAPWAP_SOCKET_UDP] = net->sock_ctrl[i];
					sock->socket[CAPWAP_SOCKET_UDPLITE] = net->sock_ctrl[i + 1];
					break;
				}
				
				case CAPWAP_SOCKET_IPV4_UDPLITE: {
					sock->family = AF_INET;
					sock->type = CAPWAP_SOCKET_UDPLITE;
					sock->socket[CAPWAP_SOCKET_UDP] = net->sock_ctrl[i - 1];
					sock->socket[CAPWAP_SOCKET_UDPLITE] = net->sock_ctrl[i];
					break;
				}

				case CAPWAP_SOCKET_IPV6_UDP: {
					sock->family = AF_INET6;
					sock->type = CAPWAP_SOCKET_UDP;
					sock->socket[CAPWAP_SOCKET_UDP] = net->sock_ctrl[i];
					sock->socket[CAPWAP_SOCKET_UDPLITE] = net->sock_ctrl[i + 1];
					break;
				}
				
				case CAPWAP_SOCKET_IPV6_UDPLITE: {
					sock->family = AF_INET6;
					sock->type = CAPWAP_SOCKET_UDPLITE;
					sock->socket[CAPWAP_SOCKET_UDP] = net->sock_ctrl[i - 1];
					sock->socket[CAPWAP_SOCKET_UDPLITE] = net->sock_ctrl[i];
					break;
				}
			}
			
			break;
		} else if (net->sock_data[i] == fd) {
			sock->isctrlsocket = 0;
			switch (i) {
				case CAPWAP_SOCKET_IPV4_UDP: {
					sock->family = AF_INET;
					sock->type = CAPWAP_SOCKET_UDP;
					sock->socket[CAPWAP_SOCKET_UDP] = net->sock_data[i];
					sock->socket[CAPWAP_SOCKET_UDPLITE] = net->sock_data[i + 1];
					break;
				}
				
				case CAPWAP_SOCKET_IPV4_UDPLITE: {
					sock->family = AF_INET;
					sock->type = CAPWAP_SOCKET_UDPLITE;
					sock->socket[CAPWAP_SOCKET_UDP] = net->sock_data[i - 1];
					sock->socket[CAPWAP_SOCKET_UDPLITE] = net->sock_data[i];
					break;
				}

				case CAPWAP_SOCKET_IPV6_UDP: {
					sock->family = AF_INET6;
					sock->type = CAPWAP_SOCKET_UDP;
					sock->socket[CAPWAP_SOCKET_UDP] = net->sock_data[i];
					sock->socket[CAPWAP_SOCKET_UDPLITE] = net->sock_data[i + 1];
					break;
				}
				
				case CAPWAP_SOCKET_IPV6_UDPLITE: {
					sock->family = AF_INET6;
					sock->type = CAPWAP_SOCKET_UDPLITE;
					sock->socket[CAPWAP_SOCKET_UDP] = net->sock_data[i - 1];
					sock->socket[CAPWAP_SOCKET_UDPLITE] = net->sock_data[i];
					break;
				}
			}
			
			break;
		}
	}
}

/* */
int capwap_sendto(int sock, void* buffer, int size, struct sockaddr_storage* sendfromaddr, struct sockaddr_storage* sendtoaddr) {
	int result;
	
	ASSERT(sock >= 0);
	ASSERT(buffer != NULL);
	ASSERT(size > 0);
	ASSERT(sendtoaddr != NULL);
	
	/* Information socket */
	if (!sendfromaddr) {
		do {
			result = sendto(sock, buffer, size, 0, (struct sockaddr*)sendtoaddr, sizeof(struct sockaddr_storage));
		} while ((result < 0) && ((errno == EAGAIN) || (errno == EINTR)));
	} else {
		struct msghdr msgh;
		struct cmsghdr* cmsg;
		struct iovec iov;
		char cbuf[256];
		
		/* */
		memset(&msgh, 0, sizeof(struct msghdr));
		iov.iov_base = buffer;
		iov.iov_len = size;
		msgh.msg_iov = &iov;
		msgh.msg_iovlen = 1;
		msgh.msg_name = sendtoaddr;
		msgh.msg_namelen = sizeof(struct sockaddr_storage);

		if (sendfromaddr->ss_family == AF_INET) {
			struct sockaddr_in* addr = (struct sockaddr_in*)sendfromaddr;

#ifdef IP_PKTINFO
			struct in_pktinfo* pkt;

			msgh.msg_control = cbuf;
			msgh.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

			cmsg = CMSG_FIRSTHDR(&msgh);
			cmsg->cmsg_level = SOL_IP;
			cmsg->cmsg_type = IP_PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

			pkt = (struct in_pktinfo*)CMSG_DATA(cmsg);
			memset(pkt, 0, sizeof(struct in_pktinfo));
			memcpy(&pkt->ipi_spec_dst, &addr->sin_addr, sizeof(struct in_addr));
#elif defined IP_RECVDSTADDR
			struct in_addr* in;

			msgh.msg_control = cbuf;
			msgh.msg_controllen = CMSG_SPACE(sizeof(struct in_addr));

			cmsg = CMSG_FIRSTHDR(&msgh);
			cmsg->cmsg_level = IPPROTO_IP;
			cmsg->cmsg_type = IP_SENDSRCADDR;
			cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));

			in = (struct in_addr*)CMSG_DATA(cmsg);
			memcpy(in, &addr->sin_addr, sizeof(struct in_addr));
#else
			#error "No method of getting the destination ip address supported"
#endif
		} else if (sendfromaddr->ss_family == AF_INET6) {
			struct in6_pktinfo* pkt;
			struct sockaddr_in6* addr = (struct sockaddr_in6*)sendfromaddr;

			msgh.msg_control = cbuf;
			msgh.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

			cmsg = CMSG_FIRSTHDR(&msgh);
			cmsg->cmsg_level = IPPROTO_IPV6;
			cmsg->cmsg_type = IPV6_PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

			pkt = (struct in6_pktinfo*)CMSG_DATA(cmsg);
			memset(pkt, 0, sizeof(struct in6_pktinfo));
			memcpy(&pkt->ipi6_addr, &addr->sin6_addr, sizeof(struct in6_addr));
		}

		do {
			result = sendmsg(sock, &msgh, 0);
		} while ((result < 0) && ((errno == EAGAIN) || (errno == EINTR)));   	
	}

	return ((result > 0) ? size : 0);
}

/* */
int capwap_sendto_fragmentpacket(int sock, struct capwap_list* fragmentlist, struct sockaddr_storage* sendfromaddr, struct sockaddr_storage* sendtoaddr) {
	struct capwap_list_item* item;

	ASSERT(sock >= 0);
	ASSERT(fragmentlist != NULL);
	ASSERT(sendtoaddr != NULL);

	item = fragmentlist->first;
	while (item) {
		struct capwap_fragment_packet_item* fragmentpacket = (struct capwap_fragment_packet_item*)item->item;
		ASSERT(fragmentpacket != NULL);
		ASSERT(fragmentpacket->offset > 0);

		if (!capwap_sendto(sock, fragmentpacket->buffer, fragmentpacket->offset, sendfromaddr, sendtoaddr)) {
			return 0;
		}

		/* */
		item = item->next;
	}

	return 1;
}

/* */
int capwap_ipv4_mapped_ipv6(struct sockaddr_storage* source, struct sockaddr_storage* dest) {
	ASSERT(source != NULL);
	ASSERT(dest != NULL);

	memset(dest, 0, sizeof(struct sockaddr_storage));
	
	if (source->ss_family == AF_INET) {
		struct sockaddr_in* addripv4 = (struct sockaddr_in*)source;
		struct sockaddr_in6* addripv6 = (struct sockaddr_in6*)dest;
		
		addripv6->sin6_family = AF_INET6;
		((unsigned long*)&addripv6->sin6_addr)[2] = htonl(0xffff);
		memcpy(&((unsigned long*)&addripv6->sin6_addr)[3], &addripv4->sin_addr, sizeof(unsigned long));
		addripv6->sin6_port = addripv4->sin_port;
		
		return 1;
	} else if (source->ss_family == AF_INET6) {
		struct sockaddr_in6* addripv6 = (struct sockaddr_in6*)source;
		struct sockaddr_in* addripv4 = (struct sockaddr_in*)dest;

		if (IN6_IS_ADDR_V4MAPPED(&addripv6->sin6_addr)) {
			addripv4->sin_family = AF_INET;
			memcpy(&addripv4->sin_addr, &((unsigned long*)&addripv6->sin6_addr)[3], sizeof(unsigned long));
			addripv4->sin_port = addripv6->sin6_port;
			
			return 1;
		}		
	}
	
	return 0;
}

/* Convert string into address */
int capwap_address_from_string(const char* ip, struct sockaddr_storage* address) {
	char* pos;
	char* buffer;
	struct addrinfo hints;
	struct addrinfo* info = NULL;
	char* service = NULL;

	ASSERT(ip != NULL);
	ASSERT(address != NULL);

	/* Init */
	memset(address, 0, sizeof(struct sockaddr_storage));
	if (!*ip) {
		return 0;
	}

	/* */
	buffer = capwap_duplicate_string(ip);

	/* */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = 0;

	/* Parsing address */
	pos = buffer;
	if (*pos == '[') {
		char* temp = pos + 1;

		pos = temp;
		hints.ai_family = AF_INET6;
		hints.ai_flags |= AI_NUMERICHOST;

		temp = strchr(temp, ']');
		if (!temp) {
			capwap_free(buffer);
			return 0;
		}

		*temp = 0;
		if (*(temp + 1) == ':') {
			service = temp + 2;
			hints.ai_flags |= AI_NUMERICSERV;
		} else if (*(temp + 1)) {
			capwap_free(buffer);
			return 0;
		}
	} else {
		char* temp = strchr(pos, ':');
		if (temp) {
			*temp = 0;
			service = temp + 1;
			hints.ai_flags |= AI_NUMERICSERV;
		}
	}

	/* Parsing address */
	if (getaddrinfo(pos, service, &hints, &info)) {
		capwap_free(buffer);
		return 0;
	}

	/* Copy address */
	memcpy(address, info->ai_addr, info->ai_addrlen);

	freeaddrinfo(info);
	capwap_free(buffer);

	return 1;
}

/* Get macaddress from interface */
int capwap_get_macaddress_from_interface(const char* interface, char* macaddress) {
	int sock;
	struct ifreq ifr;
	int result = 0;

	ASSERT(interface != NULL);
	ASSERT(macaddress != NULL);

	sock = socket(PF_PACKET, SOCK_RAW, 0);
	if (sock < 0) {
		return 0;
	}
	
	memset(&ifr, 0, sizeof(struct ifreq));
	strcpy(ifr.ifr_name, interface);
	
	if (!ioctl(sock, SIOCGIFHWADDR, &ifr)) {
		result = ((ifr.ifr_hwaddr.sa_family == ARPHRD_EUI64) ? MACADDRESS_EUI64_LENGTH : MACADDRESS_EUI48_LENGTH);
		memcpy(macaddress, ifr.ifr_hwaddr.sa_data, result);
	}
	
	close(sock);
	return result;
}

/* */
static void capwap_get_network_address(struct sockaddr_storage* addr, struct sockaddr_storage* network, unsigned long bitsmask) {
	unsigned long i;
	
	ASSERT(addr != NULL);
	ASSERT(network != NULL);

	memcpy(network, addr, sizeof(struct sockaddr_storage));

	if (addr->ss_family == AF_INET) {
		unsigned long mask = 0xffffffff;
		struct sockaddr_in* ipv4addr = (struct sockaddr_in*)network;

		for (i = bitsmask; i < 32; i++) {
			mask <<= 1;
		}

		ipv4addr->sin_addr.s_addr &= htonl(mask);
	} else {
		unsigned long pos = bitsmask / 8;
		unsigned long delta = bitsmask % 8;
		struct sockaddr_in6* ipv6addr = (struct sockaddr_in6*)network;
		
		if (!delta) {
			pos -= 1;	/* Optimize for all bits of pos equal 0 */
		} else {
			unsigned char mask = 0xff;

			for (i = delta; i < 8; i++) {
				mask <<= 1;
			}
			
			ipv6addr->sin6_addr.s6_addr[pos] &= mask;
		}
		
		for (i = pos + 1; i < 16; i++) {
			ipv6addr->sin6_addr.s6_addr[i] = 0;
		}
	}
}

/* */
static int capwap_equal_address(struct sockaddr_storage* addr1, struct sockaddr_storage* addr2) {
	ASSERT(addr1 != NULL);
	ASSERT(addr2 != NULL);
	
	if (addr1->ss_family == addr2->ss_family) {
		if (addr1->ss_family == AF_INET) {
			if (((struct sockaddr_in*)addr1)->sin_addr.s_addr == ((struct sockaddr_in*)addr2)->sin_addr.s_addr) {
				return 1;
			}
		} else if (addr1->ss_family == AF_INET6) {
			int i;
			struct in6_addr* ipv6addr1 = &((struct sockaddr_in6*)addr1)->sin6_addr;
			struct in6_addr* ipv6addr2 = &((struct sockaddr_in6*)addr2)->sin6_addr;
			
			for (i = 0; i < 16; i++) {
				if (ipv6addr1->s6_addr[i] != ipv6addr2->s6_addr[i]) {
					return 0;
				}
			}
			
			return 1;
		}
	}
	
	return 0;
}

/* */
static int capwap_get_routeaddress(struct sockaddr_storage* local, struct sockaddr_storage* remote, char* oif, int ipv6dualstack, unsigned char table) {
	int result = 0;
	int end = 0;
	
	int foundgateway = 0;
	unsigned char gatewaytable = 0;
	unsigned long gatewaymetric = 0;
	struct sockaddr_storage gateway;

	int nlsock;
	struct sockaddr_nl nllocal;
	socklen_t nllocaladdrlen;
	int sndbuf = 32768;
	int rcvbuf = 32768;
	
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	ASSERT(local != NULL);
	ASSERT(remote != NULL);

	/* Open netlink route socket */
	nlsock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nlsock < 0) {
		capwap_logging_debug("Cannot open netlink socket");
		return 0;
	}

	/* Configure socket */	
	if (setsockopt(nlsock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(int)) < 0) {
		capwap_logging_debug("Cannot set SO_SNDBUF");
		close(nlsock);
		return 0;
	}

	if (setsockopt(nlsock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(int)) < 0) {
		capwap_logging_debug("Cannot set SO_RCVBUF");
		close(nlsock);
		return 0;
	}
	
	/* Bind */
	memset(&nllocal, 0, sizeof(struct sockaddr_nl));
	nllocal.nl_family = AF_NETLINK;
	if (bind(nlsock, (struct sockaddr*)&nllocal, sizeof(struct sockaddr_nl)) < 0) {
		capwap_logging_debug("Cannot bind netlink socket");
		close(nlsock);
		return 0;
	}

	/* Check bind */
	nllocaladdrlen = sizeof(struct sockaddr_nl);
	if (getsockname(nlsock, (struct sockaddr*)&nllocal, &nllocaladdrlen) < 0) {
		capwap_logging_debug("Cannot getsockname");
		close(nlsock);
		return 0;
	}

	if ((nllocaladdrlen != sizeof(struct sockaddr_nl)) || (nllocal.nl_family != AF_NETLINK)) {
		capwap_logging_debug("Wrong bind netlink socket");
		close(nlsock);
		return 0;
	}

	/* Send request */
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETROUTE;
	req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = 0;
	req.g.rtgen_family = AF_UNSPEC;
	
	if (send(nlsock, (void*)&req, sizeof(req), 0) == sizeof(req)) {
		struct sockaddr_nl nladdr;
		struct iovec iov;
		char buf[16384];
		struct msghdr msg = {
			.msg_name = &nladdr,
			.msg_namelen = sizeof(struct sockaddr_nl),
			.msg_iov = &iov,
			.msg_iovlen = 1,
		};
	
		iov.iov_base = buf;
		while (!result && !end) {
			int status;
			struct nlmsghdr *h;
	
			/* Receive response */
			iov.iov_len = sizeof(buf);
			status = recvmsg(nlsock, &msg, 0);
			if (status < 0) {
				if ((errno == EINTR) || (errno == EAGAIN))
					continue;

				capwap_logging_debug("Error from netlink socket: %d", errno);
				break;
			} else if (status == 0) {
				capwap_logging_debug("Receive EOF by netlink socket");
				break;
			}
			
			/* Parsing message */
			h = (struct nlmsghdr*)buf;
			while (NLMSG_OK(h, status)) {
				if ((h->nlmsg_pid == nllocal.nl_pid) && (h->nlmsg_seq == 0)) {
					if ((h->nlmsg_type == NLMSG_DONE) || (h->nlmsg_type == NLMSG_ERROR)) {
						end = 1;
						break;
					} else if (h->nlmsg_type == RTM_NEWROUTE) {
						struct rtmsg* r = NLMSG_DATA(h);
						int len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));

						/* Accept only address IPv4 or IPv6 from main table route */
						if ((len >= 0) && (!table || (r->rtm_table == table)) && (remote->ss_family == r->rtm_family)) {
							struct rtattr* tb[RTA_MAX + 1];
							struct rtattr* rta = RTM_RTA(r);
							int addrsize = ((r->rtm_family == AF_INET) ? sizeof(struct in_addr) : sizeof(struct in6_addr));
							int defaultgateway = 0;
							struct sockaddr_storage dest;
							int destmask = r->rtm_dst_len;
							char ifname[IFNAMSIZ + 1];

							/* Parsing rtattr */
							memset(tb, 0, sizeof(struct rtattr*) * (RTA_MAX + 1));
							while (RTA_OK(rta, len)) {
								if (rta->rta_type <= RTA_MAX) {
									tb[rta->rta_type] = rta;
								}
								
								rta = RTA_NEXT(rta, len);
							}
							
							/* Get device name */
							if (tb[RTA_OIF]) {
								if (!if_indextoname(*(int*)RTA_DATA(tb[RTA_OIF]), ifname)) {
									ifname[0] = 0;
								}
							} else {
								ifname[0] = 0;
							}
							
							if (!oif || !strcmp(ifname, oif)) {
								/* Destination network */
								memset(&dest, 0, sizeof(struct sockaddr_storage));
								dest.ss_family = r->rtm_family;
								
								if (tb[RTA_DST]) {
									void* buffer = ((r->rtm_family == AF_INET) ? (void*)&((struct sockaddr_in*)&dest)->sin_addr : (void*)&((struct sockaddr_in6*)&dest)->sin6_addr);
									
									memcpy(buffer, RTA_DATA(tb[RTA_DST]), addrsize);
								} else if (!r->rtm_dst_len) {
									defaultgateway = 1;
								}
	
								/* Check network */
								if (defaultgateway) {
									if (tb[RTA_GATEWAY]) {
										int update = 0;
										unsigned long metric = (tb[RTA_PRIORITY] ? *(unsigned long*)RTA_DATA(tb[RTA_PRIORITY]) : 0);
										
										/* Detect primary route */
										if (gatewaytable < r->rtm_table) {
											update = 1;
										} else if ((gatewaytable == r->rtm_table) && (gatewaymetric > metric)) {
											update = 1;
										}
										
										if (update) {
											void* buffer = (void*)((r->rtm_family == AF_INET) ? (void*)&(((struct sockaddr_in*)&gateway)->sin_addr) : (void*)&(((struct sockaddr_in6*)&gateway)->sin6_addr));
											
											foundgateway = 1;
											gatewaytable = r->rtm_table;
											gatewaymetric = metric;
											
											memset(&gateway, 0, sizeof(struct sockaddr_storage));
											gateway.ss_family = r->rtm_family;
											memcpy(buffer, RTA_DATA(tb[RTA_GATEWAY]), addrsize);
										}
									}
								} else if (tb[RTA_PREFSRC]) {
									struct sockaddr_storage remotenetwork;
									struct sockaddr_storage destnework;
	
									capwap_get_network_address(remote, &remotenetwork, destmask);
									capwap_get_network_address(&dest, &destnework, destmask);
									
									if (capwap_equal_address(&remotenetwork, &destnework)) {
										void* buffer = (void*)((r->rtm_family == AF_INET) ? (void*)&(((struct sockaddr_in*)local)->sin_addr) : (void*)&(((struct sockaddr_in6*)local)->sin6_addr));
	
										result = CAPWAP_ROUTE_LOCAL_ADDRESS;
										memset(local, 0, sizeof(struct sockaddr_storage));
										local->ss_family = r->rtm_family;
										memcpy(buffer, RTA_DATA(tb[RTA_PREFSRC]), addrsize);
										
										break;
									}
								}
							}
						}
					}
				}
				
				h = NLMSG_NEXT(h, status);
			}
		}
	}

	/* */
	if (!result && foundgateway) {
		result = CAPWAP_ROUTE_VIA_ADDRESS;
		memcpy(local, &gateway, sizeof(struct sockaddr_storage));
	}

	/* */	
	close(nlsock);
	return ((result > 0) ? result : 0);
}

/* Get interface flags */
static short capwap_get_interface_flags(char* iface) {
	int sock;
	struct ifreq req;
	
	ASSERT(iface != NULL);
	ASSERT(iface[0] != 0);
	
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0) {
		return 0;
	}

	strcpy(req.ifr_name, iface);
    if (ioctl(sock, SIOCGIFFLAGS, &req) < 0) {
    	req.ifr_flags = 0;
    }

	close(sock);
	
	return req.ifr_flags;
}

/* Return local address from remote address */
int capwap_get_localaddress_by_remoteaddress(struct sockaddr_storage* local, struct sockaddr_storage* remote, char* oif, int ipv6dualstack) {
	int result;
	struct sockaddr_storage remotenorm;
	
	ASSERT(local != NULL);
	ASSERT(remote != NULL);
	
	/* Check output interface */
	if (oif && !strlen(oif)) {
		oif = NULL;
	}

	/* Loopback address */
	if (remote->ss_family == AF_INET) {
		if (((struct sockaddr_in*)remote)->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
			if (!oif || ((capwap_get_interface_flags(oif) & IFF_LOOPBACK) == IFF_LOOPBACK)) {
				memset(local, 0, sizeof(struct sockaddr_storage));
				
				local->ss_family = AF_INET;
				((struct sockaddr_in*)local)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
				
				return 1;
			} else {
				return 0;
			}
		}
	} else if (remote->ss_family == AF_INET6) {
		if (!memcmp(&((struct sockaddr_in6*)remote)->sin6_addr, &in6addr_loopback, sizeof(struct in6_addr))) {
			if (!oif || ((capwap_get_interface_flags(oif) & IFF_LOOPBACK) == IFF_LOOPBACK)) {
				memset(local, 0, sizeof(struct sockaddr_storage));
				
				local->ss_family = AF_INET6;
				memcpy(&((struct sockaddr_in6*)local)->sin6_addr, &in6addr_loopback, sizeof(struct in6_addr));
				
				return 1;
			} else {
				return 0;
			}
		}
	}

	/* Normalize ip address if a ipv4 mapped */
	if (ipv6dualstack && (remote->ss_family == AF_INET6)) {
		if (capwap_ipv4_mapped_ipv6(remote, &remotenorm)) {
			remote = &remotenorm;
		}
	}
	
	/* Get address */
	result = capwap_get_routeaddress(local, remote, oif, ipv6dualstack, RT_TABLE_MAIN);
	if (result == CAPWAP_ROUTE_NOT_FOUND) {
		return 0;
	} else if (result == CAPWAP_ROUTE_VIA_ADDRESS) {
		struct sockaddr_storage temp;
		
		result = capwap_get_routeaddress(&temp, local, oif, ipv6dualstack, RT_TABLE_MAIN);
		if (result == CAPWAP_ROUTE_NOT_FOUND) {
			return 0;
		}

		ASSERT(result == CAPWAP_ROUTE_LOCAL_ADDRESS);
		memcpy(local, &temp, sizeof(struct sockaddr_storage));
	}
		
	return 1;
}

/* Retrieve interface list */
void capwap_interface_list(struct capwap_network* net, struct capwap_list* list) {
	struct ifaddrs* ifaddrlist;
	struct ifaddrs* ifcurrentpos;

	ASSERT(net != NULL);
	ASSERT(list != NULL);

	/* Get interface list */
	if (getifaddrs(&ifaddrlist) != 0) {
		return;
	}

	/* */
	for (ifcurrentpos = ifaddrlist; ifcurrentpos != NULL; ifcurrentpos = ifcurrentpos->ifa_next) {
		struct capwap_list_item* item;
		struct sockaddr_storage* addr;

		/* No loopback interface */
		if ((ifcurrentpos->ifa_flags & IFF_LOOPBACK) != 0) {
			continue;
		}

		/* Only IPv4 and IPv6 */
		if ((ifcurrentpos->ifa_addr == NULL) || ((ifcurrentpos->ifa_addr->sa_family != AF_INET) && (ifcurrentpos->ifa_addr->sa_family != AF_INET6))) {
			continue;
		}

		/* Filter family */
		if ((net->sock_family != AF_UNSPEC) && (net->sock_family != ifcurrentpos->ifa_addr->sa_family)) {
			continue;
		}

		/* Filter interface */
		if ((net->bind_interface[0] != 0) && (strcmp(net->bind_interface, ifcurrentpos->ifa_name) != 0)) {
			continue;
		}

		/* Add local address */
		item = capwap_itemlist_create(sizeof(struct sockaddr_storage));
		addr = (struct sockaddr_storage*)item->item;

		memset(addr, 0, sizeof(struct sockaddr_storage));
		addr->ss_family = ifcurrentpos->ifa_addr->sa_family;
		CAPWAP_SET_NETWORK_PORT(addr, net->bind_sock_ctrl_port);

		if (addr->ss_family == AF_INET) {
			memcpy(&((struct sockaddr_in*)addr)->sin_addr, &((struct sockaddr_in*)ifcurrentpos->ifa_addr)->sin_addr, sizeof(struct in_addr));
		} else if (addr->ss_family == AF_INET6) {
			memcpy(&((struct sockaddr_in6*)addr)->sin6_addr, &((struct sockaddr_in6*)ifcurrentpos->ifa_addr)->sin6_addr, sizeof(struct in6_addr));
		}

		/* Add address */
		capwap_itemlist_insert_after(list, NULL, item);
	}

	/* Free */
	freeifaddrs(ifaddrlist);	
}
