#include "capwap.h"
#include "capwap_network.h"
#include "capwap_protocol.h"
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

/* */
#define CAPWAP_ROUTE_NOT_FOUND				0
#define CAPWAP_ROUTE_LOCAL_ADDRESS			1
#define CAPWAP_ROUTE_VIA_ADDRESS			2

/* Prepare socket to bind */
static int capwap_configure_socket(int sock, int socketfamily, const char* bindinterface) {
	int flag;

	ASSERT(sock >= 0);
	ASSERT((socketfamily == AF_INET) || (socketfamily == AF_INET6));

	/* Retrieve information into recvfrom local address */
	if (socketfamily == AF_INET) {
#ifdef IP_PKTINFO
		flag = 1;
		if (setsockopt(sock, SOL_IP, IP_PKTINFO, &flag, sizeof(int))) {
			capwap_logging_error("Unable set IP_PKTINFO to socket '%d'", errno);
			return -1;
		}
#elif defined IP_RECVDSTADDR
		flag = 1;
		if (setsockopt(sock, IPPROTO_IP, IP_RECVDSTADDR, &flag, sizeof(int))) {
			capwap_logging_error("Unable set IP_RECVDSTADDR to socket '%d'", errno);
			return -1;
		}
#else
		#error "No method of getting the destination ip address supported"
#endif
	} else if (socketfamily == AF_INET6) {
		flag = 1;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &flag, sizeof(int))) {
			capwap_logging_error("Unable set IPV6_RECVPKTINFO to socket '%d'", errno);
			return -1;
		}
	}

	/* Reuse address */
	flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int))) {
		capwap_logging_error("Unable set SO_REUSEADDR to socket");
		return -1;
	}

	/* Broadcast */
	flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &flag, sizeof(int))) {
		capwap_logging_error("Unable set SO_BROADCAST to socket");
		return -1;
	}

	/* Bind to interface */
	if ((bindinterface != NULL) && (bindinterface[0] != 0)) {
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, bindinterface, strlen(bindinterface) + 1)) {
			capwap_logging_error("Unable set SO_BINDTODEVICE to socket %d", errno);	
			return -1;
		}
	}

	/* Disable checksum */
	if (socketfamily == AF_INET) {
		flag = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_NO_CHECK, &flag, sizeof(int))) {
			capwap_logging_error("Unable set SO_NO_CHECK to socket");
			return -1;
		}
	}

	return 0;
}

/* Listen socket */
static int capwap_prepare_bind_socket(struct capwap_network* net) {
	int sock;

	ASSERT(net != NULL);
	ASSERT((net->localaddr.ss.ss_family == AF_INET) || (net->localaddr.ss.ss_family == AF_INET6));

	/* Create socket */
	sock = socket(net->localaddr.ss.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		return -1;
	}

	/* Prepare binding */
	if (capwap_configure_socket(sock, net->localaddr.ss.ss_family, net->bindiface)) {
		close(sock);
		return -1;
	}

	/* Binding */
	if (bind(sock, &net->localaddr.sa, sizeof(union sockaddr_capwap))) {
		close(sock);
		return -1;
	}

	/* Retrieve port */
	if (!CAPWAP_GET_NETWORK_PORT(&net->localaddr)) {
		union sockaddr_capwap sockinfo;
		socklen_t sockinfolen = sizeof(union sockaddr_capwap);

		if (getsockname(sock, &sockinfo.sa, &sockinfolen) < 0) {
			close(sock);
			return -1;
		}

		/* */
		CAPWAP_COPY_NETWORK_PORT(&net->localaddr, &sockinfo);
	}

	/* */
	net->socket = sock;
	return 0;
}

/* */
int capwap_bind_sockets(struct capwap_network* net) {
	int result;

	ASSERT(net != NULL);
	ASSERT((net->localaddr.ss.ss_family == AF_INET) || (net->localaddr.ss.ss_family == AF_INET6));

	/* */
	result = capwap_prepare_bind_socket(net);
	if (result && net->localaddr.ss.ss_family == AF_INET6) {
		uint16_t port = net->localaddr.sin6.sin6_port;

		net->localaddr.ss.ss_family = AF_INET;
		net->localaddr.sin.sin_port = port;

		result = capwap_prepare_bind_socket(net);
	}

	return result;
}

/* Close socket */
void capwap_close_sockets(struct capwap_network* net) {
	ASSERT(net != NULL);

	if (net->socket >= 0) {
		shutdown(net->socket, SHUT_RDWR);
		close(net->socket);
		net->socket = -1;
	}
}

/* */
int capwap_ipv4_mapped_ipv6(union sockaddr_capwap* addr) {
	unsigned long inetaddr;
	unsigned short inetport;
	unsigned long* inet6addr;

	ASSERT(addr != NULL);

	/* */
	inet6addr = (unsigned long*)addr->sin6.sin6_addr.s6_addr;
	if (addr->ss.ss_family == AF_INET) {
		inetaddr = addr->sin.sin_addr.s_addr;
		inetport = addr->sin.sin_port;

		/* Convert into IPv4 mapped IPv6 */
		addr->sin6.sin6_family = AF_INET;
		inet6addr[0] = 0;
		inet6addr[1] = 0;
		inet6addr[2] = htonl(0xffff);
		inet6addr[3] = inetaddr;
		addr->sin6.sin6_port = inetport;

		return 1;
	} else if ((addr->ss.ss_family == AF_INET6) && (IN6_IS_ADDR_V4MAPPED(&addr->sin6.sin6_addr))) {
		inetaddr = inet6addr[3];
		inetport = addr->sin6.sin6_port;

		/* Convert into IPv4 */
		addr->sin.sin_family = AF_INET;
		addr->sin.sin_addr.s_addr = inetaddr;
		addr->sin.sin_port = inetport;

		return 1;
	}

	return 0;
}

/* Compare ip address */
int capwap_compare_ip(union sockaddr_capwap* addr1, union sockaddr_capwap* addr2) {
	ASSERT(addr1 != NULL);
	ASSERT(addr2 != NULL);

	if (addr1->ss.ss_family != addr2->ss.ss_family) {
		return -1;
	}

	/* */
	if (addr1->ss.ss_family == AF_INET) {
		if ((addr1->sin.sin_addr.s_addr == addr2->sin.sin_addr.s_addr) && (addr1->sin.sin_port == addr2->sin.sin_port)) {
			return 0;
		}
	} else if (addr1->ss.ss_family == AF_INET6) {
		if (!memcmp(&addr1->sin6.sin6_addr, &addr2->sin6.sin6_addr, sizeof(struct in6_addr)) && (addr1->sin6.sin6_port == addr2->sin6.sin6_port)) {
			return 0;
		}
	}

	return -1;
}

/* Wait receive packet with timeout */
int capwap_wait_recvready(struct pollfd* fds, int fdscount, struct capwap_timeout* timeout) {
	int i;
	int readysocket;
	int polltimeout = CAPWAP_TIMEOUT_INFINITE;

	ASSERT(fds);
	ASSERT(fdscount > 0);

	/* Check timeout */
	if (timeout) {
		polltimeout = capwap_timeout_getcoming(timeout);
		if (!polltimeout) {
			capwap_timeout_hasexpired(timeout);
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
			if (fds[i].revents & POLLIN) {
				return i;
			} else if ((fds[i].revents & (POLLHUP | POLLERR | POLLNVAL))) {
				return CAPWAP_RECV_ERROR_SOCKET;
			}
		}
	} else if (!readysocket && timeout) {
		capwap_timeout_hasexpired(timeout);
		return CAPWAP_RECV_ERROR_TIMEOUT;
	} else if (errno == EINTR) {
		return CAPWAP_RECV_ERROR_INTR;
	}

	return CAPWAP_RECV_ERROR_SOCKET;
}

/* Receive packet from fd */
int capwap_recvfrom(int sock, void* buffer, int* size, union sockaddr_capwap* fromaddr, union sockaddr_capwap* toaddr) {
	int result = 0;
	struct iovec iov;
	struct msghdr msgh;
	struct cmsghdr* cmsg;
	char cbuf[256];

	ASSERT(sock >= 0);
	ASSERT(buffer != NULL);
	ASSERT(size != NULL);
	ASSERT(*size > 0);
	ASSERT(fromaddr != NULL);

	/* */
	iov.iov_base = buffer;
	iov.iov_len = *size;

	memset(&msgh, 0, sizeof(struct msghdr));
	msgh.msg_control = cbuf;
	msgh.msg_controllen = sizeof(cbuf);
	msgh.msg_name = &fromaddr->ss;
	msgh.msg_namelen = sizeof(struct sockaddr_storage);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_flags = 0;

	/* Receive packet with recvmsg */
	while (result <= 0) {
		result = recvmsg(sock, &msgh, 0);
		if ((result <= 0) && (errno != EAGAIN) && (errno != EINTR)) {
			capwap_logging_warning("Unable to recv packet, recvmsg return %d with error %d", result, errno);
			return -1;
		}
	}

	/* Check if IPv4 is mapped into IPv6 */
	if (fromaddr->ss.ss_family == AF_INET6) {
		if (!capwap_ipv4_mapped_ipv6(fromaddr)) {
			capwap_logging_warning("Receive packet with invalid fromaddr");
			return -1;
		}
	}

	/* */
	if (toaddr) {
		for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL; cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
#ifdef IP_PKTINFO
			if ((cmsg->cmsg_level == SOL_IP) && (cmsg->cmsg_type == IP_PKTINFO)) {
				toaddr->sin.sin_family = AF_INET;
				memcpy(&toaddr->sin.sin_addr, &((struct in_pktinfo*)CMSG_DATA(cmsg))->ipi_addr, sizeof(struct in_addr));
				break;
			}
#elif defined IP_RECVDSTADDR
			if ((cmsg->cmsg_level == IPPROTO_IP) && (cmsg->cmsg_type == IP_RECVDSTADDR)) {
				toaddr->sin.sin_family = AF_INET;
				memcpy(&toaddr->sin.sin_addr, (struct in_addr*)CMSG_DATA(cmsg), sizeof(struct in_addr));
				break;
			}
#endif
			if ((cmsg->cmsg_level == IPPROTO_IPV6) && ((cmsg->cmsg_type == IPV6_PKTINFO) || (cmsg->cmsg_type == IPV6_RECVPKTINFO))) {
				toaddr->sin6.sin6_family = AF_INET6;
				memcpy(&toaddr->sin6.sin6_addr, &((struct in6_pktinfo*)CMSG_DATA(cmsg))->ipi6_addr, sizeof(struct in6_addr));

				/* Check if IPv4 is mapped into IPv6 */
				if (fromaddr->ss.ss_family == AF_INET) {
					if (!capwap_ipv4_mapped_ipv6(toaddr)) {
						capwap_logging_warning("Receive packet with invalid toaddr");
						return -1;
					}
				}

				break;
			}
		}
	}

	/* Packet receive */
	*size = result;

#ifdef DEBUG
	{
		char strfromaddr[INET6_ADDRSTRLEN];
		char strtoaddr[INET6_ADDRSTRLEN];
		capwap_logging_debug("Receive packet from %s:%d to %s with size %d", capwap_address_to_string(fromaddr, strfromaddr, INET6_ADDRSTRLEN), (int)CAPWAP_GET_NETWORK_PORT(fromaddr), capwap_address_to_string(toaddr, strtoaddr, INET6_ADDRSTRLEN), result);
	}
#endif

	return 0;
}

/* */
void capwap_network_init(struct capwap_network* net) {
	ASSERT(net != NULL);

	/* */
	memset(net, 0, sizeof(struct capwap_network));

	/* */
	net->localaddr.ss.ss_family = AF_UNSPEC;
	net->socket = -1;
}

/* */
int capwap_network_set_pollfd(struct capwap_network* net, struct pollfd* fds, int fdscount) {
	ASSERT(net != NULL);
	ASSERT(fdscount >= 0);

	/* */
	if (!fds) {
		return (!fdscount ? 1 : -1);
	} else if (fdscount < 1) {
		return -1;
	}

	/* Configure fds array */
	fds[0].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
	fds[0].fd = net->socket;

	return 1;
}

/* */
int capwap_sendto(int sock, void* buffer, int size, union sockaddr_capwap* toaddr) {
	int result;

	ASSERT(sock >= 0);
	ASSERT(buffer != NULL);
	ASSERT(size > 0);
	ASSERT(toaddr != NULL);

	do {
		result = sendto(sock, buffer, size, 0, &toaddr->sa, sizeof(union sockaddr_capwap));
		if ((result < 0) && (errno != EAGAIN) && (errno != EINTR)) {
			capwap_logging_warning("Unable to send packet, sendto return %d with error %d", result, errno);
			return -errno;
		} else if ((result > 0) && (result != size)) {
			capwap_logging_warning("Unable to send packet, mismatch sendto size %d - %d", size, result);
			return -ENETRESET;
		}
	} while (result < 0);

#ifdef DEBUG
	{
		char strtoaddr[INET6_ADDRSTRLEN];
		capwap_logging_debug("Sent packet to %s:%d with result %d", capwap_address_to_string(toaddr, strtoaddr, INET6_ADDRSTRLEN), (int)CAPWAP_GET_NETWORK_PORT(toaddr), result);
	}
#endif

	return result;
}

/* */
int capwap_sendto_fragmentpacket(int sock, struct capwap_list* fragmentlist, union sockaddr_capwap* toaddr) {
	int err;
	struct capwap_list_item* item;

	ASSERT(sock >= 0);
	ASSERT(fragmentlist != NULL);
	ASSERT(toaddr != NULL);

	item = fragmentlist->first;
	while (item) {
		struct capwap_fragment_packet_item* fragmentpacket = (struct capwap_fragment_packet_item*)item->item;
		ASSERT(fragmentpacket != NULL);
		ASSERT(fragmentpacket->offset > 0);

		err = capwap_sendto(sock, fragmentpacket->buffer, fragmentpacket->offset, toaddr);
		if (err <= 0) {
			capwap_logging_warning("Unable to send fragment, sentto return error %d", err);
			return 0;
		}

		/* */
		item = item->next;
	}

	return 1;
}

/* Convert string into address */
int capwap_address_from_string(const char* ip, union sockaddr_capwap* sockaddr) {
	char* pos;
	char* buffer;
	struct addrinfo hints;
	struct addrinfo* info = NULL;
	char* service = NULL;

	ASSERT(ip != NULL);
	ASSERT(sockaddr != NULL);

	/* Init */
	memset(sockaddr, 0, sizeof(union sockaddr_capwap));
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
	memcpy(&sockaddr->ss, info->ai_addr, info->ai_addrlen);

	freeaddrinfo(info);
	capwap_free(buffer);

	return 1;
}

/* Convert address to string */
const char* capwap_address_to_string(union sockaddr_capwap* sockaddr, char* ip, int len) {
	ASSERT(sockaddr != NULL);
	ASSERT(ip != NULL);
	ASSERT(len > 0);

	if ((sockaddr->ss.ss_family == AF_INET) && (len >= INET_ADDRSTRLEN)) {
		if (!inet_ntop(AF_INET, &sockaddr->sin.sin_addr, ip, len)) {
			*ip = 0;
		}
	} else if ((sockaddr->ss.ss_family == AF_INET6) && (len >= INET6_ADDRSTRLEN)) {
		if (!inet_ntop(AF_INET6, &sockaddr->sin6.sin6_addr, ip, len)) {
			*ip = 0;
		}
	} else {
		*ip = 0;
	}

	return ip;
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
static void capwap_get_network_address(union sockaddr_capwap* addr, union sockaddr_capwap* network, unsigned long bitsmask) {
	unsigned long i;

	ASSERT(addr != NULL);
	ASSERT(network != NULL);

	memcpy(network, addr, sizeof(union sockaddr_capwap));

	if (addr->ss.ss_family == AF_INET) {
		unsigned long mask = 0xffffffff;

		for (i = bitsmask; i < 32; i++) {
			mask <<= 1;
		}

		network->sin.sin_addr.s_addr &= htonl(mask);
	} else {
		unsigned long pos = bitsmask / 8;
		unsigned long delta = bitsmask % 8;

		if (!delta) {
			pos -= 1;			/* Optimize for all bits of pos equal 0 */
		} else {
			unsigned char mask = 0xff;

			for (i = delta; i < 8; i++) {
				mask <<= 1;
			}

			network->sin6.sin6_addr.s6_addr[pos] &= mask;
		}

		for (i = pos + 1; i < 16; i++) {
			network->sin6.sin6_addr.s6_addr[i] = 0;
		}
	}
}

/* */
static int capwap_get_routeaddress(union sockaddr_capwap* localaddr, union sockaddr_capwap* peeraddr, char* iface, unsigned char table) {
	int result = CAPWAP_ROUTE_NOT_FOUND;

	int foundgateway = 0;
	unsigned char gatewaytable = 0;
	unsigned long gatewaymetric = 0;
	union sockaddr_capwap gateway;

	int nlsock;
	struct sockaddr_nl nllocal;
	socklen_t nllocaladdrlen;
	int sndbuf = 32768;
	int rcvbuf = 32768;

	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	ASSERT(localaddr != NULL);
	ASSERT(peeraddr != NULL);

	/* */
	memset(localaddr, 0, sizeof(union sockaddr_capwap));

	/* Open netlink route socket */
	nlsock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nlsock < 0) {
		return CAPWAP_ROUTE_NOT_FOUND;
	}

	/* Configure socket */
	if (setsockopt(nlsock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(int)) < 0) {
		close(nlsock);
		return CAPWAP_ROUTE_NOT_FOUND;
	}

	if (setsockopt(nlsock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(int)) < 0) {
		close(nlsock);
		return CAPWAP_ROUTE_NOT_FOUND;
	}

	/* Bind */
	memset(&nllocal, 0, sizeof(struct sockaddr_nl));
	nllocal.nl_family = AF_NETLINK;
	if (bind(nlsock, (struct sockaddr*)&nllocal, sizeof(struct sockaddr_nl)) < 0) {
		close(nlsock);
		return CAPWAP_ROUTE_NOT_FOUND;
	}

	/* Check bind */
	nllocaladdrlen = sizeof(struct sockaddr_nl);
	if (getsockname(nlsock, (struct sockaddr*)&nllocal, &nllocaladdrlen) < 0) {
		close(nlsock);
		return CAPWAP_ROUTE_NOT_FOUND;
	}

	if ((nllocaladdrlen != sizeof(struct sockaddr_nl)) || (nllocal.nl_family != AF_NETLINK)) {
		close(nlsock);
		return CAPWAP_ROUTE_NOT_FOUND;
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
		int end = 0;
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
		while ((result == CAPWAP_ROUTE_NOT_FOUND) && !end) {
			int status;
			struct nlmsghdr *h;

			/* Receive response */
			iov.iov_len = sizeof(buf);
			status = recvmsg(nlsock, &msg, 0);
			if (status < 0) {
				if ((errno == EINTR) || (errno == EAGAIN)) {
					continue;
				}

				break;
			} else if (!status) {
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
						if ((len >= 0) && (!table || (r->rtm_table == table)) && (peeraddr->ss.ss_family == r->rtm_family)) {
							struct rtattr* tb[RTA_MAX + 1];
							struct rtattr* rta = RTM_RTA(r);
							int addrsize = ((r->rtm_family == AF_INET) ? sizeof(struct in_addr) : sizeof(struct in6_addr));
							int defaultgateway = 0;
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

							if (!iface || !strcmp(iface, ifname)) {
								union sockaddr_capwap destaddr;

								/* Destination network */
								memset(&destaddr, 0, sizeof(union sockaddr_capwap));
								destaddr.ss.ss_family = r->rtm_family;

								if (tb[RTA_DST]) {
									memcpy(((r->rtm_family == AF_INET) ? (void*)&destaddr.sin.sin_addr : (void*)&destaddr.sin6.sin6_addr), RTA_DATA(tb[RTA_DST]), addrsize);
								} else if (!r->rtm_dst_len) {
									defaultgateway = 1;
								}

								/* Check network */
								if (defaultgateway) {
									if (tb[RTA_GATEWAY]) {
										unsigned long metric = (tb[RTA_PRIORITY] ? *(unsigned long*)RTA_DATA(tb[RTA_PRIORITY]) : 0);

										if ((gatewaytable < r->rtm_table) || ((gatewaytable == r->rtm_table) && (gatewaymetric > metric))) {
											foundgateway = 1;
											gatewaytable = r->rtm_table;
											gatewaymetric = metric;

											/* */
											memset(&gateway, 0, sizeof(union sockaddr_capwap));

											gateway.ss.ss_family = r->rtm_family;
											memcpy(((r->rtm_family == AF_INET) ? (void*)&gateway.sin.sin_addr : (void*)&gateway.sin6.sin6_addr), RTA_DATA(tb[RTA_GATEWAY]), addrsize);
										}
									}
								} else if (tb[RTA_PREFSRC]) {
									int equal = 0;
									union sockaddr_capwap peernetwork;
									union sockaddr_capwap destnework;

									/* Get subnet */
									capwap_get_network_address(peeraddr, &peernetwork, destmask);
									capwap_get_network_address(&destaddr, &destnework, destmask);

									/* Compare subnet */
									if (peernetwork.ss.ss_family == AF_INET) {
										if (peernetwork.sin.sin_addr.s_addr == destnework.sin.sin_addr.s_addr) {
											equal = 1;
										}
									} else if (peernetwork.ss.ss_family == AF_INET6) {
										if (!memcmp(&peernetwork.sin6.sin6_addr, &destnework.sin6.sin6_addr, sizeof(struct in6_addr))) {
											equal = 1;
										}
									}

									if (equal) {
										result = CAPWAP_ROUTE_LOCAL_ADDRESS;
										localaddr->ss.ss_family = r->rtm_family;
										memcpy(((r->rtm_family == AF_INET) ? (void*)&localaddr->sin.sin_addr : (void*)&localaddr->sin6.sin6_addr), RTA_DATA(tb[RTA_PREFSRC]), addrsize);

										break;
									}
								}
							}
						}
					}
				}

				/* Next */
				h = NLMSG_NEXT(h, status);
			}
		}
	}

	/* */
	if ((result == CAPWAP_ROUTE_NOT_FOUND) && foundgateway) {
		result = CAPWAP_ROUTE_VIA_ADDRESS;
		memcpy(localaddr, &gateway, sizeof(union sockaddr_capwap));
	}

	/* */
	close(nlsock);
	return result;
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
int capwap_network_get_localaddress(union sockaddr_capwap* localaddr, union sockaddr_capwap* peeraddr, char* iface) {
	int result;

	ASSERT(localaddr != NULL);
	ASSERT(peeraddr != NULL);

	/* */
	memset(localaddr, 0, sizeof(union sockaddr_capwap));

	/* Check output interface */
	if (iface && !*iface) {
		iface = NULL;
	}

	/* Check Loopback address */
	if (peeraddr->ss.ss_family == AF_INET) {
		if (peeraddr->sin.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
			if (iface && ((capwap_get_interface_flags(iface) & IFF_LOOPBACK) != IFF_LOOPBACK)) {
				return -1;
			}

			/* Loopback */
			localaddr->ss.ss_family = AF_INET;
			localaddr->sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			return 0;
		}
	} else if (peeraddr->ss.ss_family == AF_INET6) {
		if (!memcmp(&peeraddr->sin6.sin6_addr, &in6addr_loopback, sizeof(struct in6_addr))) {
			if (iface && ((capwap_get_interface_flags(iface) & IFF_LOOPBACK) != IFF_LOOPBACK)) {
				return -1;
			}

			localaddr->ss.ss_family = AF_INET6;
			memcpy(&localaddr->sin6.sin6_addr, &in6addr_loopback, sizeof(struct in6_addr));
			return 0;
		}
	} else {
		return -1;
	}

	/* Get address */
	result = capwap_get_routeaddress(localaddr, peeraddr, iface, RT_TABLE_MAIN);
	if (result == CAPWAP_ROUTE_NOT_FOUND) {
		return -1;
	} else if (result == CAPWAP_ROUTE_VIA_ADDRESS) {
		union sockaddr_capwap tempaddr;

		result = capwap_get_routeaddress(&tempaddr, localaddr, iface, RT_TABLE_MAIN);
		if (result != CAPWAP_ROUTE_LOCAL_ADDRESS) {
			return -1;
		}

		memcpy(localaddr, &tempaddr, sizeof(union sockaddr_capwap));
	}

	return 0;
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
		union sockaddr_capwap* addr;

		/* No loopback interface */
		if ((ifcurrentpos->ifa_flags & IFF_LOOPBACK) != 0) {
			continue;
		}

		/* Only IPv4 and IPv6 */
		if ((ifcurrentpos->ifa_addr == NULL) || ((ifcurrentpos->ifa_addr->sa_family != AF_INET) && (ifcurrentpos->ifa_addr->sa_family != AF_INET6))) {
			continue;
		}

		/* Filter family */
		if (net->localaddr.ss.ss_family != ifcurrentpos->ifa_addr->sa_family) {
			continue;
		}

		/* Filter interface */
		if (*net->bindiface && strcmp(net->bindiface, ifcurrentpos->ifa_name)) {
			continue;
		}

		/* Add local address */
		item = capwap_itemlist_create(sizeof(union sockaddr_capwap));
		addr = (union sockaddr_capwap*)item->item;

		memset(addr, 0, sizeof(union sockaddr_capwap));
		addr->ss.ss_family = ifcurrentpos->ifa_addr->sa_family;

		if (addr->ss.ss_family == AF_INET) {
			memcpy(&addr->sin.sin_addr, &((struct sockaddr_in*)ifcurrentpos->ifa_addr)->sin_addr, sizeof(struct in_addr));
			addr->sin.sin_port = htons(CAPWAP_CONTROL_PORT);
		} else if (addr->ss.ss_family == AF_INET6) {
			memcpy(&addr->sin6.sin6_addr, &((struct sockaddr_in6*)ifcurrentpos->ifa_addr)->sin6_addr, sizeof(struct in6_addr));
			addr->sin6.sin6_port = htons(CAPWAP_CONTROL_PORT);
		}

		/* Add address */
		capwap_itemlist_insert_after(list, NULL, item);
	}

	/* Free */
	freeifaddrs(ifaddrlist);
}

/* */
char* capwap_printf_macaddress(char* buffer, const uint8_t* macaddress, int type) {
	if (type == MACADDRESS_EUI48_LENGTH) {
		sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", macaddress[0], macaddress[1], macaddress[2], macaddress[3], macaddress[4], macaddress[5]);
	} else if (type == MACADDRESS_EUI64_LENGTH) {
		sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", macaddress[0], macaddress[1], macaddress[2], macaddress[3], macaddress[4], macaddress[5], macaddress[6], macaddress[7]);
	} else {
		return NULL;
	}

	return buffer;
}

/* */
int capwap_scanf_macaddress(uint8_t* macaddress, const char* buffer, int type) {
	if (type == MACADDRESS_EUI48_LENGTH) {
		if (sscanf(buffer, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &macaddress[0], &macaddress[1], &macaddress[2], &macaddress[3], &macaddress[4], &macaddress[5]) != 6) {
			return 0;
		}
	} else if (type == MACADDRESS_EUI64_LENGTH) {
		if (sscanf(buffer, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &macaddress[0], &macaddress[1], &macaddress[2], &macaddress[3], &macaddress[4], &macaddress[5], &macaddress[6], &macaddress[7]) != 8) {
			return 0;
		}
	} else {
		return 0;
	}

	return 1;
}
