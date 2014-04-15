#include "capwap.h"
#include <linux/socket.h>
#include "wifi_drivers.h"
#include "netlink_link.h"

/* */
struct netlink_request {
	struct nlmsghdr hdr;
	struct ifinfomsg ifinfo;
	char opts[16];
};

/* */
struct netlink* netlink_init(void) {
	int sock;
	struct sockaddr_nl local;
	struct netlink* netlinkhandle;

	/* Create netlink socket */
	sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		return NULL;
	}

	/* Bind to kernel */
	memset(&local, 0, sizeof(struct sockaddr_nl));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;
	if (bind(sock, (struct sockaddr*)&local, sizeof(struct sockaddr_nl)) < 0) {
		close(sock);
		return NULL;
	}

	/* Netlink reference */
	netlinkhandle = (struct netlink*)capwap_alloc(sizeof(struct netlink));
	netlinkhandle->sock = sock;
	netlinkhandle->nl_sequence = 1;

	return netlinkhandle;
}

/* */
void netlink_free(struct netlink* netlinkhandle) {
	ASSERT(netlinkhandle != NULL);
	ASSERT(netlinkhandle->sock  >= 0);

	/* */
	close(netlinkhandle->sock);
	capwap_free(netlinkhandle);
}

/* */
void netlink_event_receive(int fd, void** params, int paramscount) {
	int result;
	struct netlink* netlinkhandle;
	struct sockaddr_nl from;
	socklen_t fromlen;
	char buffer[8192];
	struct nlmsghdr* message;

	ASSERT(fd >= 0);
	ASSERT(params != NULL);
	ASSERT(paramscount == 2); 

	/* */
	netlinkhandle = (struct netlink*)params[0];

	/* Retrieve all netlink message */
	for (;;) {
		/* Get message */
		fromlen = sizeof(struct sockaddr_nl);
		result = recvfrom(netlinkhandle->sock, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr*)&from, &fromlen);
		if (result <= 0) {
			if (errno == EINTR) {
				continue;
			}

			/* */
			break;
		}

		/* Parsing message */
		message = (struct nlmsghdr*)buffer;
		while (NLMSG_OK(message, result)) {
			switch (message->nlmsg_type) {
				case RTM_NEWLINK: {
					if (netlinkhandle->newlink_event && NLMSG_PAYLOAD(message, 0) >= sizeof(struct ifinfomsg)) {
						netlinkhandle->newlink_event((wifi_global_handle)params[1], NLMSG_DATA(message), (uint8_t*)(NLMSG_DATA(message) + NLMSG_ALIGN(sizeof(struct ifinfomsg))), NLMSG_PAYLOAD(message, sizeof(struct ifinfomsg)));
					}

					break;
				}

				case RTM_DELLINK: {
					if (netlinkhandle->dellink_event && NLMSG_PAYLOAD(message, 0) >= sizeof(struct ifinfomsg)) {
						netlinkhandle->dellink_event((wifi_global_handle)params[1], NLMSG_DATA(message), (uint8_t*)(NLMSG_DATA(message) + NLMSG_ALIGN(sizeof(struct ifinfomsg))), NLMSG_PAYLOAD(message, sizeof(struct ifinfomsg)));
					}

					break;
				}
			}

			/* */
			message = NLMSG_NEXT(message, result);
		}
	}
}

int netlink_set_link_status(struct netlink* netlinkhandle, int ifindex, int linkmode, int operstate) {
	char* data;
	struct rtattr* rta;
	struct netlink_request request;

	ASSERT(netlinkhandle != NULL);
	ASSERT(ifindex >= 0);

	/* */
	memset(&request, 0, sizeof(struct netlink_request));
	request.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	request.hdr.nlmsg_type = RTM_SETLINK;
	request.hdr.nlmsg_flags = NLM_F_REQUEST;
	request.hdr.nlmsg_seq = netlinkhandle->nl_sequence++;
	request.hdr.nlmsg_pid = 0;
	request.ifinfo.ifi_family = AF_UNSPEC;
	request.ifinfo.ifi_type = 0;
	request.ifinfo.ifi_index = ifindex;
	request.ifinfo.ifi_flags = 0;
	request.ifinfo.ifi_change = 0;

	if (linkmode != -1) {
		rta = (struct rtattr*)((char*)&request + NLMSG_ALIGN(request.hdr.nlmsg_len));
		rta->rta_type = IFLA_LINKMODE;
		rta->rta_len = RTA_LENGTH(sizeof(char));
		data = (char*)RTA_DATA(rta);
		*data = (char)linkmode;
		request.hdr.nlmsg_len = NLMSG_ALIGN(request.hdr.nlmsg_len) + RTA_LENGTH(sizeof(char));
	}

	if (operstate != -1) {
		rta = (struct rtattr*)((char*)&request + NLMSG_ALIGN(request.hdr.nlmsg_len));
		rta->rta_type = IFLA_OPERSTATE;
		rta->rta_len = RTA_LENGTH(sizeof(char));
		data = (char*)RTA_DATA(rta);
		*data = (char)operstate;
		request.hdr.nlmsg_len = NLMSG_ALIGN(request.hdr.nlmsg_len) + RTA_LENGTH(sizeof(char));
	}

	/* Send new interface operation state */
	if (send(netlinkhandle->sock, &request, request.hdr.nlmsg_len, 0) < 0) {
		return -1;
	}

	return 0;
}
