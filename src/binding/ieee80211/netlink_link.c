#include "capwap.h"
#include "network.h"
#include <linux/socket.h>
#include "wifi_drivers.h"
#include "netlink_link.h"

static void netlink_event_receive_cb(EV_P_ ev_io *w, int revents);

/* */
struct netlink_request {
	struct nlmsghdr hdr;
	struct ifinfomsg ifinfo;
	char opts[16];
};

/* */
struct netlink *netlink_init(wifi_global_handle handle)
{
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
	netlinkhandle->handle = handle;
	netlinkhandle->sock = sock;
	netlinkhandle->nl_sequence = 1;

	ev_io_init(&netlinkhandle->io_ev, netlink_event_receive_cb, sock, EV_READ);
	ev_io_start(EV_DEFAULT_UC_ &netlinkhandle->io_ev);

	return netlinkhandle;
}

/* */
void netlink_free(struct netlink* netlinkhandle)
{
	ASSERT(netlinkhandle != NULL);
	ASSERT(netlinkhandle->sock  >= 0);

	if (ev_is_active(&netlinkhandle->io_ev))
		ev_io_stop(EV_DEFAULT_UC_ &netlinkhandle->io_ev);

	/* */
	close(netlinkhandle->sock);
	capwap_free(netlinkhandle);
}

static void invoke_event_fn(netlink_event_fn event_fn, struct netlink *netlinkhandle, struct nlmsghdr* message)
{
	if (!event_fn)
		return;

	if (NLMSG_PAYLOAD(message, 0) < sizeof(struct ifinfomsg))
		return;

	event_fn(netlinkhandle->handle,
		 NLMSG_DATA(message),
		 (uint8_t*)(NLMSG_DATA(message) + NLMSG_ALIGN(sizeof(struct ifinfomsg))),
		 NLMSG_PAYLOAD(message, sizeof(struct ifinfomsg)));
}

/* */
static void netlink_event_receive_cb(EV_P_ ev_io *w, int revents)
{
	struct netlink *netlinkhandle = (struct netlink *)
		(((char *)w) - offsetof(struct netlink, io_ev));
	int result;
	struct sockaddr_nl from;
	socklen_t fromlen;
	char buffer[8192];
	struct nlmsghdr* message;

	/* Retrieve all netlink message */
	for (;;) {
		/* Get message */
		fromlen = sizeof(struct sockaddr_nl);
		result = recvfrom(w->fd, buffer, sizeof(buffer), MSG_DONTWAIT,
				  (struct sockaddr *)&from, &fromlen);
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
			case RTM_NEWLINK:
				invoke_event_fn(netlinkhandle->newlink_event,
						netlinkhandle, message);
				break;

			case RTM_DELLINK:
				invoke_event_fn(netlinkhandle->dellink_event,
						netlinkhandle, message);
				break;

			default:
				break;
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
