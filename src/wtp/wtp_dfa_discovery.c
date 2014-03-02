#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "capwap_array.h"
#include "capwap_list.h"
#include "wtp_dfa.h"

/* */
void wtp_free_discovery_response_array(void) {
	int i;

	/* Free items */
	for (i = 0; i < g_wtp.acdiscoveryresponse->count; i++) {
		struct wtp_discovery_response* response = (struct wtp_discovery_response*)capwap_array_get_item_pointer(g_wtp.acdiscoveryresponse, i);
		capwap_array_free(response->controlipv4);
		capwap_array_free(response->controlipv6);
	}

	/* Remove all items */
	capwap_array_resize(g_wtp.acdiscoveryresponse, 0);
}

/* */
void wtp_dfa_state_discovery_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	long discoveryinterval;

	if (g_wtp.acdiscoveryresponse->count > 0) {
		int i, j, w;
		int countwtp = -1;
		int indexpreferred = -1;

		struct sockaddr_storage checkaddr;
		struct sockaddr_in* checkaddripv4;
		struct sockaddr_in6* checkaddripv6;

		/* */
		g_wtp.acctrladdress.ss_family = AF_UNSPEC;

		/* Selected by preferred or less WTP by AC */
		for (i = 0; i < g_wtp.acdiscoveryresponse->count; i++) {
			struct wtp_discovery_response* response = (struct wtp_discovery_response*)capwap_array_get_item_pointer(g_wtp.acdiscoveryresponse, i);

			/* AC with IPv4 */
			if ((g_wtp.net.sock_family == AF_UNSPEC) || (g_wtp.net.sock_family == AF_INET)) {
				for (w = 0; w < response->controlipv4->count; w++) {
					struct capwap_controlipv4_element* controlipv4 = (struct capwap_controlipv4_element*)capwap_array_get_item_pointer(response->controlipv4, w);

					/* Create IPv4 address */
					memset(&checkaddr, 0, sizeof(struct sockaddr_storage));
					checkaddripv4 = (struct sockaddr_in*)&checkaddr;
					checkaddripv4->sin_family = AF_INET;
					checkaddripv4->sin_port = htons(CAPWAP_CONTROL_PORT);
					memcpy(&checkaddripv4->sin_addr, &controlipv4->address, sizeof(struct in_addr));

					/* Check for preferred AC */
					for (j = 0; j < ((indexpreferred != -1) ? indexpreferred : g_wtp.acpreferedarray->count); j++) {
						struct sockaddr_storage* acpreferredaddr = (struct sockaddr_storage*)capwap_array_get_item_pointer(g_wtp.acpreferedarray, j);

						if (!capwap_compare_ip(acpreferredaddr, &checkaddr)) {
							indexpreferred = j;
							memcpy(&g_wtp.acctrladdress, &checkaddr, sizeof(struct sockaddr_storage));
							capwap_get_network_socket(&g_wtp.net, &g_wtp.acctrlsock, capwap_get_socket(&g_wtp.net, g_wtp.acctrladdress.ss_family, IPPROTO_UDP, 1));
							capwap_get_network_socket(&g_wtp.net, &g_wtp.acdatasock, capwap_get_socket(&g_wtp.net, g_wtp.acctrladdress.ss_family, (g_wtp.transport.type == CAPWAP_UDP_TRANSPORT ? IPPROTO_UDP : IPPROTO_UDPLITE), CAPWAP_DATA_SOCKET));
							break;
						}
					}

					/* Check by number of WTP */
					if (indexpreferred == -1) {
						if ((countwtp == -1) || (countwtp > controlipv4->wtpcount)) {
							countwtp = controlipv4->wtpcount;
							memcpy(&g_wtp.acctrladdress, &checkaddr, sizeof(struct sockaddr_storage));
							capwap_get_network_socket(&g_wtp.net, &g_wtp.acctrlsock, capwap_get_socket(&g_wtp.net, g_wtp.acctrladdress.ss_family, IPPROTO_UDP, 1));
							capwap_get_network_socket(&g_wtp.net, &g_wtp.acdatasock, capwap_get_socket(&g_wtp.net, g_wtp.acctrladdress.ss_family, (g_wtp.transport.type == CAPWAP_UDP_TRANSPORT ? IPPROTO_UDP : IPPROTO_UDPLITE), CAPWAP_DATA_SOCKET));
						}
					}
				}
			}

			/* AC with IPv6 */
			if ((g_wtp.net.sock_family == AF_UNSPEC) || (g_wtp.net.sock_family == AF_INET6)) {
				for (w = 0; w < response->controlipv6->count; w++) {
					struct capwap_controlipv6_element* controlipv6 = (struct capwap_controlipv6_element*)capwap_array_get_item_pointer(response->controlipv6, w);

					/* Create IPv6 address */
					memset(&checkaddr, 0, sizeof(struct sockaddr_storage));
					checkaddripv6 = (struct sockaddr_in6*)&checkaddr;
					checkaddripv6->sin6_family = AF_INET6;
					checkaddripv6->sin6_port = htons(CAPWAP_CONTROL_PORT);
					memcpy(&checkaddripv6->sin6_addr, &controlipv6->address, sizeof(struct in6_addr));

					/* Check for preferred AC */
					for (j = 0; j < ((indexpreferred != -1) ? indexpreferred : g_wtp.acpreferedarray->count); j++) {
						struct sockaddr_storage* acpreferredaddr = (struct sockaddr_storage*)capwap_array_get_item_pointer(g_wtp.acpreferedarray, j);

						if (!capwap_compare_ip(acpreferredaddr, &checkaddr)) {
							indexpreferred = j;
							memcpy(&g_wtp.acctrladdress, &checkaddr, sizeof(struct sockaddr_storage));
							capwap_get_network_socket(&g_wtp.net, &g_wtp.acctrlsock, capwap_get_socket(&g_wtp.net, g_wtp.acctrladdress.ss_family, IPPROTO_UDP, 1));
							capwap_get_network_socket(&g_wtp.net, &g_wtp.acdatasock, capwap_get_socket(&g_wtp.net, g_wtp.acctrladdress.ss_family, (g_wtp.transport.type == CAPWAP_UDP_TRANSPORT ? IPPROTO_UDP : IPPROTO_UDPLITE), CAPWAP_DATA_SOCKET));
							break;
						}
					}

					/* Check by number of WTP */
					if (indexpreferred == -1) {
						if ((countwtp == -1) || (countwtp > controlipv6->wtpcount)) {
							countwtp = controlipv6->wtpcount;
							memcpy(&g_wtp.acctrladdress, &checkaddr, sizeof(struct sockaddr_storage));
							capwap_get_network_socket(&g_wtp.net, &g_wtp.acctrlsock, capwap_get_socket(&g_wtp.net, g_wtp.acctrladdress.ss_family, IPPROTO_UDP, 1));
							capwap_get_network_socket(&g_wtp.net, &g_wtp.acdatasock, capwap_get_socket(&g_wtp.net, g_wtp.acctrladdress.ss_family, (g_wtp.transport.type == CAPWAP_UDP_TRANSPORT ? IPPROTO_UDP : IPPROTO_UDPLITE), CAPWAP_DATA_SOCKET));
						}
					}
				}
			}
		}

		/* Free memory */
		wtp_free_discovery_response_array();

		/* Change state if found AC */
		if (g_wtp.acctrladdress.ss_family != AF_UNSPEC) {
			memcpy(&g_wtp.acdataaddress, &g_wtp.acctrladdress, sizeof(struct sockaddr_storage));
			CAPWAP_SET_NETWORK_PORT(&g_wtp.acdataaddress, CAPWAP_GET_NETWORK_PORT(&g_wtp.acdataaddress) + 1);

			/* Retrieve local address */
			if (capwap_get_localaddress_by_remoteaddress(&g_wtp.wtpctrladdress, &g_wtp.acctrladdress, g_wtp.net.bind_interface, (!(g_wtp.net.bind_ctrl_flags & CAPWAP_IPV6ONLY_FLAG) ? 1 : 0))) {
				struct sockaddr_storage sockinfo;
				socklen_t sockinfolen = sizeof(struct sockaddr_storage);

				memset(&sockinfo, 0, sizeof(struct sockaddr_storage));
				if (!getsockname(g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], (struct sockaddr*)&sockinfo, &sockinfolen)) {
					CAPWAP_SET_NETWORK_PORT(&g_wtp.wtpctrladdress, CAPWAP_GET_NETWORK_PORT(&sockinfo));

					/* */
					memcpy(&g_wtp.wtpdataaddress, &g_wtp.wtpctrladdress, sizeof(struct sockaddr_storage));
					CAPWAP_SET_NETWORK_PORT(&g_wtp.wtpdataaddress, CAPWAP_GET_NETWORK_PORT(&g_wtp.wtpdataaddress) + 1);

					/* */
					if (!g_wtp.enabledtls) {
						wtp_send_join();			/* Bypass DTLS connection */
					} else {
						wtp_start_dtlssetup();		/* Create DTLS connection */
					}

					return;
				}
			}
		}
	}

	/* No Discovery response received */
	g_wtp.discoverycount++;
	if (g_wtp.discoverycount >= WTP_MAX_DISCOVERY_COUNT) {
		/* Timeout discovery state */
		wtp_dfa_change_state(CAPWAP_SULKING_STATE);
		capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_SILENT_INTERVAL, wtp_dfa_state_sulking_timeout, NULL, NULL);
	} else {
		int i;
		struct capwap_header_data capwapheader;
		struct capwap_packet_txmng* txmngpacket;

		/* Update status radio */
		g_wtp.descriptor.radiosinuse = wtp_update_radio_in_use();

		/* Build packet */
		capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
		txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_DISCOVERY_REQUEST, g_wtp.localseqnumber++, g_wtp.mtu);

		/* Add message element */
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_DISCOVERYTYPE, &g_wtp.discoverytype);
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPBOARDDATA, &g_wtp.boarddata);
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPDESCRIPTOR, &g_wtp.descriptor);
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPFRAMETUNNELMODE, &g_wtp.mactunnel);
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPMACTYPE, &g_wtp.mactype);

		if (g_wtp.binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
			wtp_create_80211_wtpradioinformation_element(txmngpacket);
		}

		/* CAPWAP_ELEMENT_MTUDISCOVERY */					/* TODO */
		/* CAPWAP_ELEMENT_VENDORPAYLOAD */					/* TODO */

		/* Discovery request complete, get fragment packets */
		wtp_free_reference_last_request();
		capwap_packet_txmng_get_fragment_packets(txmngpacket, g_wtp.requestfragmentpacket, g_wtp.fragmentid);
		if (g_wtp.requestfragmentpacket->count > 1) {
			g_wtp.fragmentid++;
		}

		/* Free packets manager */
		capwap_packet_txmng_free(txmngpacket);

		/* Send discovery request to AC */
		for (i = 0; i < g_wtp.acdiscoveryarray->count; i++) {
			int sock;
			struct sockaddr_storage* sendtoaddr = (struct sockaddr_storage*)capwap_array_get_item_pointer(g_wtp.acdiscoveryarray, i);

			sock = capwap_get_socket(&g_wtp.net, sendtoaddr->ss_family, IPPROTO_UDP, 1);
			if (sock >= 0) {
				if (!capwap_sendto_fragmentpacket(sock, g_wtp.requestfragmentpacket, NULL, sendtoaddr)) {
					capwap_logging_debug("Warning: error to send discovery request packet");
					break;
				}
			}
		}

		/* Don't buffering a packets sent */
		wtp_free_reference_last_request();

		/* Wait before send another Discovery Request */
		discoveryinterval = (capwap_get_rand(g_wtp.discoveryinterval - WTP_MIN_DISCOVERY_INTERVAL) + WTP_MIN_DISCOVERY_INTERVAL);
		capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, discoveryinterval, wtp_dfa_state_discovery_timeout, NULL, NULL);
	}
}

/* */
void wtp_dfa_state_discovery(struct capwap_parsed_packet* packet) {
	unsigned short binding;
	struct capwap_array* controlip;

	ASSERT(packet != NULL);

	/* */
	binding = GET_WBID_HEADER(packet->rxmngpacket->header);
	if (packet->rxmngpacket->isctrlpacket && (binding == g_wtp.binding) && (packet->rxmngpacket->ctrlmsg.type == CAPWAP_DISCOVERY_RESPONSE) && ((g_wtp.localseqnumber - 1) == packet->rxmngpacket->ctrlmsg.seq)) {
		struct capwap_resultcode_element* resultcode;

		/* Check the success of the Request */
		resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
		if (!resultcode || CAPWAP_RESULTCODE_OK(resultcode->code)) {
			int i;
			struct wtp_discovery_response* response = (struct wtp_discovery_response*)capwap_array_get_item_pointer(g_wtp.acdiscoveryresponse, g_wtp.acdiscoveryresponse->count);

			/* */
			response->controlipv4 = capwap_array_create(sizeof(struct capwap_controlipv4_element), 0, 0);
			response->controlipv6 = capwap_array_create(sizeof(struct capwap_controlipv6_element), 0, 0);

			/* Create controlipv4 */
			controlip = (struct capwap_array*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_CONTROLIPV4);
			if (controlip) {
				for (i = 0; i < controlip->count; i++) {
					struct capwap_controlipv4_element* src = *(struct capwap_controlipv4_element**)capwap_array_get_item_pointer(controlip, i);
					struct capwap_controlipv4_element* dst = (struct capwap_controlipv4_element*)capwap_array_get_item_pointer(response->controlipv4, i);

					memcpy(dst, src, sizeof(struct capwap_controlipv4_element));
				}
			}

			/* Create controlipv6 */
			controlip = (struct capwap_array*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_CONTROLIPV6);
			if (controlip) {
				for (i = 0; i < (controlip)->count; i++) {
					struct capwap_controlipv6_element* src = *(struct capwap_controlipv6_element**)capwap_array_get_item_pointer((controlip), i);
					struct capwap_controlipv6_element* dst = (struct capwap_controlipv6_element*)capwap_array_get_item_pointer(response->controlipv6, i);

					memcpy(dst, src, sizeof(struct capwap_controlipv6_element));
				}
			}
		}
	}
}
