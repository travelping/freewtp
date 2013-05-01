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
		
		capwap_free_element_discovery_response(&response->discoveryresponse, GET_WBID_HEADER(&response->packet->header));
		capwap_build_packet_free(response->packet);
	}
	
	/* Remove all items */
	capwap_array_resize(g_wtp.acdiscoveryresponse, 0);
}

/* */
int wtp_dfa_state_discovery(struct capwap_packet* packet, struct timeout_control* timeout) {
	int status = WTP_DFA_ACCEPT_PACKET;
	
	ASSERT(timeout != NULL);

	if (packet) {
		struct capwap_build_packet* buildpacket;
	
		buildpacket = capwap_rx_packet_create((void*)packet->header, packet->packetsize, packet->socket.isctrlsocket);
		if (buildpacket) {
			if (capwap_build_packet_validate(buildpacket, NULL)) {
				capwap_build_packet_free(buildpacket);			/* Invalid packet */
			} else {
				unsigned short binding;
				
				/* */
				binding = GET_WBID_HEADER(&buildpacket->header);
				if ((binding != g_wtp.binding) || (ntohl(buildpacket->ctrlmsg.type) != CAPWAP_DISCOVERY_RESPONSE) || ((g_wtp.localseqnumber - 1) != buildpacket->ctrlmsg.seq)) {
					capwap_build_packet_free(buildpacket);		/* Invalid packet */
				} else {
					struct wtp_discovery_response* response = (struct wtp_discovery_response*)capwap_array_get_item_pointer(g_wtp.acdiscoveryresponse, g_wtp.acdiscoveryresponse->count);

					/* Discovery response info */
					memcpy(&response->acaddr, &packet->remoteaddr, sizeof(struct sockaddr_storage));
					response->packet = buildpacket;
					capwap_init_element_discovery_response(&response->discoveryresponse, binding);

					/* Parsing elements list */
					capwap_parsing_element_discovery_response(&response->discoveryresponse, buildpacket->elementslist->first);
				}
			}
		}
	} else if (g_wtp.acdiscoveryresponse->count > 0) {
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
				for (w = 0; w < response->discoveryresponse.controlipv4->count; w++) {
					struct capwap_controlipv4_element* controlipv4 = *(struct capwap_controlipv4_element**)capwap_array_get_item_pointer(response->discoveryresponse.controlipv4, w);
					
					/* Create IPv4 address */
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
				for (w = 0; w < response->discoveryresponse.controlipv6->count; w++) {
					struct capwap_controlipv6_element* controlipv6 = *(struct capwap_controlipv6_element**)capwap_array_get_item_pointer(response->discoveryresponse.controlipv6, w);
					
					/* Create IPv6 address */
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
			wtp_dfa_change_state(CAPWAP_DISCOVERY_TO_DTLS_SETUP_STATE);
		}
		
		status = WTP_DFA_NO_PACKET;
	} else {
		int i;
		int result;
		struct capwap_build_packet* buildpacket;

		/* No Discovery response received */
		g_wtp.dfa.rfcDiscoveryCount++;
		if (g_wtp.dfa.rfcDiscoveryCount >= g_wtp.dfa.rfcMaxDiscoveries) {
			/* Timeout discovery state */
			wtp_dfa_change_state(CAPWAP_DISCOVERY_TO_SULKING_STATE);
			status = WTP_DFA_NO_PACKET;
		} else {
			/* Update status radio */
			g_wtp.descriptor.radiosinuse = wtp_update_radio_in_use();
	
			/* Build packet */
			buildpacket = capwap_tx_packet_create(CAPWAP_RADIOID_NONE, g_wtp.binding);
			buildpacket->isctrlmsg = 1;
			
			/* Prepare discovery request */
			capwap_build_packet_set_control_message_type(buildpacket, CAPWAP_DISCOVERY_REQUEST, g_wtp.localseqnumber++);
			capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_DISCOVERYTYPE_ELEMENT(&g_wtp.discoverytype));
			capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_WTPBOARDDATA_ELEMENT(&g_wtp.boarddata));
			capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_WTPDESCRIPTOR_ELEMENT(&g_wtp.descriptor));
			capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_WTPFRAMETUNNELMODE_ELEMENT(&g_wtp.mactunnel));
			capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_WTPMACTYPE_ELEMENT(&g_wtp.mactype));
			
			if (g_wtp.binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
				for (i = 0; i < g_wtp.radios->count; i++) {
					struct wtp_radio* radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);
					capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_80211_WTPRADIOINFORMATION_ELEMENT(&radio->radioinformation));
				}
			} else {
				capwap_logging_debug("Unknown capwap binding");
			}
			
			/* CAPWAP_CREATE_MTUDISCOVERYPADDING_ELEMENT */		/* TODO */
			/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */	/* TODO */
			
			/* Create discovery request packet */
			if (!capwap_build_packet_validate(buildpacket, NULL)) {
				wtp_free_reference_last_request();
				result = capwap_fragment_build_packet(buildpacket, g_wtp.requestfragmentpacket, g_wtp.mtu, g_wtp.fragmentid);
				if (result == 1) {
					g_wtp.fragmentid++;
				}
			} else {
				result = -1;
				capwap_logging_debug("Warning: build invalid discovery request packet");
			}
			
			capwap_build_packet_free(buildpacket);
	
			/* Send discovery request to AC */
			if (result >= 0) {
				int i;
				
				/* Send broadcast packet to all socket */
				for (i = 0; i < g_wtp.requestfragmentpacket->count; i++) {
					int j;				
					struct capwap_packet* packet = (struct capwap_packet*)capwap_array_get_item_pointer(g_wtp.requestfragmentpacket, i);
	
					ASSERT(packet != NULL);
					
					for (j = 0; j < g_wtp.acdiscoveryarray->count; j++) {
						int sock;
						struct sockaddr_storage* sendtoaddr = (struct sockaddr_storage*)capwap_array_get_item_pointer(g_wtp.acdiscoveryarray, j);
						
						sock = capwap_get_socket(&g_wtp.net, sendtoaddr->ss_family, IPPROTO_UDP, 1);
						if (sock >= 0) {
							if (!capwap_sendto(sock, packet->header, packet->packetsize, NULL, sendtoaddr)) {
								capwap_logging_debug("Warning: error to send discovery request packet");
								break;
							}
						}
					}
				}
	
				/* Don't buffering a packets sent */
				wtp_free_reference_last_request();
			}
			
			/* Wait before send another Discovery Request */
			capwap_set_timeout(g_wtp.dfa.rfcDiscoveryInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		}
	}

	return status;
}

/* */
int wtp_dfa_state_discovery_to_sulking(struct capwap_packet* packet, struct timeout_control* timeout) {
	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);
	
	capwap_set_timeout(g_wtp.dfa.rfcSilentInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
	wtp_dfa_change_state(CAPWAP_SULKING_STATE);

	return WTP_DFA_DROP_PACKET;
}

/* */
int wtp_dfa_state_discovery_to_dtlssetup(struct capwap_packet* packet, struct timeout_control* timeout) {
	int status = WTP_DFA_ACCEPT_PACKET;
	
	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);

	/* Retrieve local address */
	if (!capwap_get_localaddress_by_remoteaddress(&g_wtp.wtpctrladdress, &g_wtp.acctrladdress, g_wtp.net.bind_interface, (!(g_wtp.net.bind_ctrl_flags & CAPWAP_IPV6ONLY_FLAG) ? 1 : 0))) {
		wtp_dfa_change_state(CAPWAP_DISCOVERY_TO_SULKING_STATE);
		status = WTP_DFA_NO_PACKET;
	} else {
		struct sockaddr_storage sockinfo;
		socklen_t sockinfolen = sizeof(struct sockaddr_storage);

		memset(&sockinfo, 0, sizeof(struct sockaddr_storage));
		if (getsockname(g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], (struct sockaddr*)&sockinfo, &sockinfolen) < 0) {
			wtp_dfa_change_state(CAPWAP_DTLS_SETUP_TO_SULKING_STATE);
			status = WTP_DFA_NO_PACKET; 
		} else {
			CAPWAP_SET_NETWORK_PORT(&g_wtp.wtpctrladdress, CAPWAP_GET_NETWORK_PORT(&sockinfo));

			/* */
			memcpy(&g_wtp.wtpdataaddress, &g_wtp.wtpctrladdress, sizeof(struct sockaddr_storage));
			CAPWAP_SET_NETWORK_PORT(&g_wtp.wtpdataaddress, CAPWAP_GET_NETWORK_PORT(&g_wtp.wtpdataaddress) + 1);
			
			/* */
			if (!g_wtp.enabledtls) {
				/* Bypass DTLS connection */
				wtp_dfa_change_state(CAPWAP_DTLS_CONNECT_TO_JOIN_STATE);
				status = WTP_DFA_NO_PACKET;
			} else {
				/* Create DTLS connection */
				wtp_dfa_change_state(CAPWAP_DTLS_SETUP_STATE);
				status = WTP_DFA_NO_PACKET;
			}
		}
	}
	
	return status;
}
