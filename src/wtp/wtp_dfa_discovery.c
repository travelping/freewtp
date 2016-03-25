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
		union sockaddr_capwap checkaddr;
		union sockaddr_capwap peeraddr;

		/* */
		peeraddr.ss.ss_family = AF_UNSPEC;

		/* Selected by preferred or less WTP by AC */
		for (i = 0; i < g_wtp.acdiscoveryresponse->count; i++) {
			struct wtp_discovery_response* response = (struct wtp_discovery_response*)capwap_array_get_item_pointer(g_wtp.acdiscoveryresponse, i);

			/* AC with IPv4 */
			for (w = 0; w < response->controlipv4->count; w++) {
				struct capwap_controlipv4_element* controlipv4 = (struct capwap_controlipv4_element*)capwap_array_get_item_pointer(response->controlipv4, w);

				/* Create IPv4 address */
				checkaddr.sin.sin_family = AF_INET;
				memcpy(&checkaddr.sin.sin_addr, &controlipv4->address, sizeof(struct in_addr));
				checkaddr.sin.sin_port = htons(CAPWAP_CONTROL_PORT);

				/* Check for preferred AC */
				for (j = 0; j < ((indexpreferred != -1) ? indexpreferred : g_wtp.acpreferedarray->count); j++) {
					struct addr_capwap* acpreferredaddr = (struct addr_capwap*)capwap_array_get_item_pointer(g_wtp.acpreferedarray, j);
					if (!acpreferredaddr->resolved) {
						if (capwap_address_from_string(acpreferredaddr->fqdn, &acpreferredaddr->sockaddr)) {
							if (!CAPWAP_GET_NETWORK_PORT(&acpreferredaddr->sockaddr)) {
									CAPWAP_SET_NETWORK_PORT(&acpreferredaddr->sockaddr, CAPWAP_CONTROL_PORT);
							}
							acpreferredaddr->resolved = 1;
						} else {
							capwap_logging_info("%s:%d Could not resolve application.acprefered.host %s", __FILE__, __LINE__, acpreferredaddr->fqdn);
						}
					}
					if (!capwap_compare_ip(&acpreferredaddr->sockaddr, &checkaddr)) {
						indexpreferred = j;
						memcpy(&peeraddr, &checkaddr, sizeof(union sockaddr_capwap));
						break;
					}
				}

				/* Check by number of WTP */
				if (indexpreferred == -1) {
					if ((countwtp == -1) || (countwtp > controlipv4->wtpcount)) {
						countwtp = controlipv4->wtpcount;
						memcpy(&peeraddr, &checkaddr, sizeof(union sockaddr_capwap));
					}
				}
			}

			/* AC with IPv6 */
			if (g_wtp.net.localaddr.ss.ss_family == AF_INET6) {
				for (w = 0; w < response->controlipv6->count; w++) {
					struct capwap_controlipv6_element* controlipv6 = (struct capwap_controlipv6_element*)capwap_array_get_item_pointer(response->controlipv6, w);

					/* Create IPv6 address */
					checkaddr.sin6.sin6_family = AF_INET6;
					memcpy(&checkaddr.sin6.sin6_addr, &controlipv6->address, sizeof(struct in6_addr));
					checkaddr.sin6.sin6_port = htons(CAPWAP_CONTROL_PORT);

					/* Check for preferred AC */
					for (j = 0; j < ((indexpreferred != -1) ? indexpreferred : g_wtp.acpreferedarray->count); j++) {
						struct addr_capwap* acpreferredaddr = (struct addr_capwap*)capwap_array_get_item_pointer(g_wtp.acpreferedarray, j);
						if (!acpreferredaddr->resolved) {
							if (capwap_address_from_string(acpreferredaddr->fqdn, &acpreferredaddr->sockaddr)) {
								if (!CAPWAP_GET_NETWORK_PORT(&acpreferredaddr->sockaddr)) {
									CAPWAP_SET_NETWORK_PORT(&acpreferredaddr->sockaddr, CAPWAP_CONTROL_PORT);
								}
								acpreferredaddr->resolved = 1;
							} else {
								capwap_logging_info("Could not resolve application.acprefered.host %s", acpreferredaddr->fqdn);
							}
						}
						if (!capwap_compare_ip(&acpreferredaddr->sockaddr, &checkaddr)) {
							indexpreferred = j;
							memcpy(&peeraddr, &checkaddr, sizeof(union sockaddr_capwap));
							break;
						}
					}

					/* Check by number of WTP */
					if (indexpreferred == -1) {
						if ((countwtp == -1) || (countwtp > controlipv6->wtpcount)) {
							countwtp = controlipv6->wtpcount;
							memcpy(&peeraddr, &checkaddr, sizeof(union sockaddr_capwap));
						}
					}
				}
			}
		}

		/* Free memory */
		wtp_free_discovery_response_array();

		/* Change state if found AC */
		if (peeraddr.ss.ss_family != AF_UNSPEC) {
			union sockaddr_capwap localaddr;

			if (capwap_connect_socket(&g_wtp.net, &peeraddr) < 0) {
				capwap_logging_fatal("Cannot bind control address");
				capwap_close_sockets(&g_wtp.net);
				return;
			}

			/* Retrieve local address */
			if (capwap_getsockname(&g_wtp.net, &localaddr) < 0) {
				capwap_logging_fatal("Cannot get local endpoint address");
				capwap_close_sockets(&g_wtp.net);
				return;
			}

			/* */
			capwap_crypt_setconnection(&g_wtp.dtls, g_wtp.net.socket, &localaddr, &peeraddr);

			/* */
			if (!g_wtp.enabledtls) {
				wtp_send_join();		/* Bypass DTLS connection */
			} else {
				wtp_start_dtlssetup();		/* Create DTLS connection */
			}

			return;
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

		if (g_wtp.net.socket < 0)
			if (capwap_bind_sockets(&g_wtp.net) < 0) {
				capwap_logging_fatal("Cannot bind control address");
				exit(-1);
			}

		/* Update status radio */
		g_wtp.descriptor.radiosinuse = wtp_update_radio_in_use();

		/* Build packet */
		capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
		txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_DISCOVERY_REQUEST, g_wtp.localseqnumber, g_wtp.mtu);

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
			struct addr_capwap* addr = capwap_array_get_item_pointer(g_wtp.acdiscoveryarray, i);
			if (!addr->resolved) {
				if (capwap_address_from_string(addr->fqdn, &addr->sockaddr)) {
					if (!CAPWAP_GET_NETWORK_PORT(&addr->sockaddr)) {
						CAPWAP_SET_NETWORK_PORT(&addr->sockaddr, CAPWAP_CONTROL_PORT);
					}
					addr->resolved = 1;
					g_wtp.discoverytype.type = CAPWAP_DISCOVERYTYPE_TYPE_STATIC;
				} else {
					capwap_logging_info("%s:%d Could not resolve application.acdiscovery.host %s", __FILE__, __LINE__, addr->fqdn);
				}
			}
			if (!capwap_sendto_fragmentpacket(g_wtp.net.socket, g_wtp.requestfragmentpacket, &addr->sockaddr)) {
				capwap_logging_info("Error to send discovery request packet");
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
void wtp_dfa_state_discovery(struct capwap_parsed_packet* packet)
{
	unsigned short binding;
	struct capwap_array* controlip;

	ASSERT(packet != NULL);

	/* */
	binding = GET_WBID_HEADER(packet->rxmngpacket->header);
	if ((binding == g_wtp.binding) &&
	    (packet->rxmngpacket->ctrlmsg.type == CAPWAP_DISCOVERY_RESPONSE) &&
	    (g_wtp.localseqnumber == packet->rxmngpacket->ctrlmsg.seq))
	{
		struct capwap_resultcode_element* resultcode;

		/* */
		g_wtp.localseqnumber++;

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
