#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "capwap_array.h"
#include "capwap_list.h"
#include "wtp_dfa.h"

/* */
static unsigned long wtp_join_ac(struct capwap_element_join_response* joinresponse) {
	/* TODO: gestione richiesta 
		CAPWAP_JOIN_TO_IMAGE_DATA_STATE <-> CAPWAP_JOIN_TO_CONFIGURE_STATE
	*/
	
	/* Check DTLS data policy */
	if (!(g_wtp.validdtlsdatapolicy & joinresponse->acdescriptor->dtlspolicy)) {
		return CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE;
	}

	/* AC name associated */
	strcpy(g_wtp.acname.name, joinresponse->acname->name);
	
	/* DTLS data policy */
	g_wtp.dtlsdatapolicy = joinresponse->acdescriptor->dtlspolicy & g_wtp.validdtlsdatapolicy;
	
	return CAPWAP_JOIN_TO_CONFIGURE_STATE;
}

/* */
int wtp_dfa_state_dtlsconnect_to_join(struct capwap_packet* packet, struct timeout_control* timeout) {
	int i;
	int result = -1;
	int status = WTP_DFA_NO_PACKET;
	struct capwap_build_packet* buildpacket;

#ifdef DEBUG
	char sessionname[33];
#endif

	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);
	
	/* Reset DTLS counter */
	g_wtp.dfa.rfcFailedDTLSSessionCount = 0;
	
	/* Update status radio */
	g_wtp.descriptor.radiosinuse = wtp_update_radio_in_use();

	/* Generate session id */
	capwap_sessionid_generate(&g_wtp.sessionid);

#ifdef DEBUG
	capwap_sessionid_printf(&g_wtp.sessionid, sessionname);
	capwap_logging_debug("Create WTP sessionid: %s", sessionname);
#endif

	/* Build packet */
	buildpacket = capwap_tx_packet_create(CAPWAP_RADIOID_NONE, g_wtp.binding);
	buildpacket->isctrlmsg = 1;
	
	/* Prepare join request */
	capwap_build_packet_set_control_message_type(buildpacket, CAPWAP_JOIN_REQUEST, g_wtp.localseqnumber++);
	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_LOCATION_ELEMENT(&g_wtp.location));
	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_WTPBOARDDATA_ELEMENT(&g_wtp.boarddata));
	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_WTPDESCRIPTOR_ELEMENT(&g_wtp.descriptor));
	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_WTPNAME_ELEMENT(&g_wtp.name));
	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_SESSIONID_ELEMENT(&g_wtp.sessionid));
	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_WTPFRAMETUNNELMODE_ELEMENT(&g_wtp.mactunnel));
	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_WTPMACTYPE_ELEMENT(&g_wtp.mactype));

	if (g_wtp.binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		wtp_create_80211_wtpradioinformation_element(buildpacket);
	} else {
		capwap_logging_debug("Unknown capwap binding");
	}

	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_ECNSUPPORT_ELEMENT(&g_wtp.ecn));

	if (g_wtp.wtpctrladdress.ss_family == AF_INET) {
		struct capwap_localipv4_element addr;
		
		memcpy(&addr.address, &((struct sockaddr_in*)&g_wtp.wtpctrladdress)->sin_addr, sizeof(struct in_addr));
		capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_LOCALIPV4_ELEMENT(&addr));
	} else if (g_wtp.wtpctrladdress.ss_family == AF_INET6) {
		struct capwap_localipv6_element addr;
		
		memcpy(&addr.address, &((struct sockaddr_in6*)&g_wtp.wtpctrladdress)->sin6_addr, sizeof(struct in6_addr));
		capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_LOCALIPV6_ELEMENT(&addr));
	}

	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_TRANSPORT_ELEMENT(&g_wtp.transport));
	/* CAPWAP_CREATE_MAXIMUMMESSAGELENGTH_ELEMENT */	/* TODO */
	/* CAPWAP_CREATE_WTPREBOOTSTATISTICS_ELEMENT */		/* TODO */
	/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */	/* TODO */

	/* Create join request packet */
	if (!capwap_build_packet_validate(buildpacket, NULL)) {
		wtp_free_reference_last_request();
		result = capwap_fragment_build_packet(buildpacket, g_wtp.requestfragmentpacket, g_wtp.mtu, g_wtp.fragmentid);
		if (result == 1) {
			g_wtp.fragmentid++;
		}
	} else {
		capwap_logging_debug("Warning: build invalid join request packet");
	}

	capwap_build_packet_free(buildpacket);

	/* Send join request to AC */
	if (result >= 0) {
		for (i = 0; i < g_wtp.requestfragmentpacket->count; i++) {
			struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(g_wtp.requestfragmentpacket, i);
			ASSERT(txpacket != NULL);
			
			if (!capwap_crypt_sendto(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], txpacket->header, txpacket->packetsize, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
				capwap_logging_debug("Warning: error to send join request packet");
				result = -1;
				break;
			}
		}

		if (result == -1) {
			/* Error to send packets */
			wtp_free_reference_last_request();
			wtp_dfa_change_state(CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE);
		} else {
			g_wtp.dfa.rfcRetransmitCount = 0;
			capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
			wtp_dfa_change_state(CAPWAP_JOIN_STATE);
			status = WTP_DFA_ACCEPT_PACKET;
		}
	} else {
		wtp_dfa_change_state(CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE);
	}

	return status;
}

/* */
int wtp_dfa_state_join(struct capwap_packet* packet, struct timeout_control* timeout) {
	int status = WTP_DFA_ACCEPT_PACKET;
	
	ASSERT(timeout != NULL);

	if (packet) {
		if (!capwap_compare_ip(&g_wtp.acctrladdress, &packet->remoteaddr)) {
			struct capwap_build_packet* buildpacket;

			/* Parsing packet */
			buildpacket = capwap_rx_packet_create((void*)packet->header, packet->packetsize, packet->socket.isctrlsocket);
			if (buildpacket) {
				if (!capwap_build_packet_validate(buildpacket, NULL)) {
					unsigned short binding;
					
					/* */
					binding = GET_WBID_HEADER(&buildpacket->header);
					if ((binding == g_wtp.binding) && (ntohl(buildpacket->ctrlmsg.type) == CAPWAP_JOIN_RESPONSE) && ((g_wtp.localseqnumber - 1) == buildpacket->ctrlmsg.seq)) {
						struct capwap_element_join_response joinresponse;
						
						/* Valid packet, free request packet */
						wtp_free_reference_last_request();
						
						/* Join response info */
						capwap_init_element_join_response(&joinresponse, binding);
	
						/* Parsing elements list */
						if (capwap_parsing_element_join_response(&joinresponse, buildpacket->elementslist->first)) {
							wtp_dfa_change_state(wtp_join_ac(&joinresponse));
							status = WTP_DFA_NO_PACKET;
						}
												
						/* Free join response */
						capwap_free_element_join_response(&joinresponse, binding);
					}
				}

				/* Free */				
				capwap_build_packet_free(buildpacket);
			}
		}
	} else {
		int i;
		
		/* No Join response received */
		g_wtp.dfa.rfcRetransmitCount++;
		if (g_wtp.dfa.rfcRetransmitCount >= g_wtp.dfa.rfcMaxRetransmit) {
			/* Timeout join state */
			wtp_free_reference_last_request();
			wtp_dfa_change_state(CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE);
			status = WTP_DFA_NO_PACKET;
		} else {
			/* Retransmit join request */	
			for (i = 0; i < g_wtp.requestfragmentpacket->count; i++) {
				struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(g_wtp.requestfragmentpacket, i);
				ASSERT(txpacket != NULL);
				
				if (!capwap_crypt_sendto(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], txpacket->header, txpacket->packetsize, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
					capwap_logging_debug("Warning: error to send join request packet");
					break;
				}
			}
	
			/* Update timeout */
			capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		}
	}

	return status;
}

/* */
int wtp_dfa_state_join_to_configure(struct capwap_packet* packet, struct timeout_control* timeout) {
	unsigned long i;
	int result = -1;
	int status = WTP_DFA_NO_PACKET;
	struct capwap_build_packet* buildpacket;
	
	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);
	
	/* Build packet */
	buildpacket = capwap_tx_packet_create(CAPWAP_RADIOID_NONE, g_wtp.binding);
	buildpacket->isctrlmsg = 1;
	
	/* Prepare Configuration Status request */
	capwap_build_packet_set_control_message_type(buildpacket, CAPWAP_CONFIGURATION_STATUS_REQUEST, g_wtp.localseqnumber++);
	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_ACNAME_ELEMENT(&g_wtp.acname));
	
	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio* radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);
		struct capwap_radioadmstate_element radioadmstate;
		
		radioadmstate.radioid = (unsigned char)(i + 1);
		radioadmstate.state = ((radio->status == WTP_RADIO_DISABLED) ? CAPWAP_RADIO_ADMIN_STATE_DISABLED : CAPWAP_RADIO_ADMIN_STATE_ENABLED);
		capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_RADIOADMSTATE_ELEMENT(&radioadmstate));
	}
	
	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_STATISTICSTIMER_ELEMENT(&g_wtp.statisticstimer));
	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_WTPREBOOTSTAT_ELEMENT(&g_wtp.rebootstat));
	
	/* CAPWAP_CREATE_ACNAMEPRIORITY_ELEMENT */			/* TODO */
	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_TRANSPORT_ELEMENT(&g_wtp.transport));
	/* CAPWAP_CREATE_WTPSTATICIPADDRESS_ELEMENT */		/* TODO */
	/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */	/* TODO */

	if (g_wtp.binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		wtp_create_80211_wtpradioinformation_element(buildpacket);
	} else {
		capwap_logging_debug("Unknown capwap binding");
	}

	/* Create Configuration Status request packet */
	if (!capwap_build_packet_validate(buildpacket, NULL)) {
		wtp_free_reference_last_request();
		result = capwap_fragment_build_packet(buildpacket, g_wtp.requestfragmentpacket, g_wtp.mtu, g_wtp.fragmentid);
		if (result == 1) {
			g_wtp.fragmentid++;
		}
	} else {
		capwap_logging_debug("Warning: build invalid configuretion status request packet");
	}

	capwap_build_packet_free(buildpacket);

	/* Send Configuration Status request to AC */
	if (result >= 0) {
		for (i = 0; i < g_wtp.requestfragmentpacket->count; i++) {
			struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(g_wtp.requestfragmentpacket, i);
			ASSERT(txpacket != NULL);
			
			if (!capwap_crypt_sendto(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], txpacket->header, txpacket->packetsize, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
				capwap_logging_debug("Warning: error to send configuration status request packet");
				result = -1;
				break;
			}
		}

		if (result == -1) {
			/* Error to send packets */
			wtp_free_reference_last_request();
			wtp_dfa_change_state(CAPWAP_CONFIGURE_TO_DTLS_TEARDOWN_STATE);
		} else {
			g_wtp.dfa.rfcRetransmitCount = 0;
			capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
			wtp_dfa_change_state(CAPWAP_CONFIGURE_STATE);
			status = WTP_DFA_ACCEPT_PACKET;
		}
	} else {
		wtp_dfa_change_state(CAPWAP_CONFIGURE_TO_DTLS_TEARDOWN_STATE);
	}

	return status;
}

/* */
int wtp_dfa_state_join_to_dtlsteardown(struct capwap_packet* packet, struct timeout_control* timeout) {
	ASSERT(packet == NULL);
	ASSERT(timeout != NULL);

	return wtp_teardown_connection(timeout);
}
