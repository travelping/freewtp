#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "capwap_array.h"
#include "capwap_list.h"
#include "wtp_dfa.h"

/* */
static unsigned long wtp_configure_ac(struct capwap_element_configurationstatus_response* configureresponse) {
	/* TODO: gestione richiesta */

	/* */
	g_wtp.dfa.rfcMaxDiscoveryInterval = configureresponse->timers->discovery;
	g_wtp.dfa.rfcEchoInterval = configureresponse->timers->echorequest;

	return CAPWAP_CONFIGURE_TO_DATA_CHECK_STATE;
}

/* */
int wtp_dfa_state_configure(struct capwap_packet* packet, struct timeout_control* timeout) {
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
					if ((binding == g_wtp.binding) && (ntohl(buildpacket->ctrlmsg.type) == CAPWAP_CONFIGURATION_STATUS_RESPONSE) && ((g_wtp.localseqnumber - 1) == buildpacket->ctrlmsg.seq)) {
						struct capwap_element_configurationstatus_response configureresponse;
						
						/* Valid packet, free request packet */
						wtp_free_reference_last_request();
						
						/* Configuration status response info */
						capwap_init_element_configurationstatus_response(&configureresponse, binding);
	
						/* Parsing elements list */
						if (capwap_parsing_element_configurationstatus_response(&configureresponse, buildpacket->elementslist->first)) {
							wtp_dfa_change_state(wtp_configure_ac(&configureresponse));
							status = WTP_DFA_NO_PACKET;
						}
						
						/* Free join response */
						capwap_free_element_configurationstatus_response(&configureresponse, binding);
					}
				}

				/* Free */				
				capwap_build_packet_free(buildpacket);
			}
		}
	} else {
		int i;
		
		/* No Configuration status response received */
		g_wtp.dfa.rfcRetransmitCount++;
		if (g_wtp.dfa.rfcRetransmitCount >= g_wtp.dfa.rfcMaxRetransmit) {
			/* Timeout join state */
			wtp_free_reference_last_request();
			wtp_dfa_change_state(CAPWAP_CONFIGURE_TO_DTLS_TEARDOWN_STATE);
			status = WTP_DFA_NO_PACKET;
		} else {
			/* Retransmit configuration request */	
			for (i = 0; i < g_wtp.requestfragmentpacket->count; i++) {
				struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(g_wtp.requestfragmentpacket, i);
				ASSERT(txpacket != NULL);
				
				if (!capwap_crypt_sendto(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], txpacket->header, txpacket->packetsize, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
					capwap_logging_debug("Warning: error to send configuration status request packet");
					break;
				}
			}
	
			/* Update timeout */
			capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		}
	}

	return status;
}

int wtp_dfa_state_configure_to_datacheck(struct capwap_packet* packet, struct timeout_control* timeout) {
	unsigned long i;
	int result = -1;
	int status = WTP_DFA_NO_PACKET;
	struct capwap_build_packet* buildpacket;
	struct capwap_resultcode_element resultcode;
	
	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);
	
	/* Build packet */
	buildpacket = capwap_tx_packet_create(CAPWAP_RADIOID_NONE, g_wtp.binding);
	buildpacket->isctrlmsg = 1;
	
	/* Prepare change state event request */
	capwap_build_packet_set_control_message_type(buildpacket, CAPWAP_CHANGE_STATE_EVENT_REQUEST, g_wtp.localseqnumber++);
	
	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio* radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);
		struct capwap_radiooprstate_element radiooprstate;
		
		radiooprstate.radioid = (unsigned char)(i + 1);
		radiooprstate.state = ((radio->status == WTP_RADIO_ENABLED) ? CAPWAP_RADIO_OPERATIONAL_STATE_ENABLED : CAPWAP_RADIO_OPERATIONAL_STATE_DISABLED);
		
		if (radiooprstate.state == WTP_RADIO_ENABLED) {
			radiooprstate.cause = CAPWAP_RADIO_OPERATIONAL_CAUSE_NORMAL;
		} else if (radiooprstate.state == WTP_RADIO_DISABLED) {
			radiooprstate.cause = CAPWAP_RADIO_OPERATIONAL_CAUSE_ADMINSET;
		} else if (radiooprstate.state == WTP_RADIO_HWFAILURE) {
			radiooprstate.cause = CAPWAP_RADIO_OPERATIONAL_CAUSE_RADIOFAILURE;
		} else if (radiooprstate.state == WTP_RADIO_SWFAILURE) {
			radiooprstate.cause = CAPWAP_RADIO_OPERATIONAL_CAUSE_SOFTWAREFAILURE;
		}

		capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_RADIOOPRSTATE_ELEMENT(&radiooprstate));
	}
	
	resultcode.code = CAPWAP_RESULTCODE_SUCCESS;
	capwap_build_packet_add_message_element(buildpacket, CAPWAP_CREATE_RESULTCODE_ELEMENT(&resultcode));
	/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */	/* TODO */

	/* Create change state event request packet */
	if (!capwap_build_packet_validate(buildpacket, NULL)) {
		wtp_free_reference_last_request();
		result = capwap_fragment_build_packet(buildpacket, g_wtp.requestfragmentpacket, g_wtp.mtu, g_wtp.fragmentid);
		if (result == 1) {
			g_wtp.fragmentid++;
		}
	} else {
		capwap_logging_debug("Warning: build invalid change state event request packet");
	}

	capwap_build_packet_free(buildpacket);

	/* Send change state event request to AC */
	if (result >= 0) {
		for (i = 0; i < g_wtp.requestfragmentpacket->count; i++) {
			struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(g_wtp.requestfragmentpacket, i);
			ASSERT(txpacket != NULL);
			
			if (!capwap_crypt_sendto(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], txpacket->header, txpacket->packetsize, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
				capwap_logging_debug("Warning: error to send change state event request packet");
				result = -1;
				break;
			}
		}

		if (result == -1) {
			/* Error to send packets */
			wtp_free_reference_last_request();
			wtp_dfa_change_state(CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
		} else {
			g_wtp.dfa.rfcRetransmitCount = 0;
			capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
			wtp_dfa_change_state(CAPWAP_DATA_CHECK_STATE);
			status = WTP_DFA_ACCEPT_PACKET;
		}
	} else {
		wtp_dfa_change_state(CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE);
	}

	return status;
}

/* */
int wtp_dfa_state_configure_to_dtlsteardown(struct capwap_packet* packet, struct timeout_control* timeout) {
	ASSERT(packet == NULL);
	ASSERT(timeout != NULL);

	return wtp_teardown_connection(timeout);
}
