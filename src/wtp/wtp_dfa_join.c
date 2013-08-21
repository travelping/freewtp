#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "capwap_array.h"
#include "capwap_list.h"
#include "wtp_dfa.h"

/* */
static unsigned long wtp_join_ac(struct capwap_parsed_packet* packet) {
	struct capwap_acdescriptor_element* acdescriptor;
	struct capwap_acname_element* acname;
	struct capwap_resultcode_element* resultcode;

	/* Check the success of the Request */
	resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
	if (resultcode && !CAPWAP_RESULTCODE_OK(resultcode->code)) {
		capwap_logging_warning("Receive Join Response with error: %d", (int)resultcode->code);
		return CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE;
	}

	/* TODO: gestione richiesta 
		CAPWAP_JOIN_TO_IMAGE_DATA_STATE <-> CAPWAP_JOIN_TO_CONFIGURE_STATE
	*/
	
	/* Check DTLS data policy */
	acdescriptor = (struct capwap_acdescriptor_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_ACDESCRIPTION);
	if (!(g_wtp.validdtlsdatapolicy & acdescriptor->dtlspolicy)) {
		return CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE;
	}

	/* AC name associated */
	acname = (struct capwap_acname_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_ACNAME);
	g_wtp.acname.name = (uint8_t*)capwap_duplicate_string((const char*)acname->name);

	/* DTLS data policy */
	g_wtp.dtlsdatapolicy = acdescriptor->dtlspolicy & g_wtp.validdtlsdatapolicy;
	
	return CAPWAP_JOIN_TO_CONFIGURE_STATE;
}

/* */
int wtp_dfa_state_dtlsconnect_to_join(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	int status = WTP_DFA_NO_PACKET;

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
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_JOIN_REQUEST, g_wtp.localseqnumber++, g_wtp.mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_LOCATION, &g_wtp.location);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPBOARDDATA, &g_wtp.boarddata);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPDESCRIPTOR, &g_wtp.descriptor);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPNAME, &g_wtp.name);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_SESSIONID, &g_wtp.sessionid);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPFRAMETUNNELMODE, &g_wtp.mactunnel);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPMACTYPE, &g_wtp.mactype);

	if (g_wtp.binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		wtp_create_80211_wtpradioinformation_element(txmngpacket);
	}

	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ECNSUPPORT, &g_wtp.ecn);

	if (g_wtp.wtpctrladdress.ss_family == AF_INET) {
		struct capwap_localipv4_element addr;

		memcpy(&addr.address, &((struct sockaddr_in*)&g_wtp.wtpctrladdress)->sin_addr, sizeof(struct in_addr));
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_LOCALIPV4, &addr);
	} else if (g_wtp.wtpctrladdress.ss_family == AF_INET6) {
		struct capwap_localipv6_element addr;

		memcpy(&addr.address, &((struct sockaddr_in6*)&g_wtp.wtpctrladdress)->sin6_addr, sizeof(struct in6_addr));
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_LOCALIPV6, &addr);
	}

	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_TRANSPORT, &g_wtp.transport);
	/* CAPWAP_ELEMENT_MAXIMUMLENGTH */					/* TODO */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPREBOOTSTAT, &g_wtp.rebootstat);
	/* CAPWAP_ELEMENT_VENDORPAYLOAD */					/* TODO */

	/* Join request complete, get fragment packets */
	wtp_free_reference_last_request();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, g_wtp.requestfragmentpacket, g_wtp.fragmentid);
	if (g_wtp.requestfragmentpacket->count > 1) {
		g_wtp.fragmentid++;
	}

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send join request to AC */
	if (capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], g_wtp.requestfragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
		g_wtp.dfa.rfcRetransmitCount = 0;
		capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		wtp_dfa_change_state(CAPWAP_JOIN_STATE);
		status = WTP_DFA_ACCEPT_PACKET;
	} else {
		/* Error to send packets */
		capwap_logging_debug("Warning: error to send join request packet");
		wtp_free_reference_last_request();
		wtp_dfa_change_state(CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE);
	}

	return status;
}

/* */
int wtp_dfa_state_join(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	int status = WTP_DFA_ACCEPT_PACKET;
	
	ASSERT(timeout != NULL);

	if (packet) {
		unsigned short binding;

		/* */
		binding = GET_WBID_HEADER(packet->rxmngpacket->header);
		if (packet->rxmngpacket->isctrlpacket && (binding == g_wtp.binding) && (packet->rxmngpacket->ctrlmsg.type == CAPWAP_JOIN_RESPONSE) && ((g_wtp.localseqnumber - 1) == packet->rxmngpacket->ctrlmsg.seq)) {
			/* Valid packet, free request packet */
			wtp_free_reference_last_request();

			/* Parsing response values  */
			wtp_dfa_change_state(wtp_join_ac(packet));
			status = WTP_DFA_NO_PACKET;
		}
	} else {
		/* No Join response received */
		g_wtp.dfa.rfcRetransmitCount++;
		if (g_wtp.dfa.rfcRetransmitCount >= g_wtp.dfa.rfcMaxRetransmit) {
			/* Timeout join state */
			wtp_free_reference_last_request();
			wtp_dfa_change_state(CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE);
			status = WTP_DFA_NO_PACKET;
		} else {
			/* Retransmit join request */
			if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], g_wtp.requestfragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
				capwap_logging_debug("Warning: error to send join request packet");
			}

			/* Update timeout */
			capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		}
	}

	return status;
}

/* */
int wtp_dfa_state_join_to_configure(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	int status = WTP_DFA_NO_PACKET;

	ASSERT(timeout != NULL);
	ASSERT(packet == NULL);

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_CONFIGURATION_STATUS_REQUEST, g_wtp.localseqnumber++, g_wtp.mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ACNAME, &g_wtp.acname);
	wtp_create_radioadmstate_element(txmngpacket);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_STATISTICSTIMER, &g_wtp.statisticstimer);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_WTPREBOOTSTAT, &g_wtp.rebootstat);
	/* CAPWAP_ELEMENT_ACNAMEPRIORITY */					/* TODO */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_TRANSPORT, &g_wtp.transport);
	/* CAPWAP_ELEMENT_WTPSTATICIPADDRESS */				/* TODO */
	/* CAPWAP_ELEMENT_80211_ANTENNA */					/* TODO */
	/* CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL */	/* TODO */
	/* CAPWAP_ELEMENT_80211_MACOPERATION */				/* TODO */
	/* CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY */	/* TODO */
	/* CAPWAP_ELEMENT_80211_OFDMCONTROL */				/* TODO */
	/* CAPWAP_ELEMENT_80211_SUPPORTEDRATES */			/* TODO */
	/* CAPWAP_ELEMENT_80211_TXPOWER */					/* TODO */
	/* CAPWAP_ELEMENT_80211_TXPOWERLEVEL */				/* TODO */
	/* CAPWAP_ELEMENT_80211_WTP_RADIO_CONF */			/* TODO */

	if (g_wtp.binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		wtp_create_80211_wtpradioinformation_element(txmngpacket);
	}

	/* CAPWAP_ELEMENT_VENDORPAYLOAD */					/* TODO */

	/* Configuration Status request complete, get fragment packets */
	wtp_free_reference_last_request();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, g_wtp.requestfragmentpacket, g_wtp.fragmentid);
	if (g_wtp.requestfragmentpacket->count > 1) {
		g_wtp.fragmentid++;
	}

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send Configuration Status request to AC */
	if (capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], g_wtp.requestfragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
		g_wtp.dfa.rfcRetransmitCount = 0;
		capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		wtp_dfa_change_state(CAPWAP_CONFIGURE_STATE);
		status = WTP_DFA_ACCEPT_PACKET;
	} else {
		/* Error to send packets */
		capwap_logging_debug("Warning: error to send configuration status request packet");
		wtp_free_reference_last_request();
		wtp_dfa_change_state(CAPWAP_CONFIGURE_TO_DTLS_TEARDOWN_STATE);
	}

	return status;
}

/* */
int wtp_dfa_state_join_to_dtlsteardown(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	ASSERT(packet == NULL);
	ASSERT(timeout != NULL);

	return wtp_teardown_connection(timeout);
}
