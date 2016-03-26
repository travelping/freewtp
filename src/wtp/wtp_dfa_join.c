#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "capwap_array.h"
#include "capwap_list.h"
#include "wtp_dfa.h"
#include "wtp_radio.h"

/* */
void wtp_send_join(void)
{
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;

	/* Reset DTLS counter */
	g_wtp.faileddtlssessioncount = 0;

	/* Update status radio */
	g_wtp.descriptor.radiosinuse = wtp_update_radio_in_use();

	/* Generate session id */
	capwap_sessionid_generate(&g_wtp.sessionid);

#ifdef DEBUG
	do {
		char sessionname[33];

		capwap_sessionid_printf(&g_wtp.sessionid, sessionname);
		capwap_logging_debug("Create WTP sessionid: %s", sessionname);
	} while (0);
#endif

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader,
							      CAPWAP_JOIN_REQUEST,
							      g_wtp.localseqnumber, g_wtp.mtu);

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

	if (g_wtp.dtls.localaddr.ss.ss_family == AF_INET) {
		struct capwap_localipv4_element addr;

		memcpy(&addr.address, &g_wtp.dtls.localaddr.sin.sin_addr, sizeof(struct in_addr));
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_LOCALIPV4, &addr);
	} else if (g_wtp.dtls.localaddr.ss.ss_family == AF_INET6) {
		struct capwap_localipv6_element addr;

		memcpy(&addr.address, &g_wtp.dtls.localaddr.sin6.sin6_addr, sizeof(struct in6_addr));
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
	if (capwap_crypt_sendto_fragmentpacket(&g_wtp.dtls, g_wtp.requestfragmentpacket)) {
		g_wtp.retransmitcount = 0;
		wtp_dfa_change_state(CAPWAP_JOIN_STATE);
		capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_RETRANSMIT_INTERVAL, wtp_dfa_retransmition_timeout, NULL, NULL);
	} else {
		/* Error to send packets */
		capwap_logging_debug("Warning: error to send join request packet");
		wtp_free_reference_last_request();
		wtp_teardown_connection();
	}
}

/* */
void wtp_dfa_state_join(struct capwap_parsed_packet* packet)
{
	unsigned short binding;
	struct capwap_acdescriptor_element* acdescriptor;
	struct capwap_acname_element* acname;
	struct capwap_resultcode_element* resultcode;

	/* */
	binding = GET_WBID_HEADER(packet->rxmngpacket->header);
	if ((binding == g_wtp.binding) && (packet->rxmngpacket->ctrlmsg.type == CAPWAP_JOIN_RESPONSE) && (g_wtp.localseqnumber == packet->rxmngpacket->ctrlmsg.seq)) {
		g_wtp.localseqnumber++;

		/* Valid packet, free request packet */
		wtp_free_reference_last_request();

		/* Check the success of the Request */
		resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
		if (resultcode && !CAPWAP_RESULTCODE_OK(resultcode->code)) {
			capwap_logging_warning("Receive Join Response with error: %d", (int)resultcode->code);
			wtp_teardown_connection();
		} else {
			/* TODO: gestione richiesta CAPWAP_IMAGE_DATA_STATE <-> CAPWAP_CONFIGURE_STATE */

			/* Check DTLS data policy */
			acdescriptor = (struct capwap_acdescriptor_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_ACDESCRIPTION);
			if (g_wtp.validdtlsdatapolicy & acdescriptor->dtlspolicy) {
				/* AC name associated */
				acname = (struct capwap_acname_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_ACNAME);
				g_wtp.acname.name = (uint8_t*)capwap_duplicate_string((const char*)acname->name);

				/* DTLS data policy */
				g_wtp.dtlsdatapolicy = acdescriptor->dtlspolicy & g_wtp.validdtlsdatapolicy;

				/* Binding values */
				if (!wtp_radio_setconfiguration(packet)) {
					wtp_send_configure();						/* Send configuration packet */
				} else {
					capwap_logging_warning("Receive Join Response with invalid elements");
					wtp_teardown_connection();
				}
			} else {
				capwap_logging_warning("Receive Join Response with invalid DTLS data policy");
				wtp_teardown_connection();
			}
		}
	}
}
