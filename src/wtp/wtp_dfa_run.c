#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "wtp_dfa.h"

/* */
static int send_echo_request() {
	int result = -1;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_ECHO_REQUEST, g_wtp.localseqnumber++, g_wtp.mtu);

	/* Add message element */
	/* CAPWAP_ELEMENT_VENDORPAYLOAD */				/* TODO */

	/* Echo request complete, get fragment packets */
	wtp_free_reference_last_request();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, g_wtp.requestfragmentpacket, g_wtp.fragmentid);
	if (g_wtp.requestfragmentpacket->count > 1) {
		g_wtp.fragmentid++;
	}

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send echo request to AC */
	if (capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], g_wtp.requestfragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
		result = 0;
	} else {
		/* Error to send packets */
		capwap_logging_debug("Warning: error to send echo request packet");
		wtp_free_reference_last_request();
	}

	return result;
}

/* */
static int receive_echo_response(struct capwap_parsed_packet* packet) {
	struct capwap_resultcode_element* resultcode;

	ASSERT(packet != NULL);

	/* Check the success of the Request */
	resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
	if (resultcode && !CAPWAP_RESULTCODE_OK(resultcode->code)) {
		capwap_logging_warning("Receive Echo Response with error: %d", (int)resultcode->code);
		return 1;
	}

	/* Valid packet, free request packet */
	wtp_free_reference_last_request();
	return 0;
}

/* */
static void receive_reset_request(struct capwap_parsed_packet* packet) {
	unsigned short binding;

	ASSERT(packet != NULL);

	/* */
	binding = GET_WBID_HEADER(packet->rxmngpacket->header);
	if ((binding == g_wtp.binding) && IS_SEQUENCE_SMALLER(g_wtp.remoteseqnumber, packet->rxmngpacket->ctrlmsg.seq)) {
		struct capwap_header_data capwapheader;
		struct capwap_packet_txmng* txmngpacket;
		struct capwap_resultcode_element resultcode = { .code = CAPWAP_RESULTCODE_SUCCESS };

		/* Build packet */
		capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
		txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_RESET_RESPONSE, packet->rxmngpacket->ctrlmsg.seq, g_wtp.mtu);

		/* Add message element */
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RESULTCODE, &resultcode);
		/* CAPWAP_ELEMENT_VENDORPAYLOAD */				/* TODO */

		/* Reset response complete, get fragment packets */
		wtp_free_reference_last_response();
		capwap_packet_txmng_get_fragment_packets(txmngpacket, g_wtp.responsefragmentpacket, g_wtp.fragmentid);
		if (g_wtp.responsefragmentpacket->count > 1) {
			g_wtp.fragmentid++;
		}

		/* Free packets manager */
		capwap_packet_txmng_free(txmngpacket);

		/* Save remote sequence number */
		g_wtp.remoteseqnumber = packet->rxmngpacket->ctrlmsg.seq;
		capwap_get_packet_digest(packet->rxmngpacket, packet->connection, g_wtp.lastrecvpackethash);

		/* Send Reset response to AC */
		if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], g_wtp.responsefragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
			capwap_logging_debug("Warning: error to send reset response packet");
		}
	}
}

/* */
static void receive_ieee80211_wlan_configuration_request(struct capwap_parsed_packet* packet) {
	unsigned short binding;

	ASSERT(packet != NULL);

	/* */
	binding = GET_WBID_HEADER(packet->rxmngpacket->header);
	if ((binding == g_wtp.binding) && IS_SEQUENCE_SMALLER(g_wtp.remoteseqnumber, packet->rxmngpacket->ctrlmsg.seq)) {
		struct capwap_header_data capwapheader;
		struct capwap_packet_txmng* txmngpacket;
		struct capwap_resultcode_element resultcode = { .code = CAPWAP_RESULTCODE_SUCCESS };

		/* Build packet */
		capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
		txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_IEEE80211_WLAN_CONFIGURATION_RESPONSE, packet->rxmngpacket->ctrlmsg.seq, g_wtp.mtu);

		/* Add message element */
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RESULTCODE, &resultcode);
		/* CAPWAP_ELEMENT_80211_ASSIGN_BSSID */			/* TODO */
		/* CAPWAP_ELEMENT_VENDORPAYLOAD */				/* TODO */

		/* IEEE802.11 WLAN Configuration response complete, get fragment packets */
		wtp_free_reference_last_response();
		capwap_packet_txmng_get_fragment_packets(txmngpacket, g_wtp.responsefragmentpacket, g_wtp.fragmentid);
		if (g_wtp.responsefragmentpacket->count > 1) {
			g_wtp.fragmentid++;
		}

		/* Free packets manager */
		capwap_packet_txmng_free(txmngpacket);

		/* Save remote sequence number */
		g_wtp.remoteseqnumber = packet->rxmngpacket->ctrlmsg.seq;
		capwap_get_packet_digest(packet->rxmngpacket, packet->connection, g_wtp.lastrecvpackethash);

		/* Send IEEE802.11 WLAN Configuration response to AC */
		if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], g_wtp.responsefragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
			capwap_logging_debug("Warning: error to send IEEE802.11 WLAN Configuration response packet");
		}
	}
}

/* */
void wtp_dfa_state_run(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	ASSERT(timeout != NULL);

	if (packet) {
		if (packet->rxmngpacket->isctrlpacket) {
			if (capwap_is_request_type(packet->rxmngpacket->ctrlmsg.type) || ((g_wtp.localseqnumber - 1) == packet->rxmngpacket->ctrlmsg.seq)) {
				switch (packet->rxmngpacket->ctrlmsg.type) {
					case CAPWAP_CONFIGURATION_UPDATE_REQUEST: {
						/* TODO */
						break;
					}

					case CAPWAP_CHANGE_STATE_EVENT_RESPONSE: {
						/* TODO */
						break;
					}

					case CAPWAP_ECHO_RESPONSE: {
						if (!receive_echo_response(packet)) {
							capwap_kill_timeout(timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
							capwap_set_timeout(g_wtp.dfa.rfcEchoInterval, timeout, CAPWAP_TIMER_CONTROL_ECHO);
						}

						break;
					}

					case CAPWAP_CLEAR_CONFIGURATION_REQUEST: {
						/* TODO */
						break;
					}

					case CAPWAP_WTP_EVENT_RESPONSE: {
						/* TODO */
						break;
					}

					case CAPWAP_DATA_TRANSFER_REQUEST: {
						/* TODO */
						break;
					}

					case CAPWAP_DATA_TRANSFER_RESPONSE: {
						/* TODO */
						break;
					}

					case CAPWAP_STATION_CONFIGURATION_REQUEST: {
						/* TODO */
						break;
					}

					case CAPWAP_RESET_REQUEST: {
						receive_reset_request(packet);
						capwap_set_timeout(0, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
						wtp_dfa_change_state(CAPWAP_RESET_STATE);
						break;
					}

					case CAPWAP_IEEE80211_WLAN_CONFIGURATION_REQUEST: {
						receive_ieee80211_wlan_configuration_request(packet);
						break;
					}
				}
			}
		} else {
			if (IS_FLAG_K_HEADER(packet->rxmngpacket->header) && capwap_is_enable_timeout(timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD)) {
				if (!memcmp(capwap_get_message_element_data(packet, CAPWAP_ELEMENT_SESSIONID), &g_wtp.sessionid, sizeof(struct capwap_sessionid_element))) {
					/* Receive Data Keep-Alive, wait for next packet */
					capwap_kill_timeout(timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD);
					capwap_set_timeout(g_wtp.dfa.rfcDataChannelKeepAlive, timeout, CAPWAP_TIMER_DATA_KEEPALIVE);
				}
			} else {
				/* TODO */

				/* Update data keep-alive timeout */
				if (!capwap_is_enable_timeout(timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD)) {
					capwap_set_timeout(g_wtp.dfa.rfcDataChannelKeepAlive, timeout, CAPWAP_TIMER_DATA_KEEPALIVE);
				}
			}
		}
	} else {
		if (capwap_is_timeout(timeout, CAPWAP_TIMER_CONTROL_CONNECTION)) {
			/* No response received */
			g_wtp.dfa.rfcRetransmitCount++;
			if (g_wtp.dfa.rfcRetransmitCount >= g_wtp.dfa.rfcMaxRetransmit) {
				/* Timeout run state */
				wtp_free_reference_last_request();
				wtp_teardown_connection(timeout);
			} else {
				/* Retransmit request */
				if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], g_wtp.requestfragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
					capwap_logging_debug("Warning: error to send request packet");
				}

				/* Update timeout */
				capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
			}
		} else if (capwap_is_timeout(timeout, CAPWAP_TIMER_CONTROL_ECHO)) {
			/* Disable echo timer */
			capwap_kill_timeout(timeout, CAPWAP_TIMER_CONTROL_ECHO);

			if (!send_echo_request()) {
				g_wtp.dfa.rfcRetransmitCount = 0;
				capwap_set_timeout(g_wtp.dfa.rfcRetransmitInterval, timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
			} else {
				wtp_teardown_connection(timeout);
			}
		} else if (capwap_is_timeout(timeout, CAPWAP_TIMER_DATA_KEEPALIVE)) {
			struct capwap_list* txfragpacket;
			struct capwap_header_data capwapheader;
			struct capwap_packet_txmng* txmngpacket;

			/* Build packet */
			capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
			capwap_header_set_keepalive_flag(&capwapheader, 1);
			txmngpacket = capwap_packet_txmng_create_data_message(&capwapheader, g_wtp.mtu);		/* CAPWAP_DONT_FRAGMENT */

			/* Add message element */
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_SESSIONID, &g_wtp.sessionid);

			/* Data keepalive complete, get fragment packets into local list */
			txfragpacket = capwap_list_create();
			capwap_packet_txmng_get_fragment_packets(txmngpacket, txfragpacket, 0);
			if (txfragpacket->count == 1) {
				/* Send Data keepalive to AC */
				if (capwap_crypt_sendto_fragmentpacket(&g_wtp.datadtls, g_wtp.acdatasock.socket[g_wtp.acdatasock.type], txfragpacket, &g_wtp.wtpdataaddress, &g_wtp.acdataaddress)) {
					capwap_kill_timeout(timeout, CAPWAP_TIMER_DATA_KEEPALIVE);
					capwap_set_timeout(g_wtp.dfa.rfcDataChannelDeadInterval, timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD);
				} else {
					/* Error to send packets */
					capwap_logging_debug("Warning: error to send data channel keepalive packet");
					wtp_teardown_connection(timeout);
				}
			} else {
				capwap_logging_debug("Warning: error to send data channel keepalive packet, fragment packet");
				wtp_teardown_connection(timeout);
			}

			/* Free packets manager */
			capwap_list_free(txfragpacket);
			capwap_packet_txmng_free(txmngpacket);
		} else if (capwap_is_timeout(timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD)) {
			/* Data Keep-Alive timeout */
			capwap_kill_timeout(timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD);
			wtp_teardown_connection(timeout);
		}
	}
}
