#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "wtp_dfa.h"
#include "wtp_radio.h"

/* */
static int send_echo_request(void) {
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
		int action = 0;
		struct capwap_header_data capwapheader;
		struct capwap_packet_txmng* txmngpacket;
		struct capwap_80211_assignbssid_element bssid;
		struct capwap_resultcode_element resultcode = { .code = CAPWAP_RESULTCODE_FAILURE };

		/* Parsing request message */
		if (capwap_get_message_element(packet, CAPWAP_ELEMENT_80211_ADD_WLAN)) {
			action = CAPWAP_ELEMENT_80211_ADD_WLAN;
			resultcode.code = wtp_radio_create_wlan(packet, &bssid);
		} else if (capwap_get_message_element(packet, CAPWAP_ELEMENT_80211_UPDATE_WLAN)) {
			action = CAPWAP_ELEMENT_80211_UPDATE_WLAN;
			resultcode.code = wtp_radio_update_wlan(packet);
		} else if (capwap_get_message_element(packet, CAPWAP_ELEMENT_80211_DELETE_WLAN)) {
			action = CAPWAP_ELEMENT_80211_DELETE_WLAN;
			resultcode.code = wtp_radio_delete_wlan(packet);
		}

		/* Build packet */
		capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
		txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_IEEE80211_WLAN_CONFIGURATION_RESPONSE, packet->rxmngpacket->ctrlmsg.seq, g_wtp.mtu);

		/* Add message element */
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RESULTCODE, &resultcode);
		if ((resultcode.code == CAPWAP_RESULTCODE_SUCCESS) && (action == CAPWAP_ELEMENT_80211_ADD_WLAN)) {
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_ASSIGN_BSSID, &bssid);
		}

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
static void send_data_keepalive_request() {
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
			capwap_timeout_kill(g_wtp.timeout, CAPWAP_TIMER_DATA_KEEPALIVE);
			capwap_timeout_set(g_wtp.dfa.rfcDataChannelDeadInterval, g_wtp.timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD);
		} else {
			/* Error to send packets */
			capwap_logging_debug("Warning: error to send data channel keepalive packet");
			wtp_teardown_connection();
		}
	} else {
		capwap_logging_debug("Warning: error to send data channel keepalive packet, fragment packet");
		wtp_teardown_connection();
	}

	/* Free packets manager */
	capwap_list_free(txfragpacket);
	capwap_packet_txmng_free(txmngpacket);
}

/* */
void wtp_send_data_wireless_packet(uint8_t radioid, uint8_t wlanid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength, int leavenativeframe) {
	struct capwap_list* txfragpacket;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;

	/* Build packet */
	capwap_header_init(&capwapheader, radioid, g_wtp.binding);
	capwap_header_set_nativeframe_flag(&capwapheader, leavenativeframe);
	txmngpacket = capwap_packet_txmng_create_data_message(&capwapheader, g_wtp.mtu);

	/* */
	if (leavenativeframe) {
		capwap_packet_txmng_add_data(txmngpacket, (uint8_t*)mgmt, (unsigned short)mgmtlength);
	} else {
		/* TODO */
	}

	/* Data message complete, get fragment packets into local list */
	txfragpacket = capwap_list_create();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, txfragpacket, 0);
	if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.datadtls, g_wtp.acdatasock.socket[g_wtp.acdatasock.type], txfragpacket, &g_wtp.wtpdataaddress, &g_wtp.acdataaddress)) {
		capwap_logging_debug("Warning: error to send data packet");
	}

	/* Free packets manager */
	capwap_list_free(txfragpacket);
	capwap_packet_txmng_free(txmngpacket);
}

/* */
void wtp_dfa_state_run(struct capwap_parsed_packet* packet) {
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
							capwap_timeout_kill(g_wtp.timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
							capwap_timeout_set(g_wtp.dfa.rfcEchoInterval, g_wtp.timeout, CAPWAP_TIMER_CONTROL_ECHO);
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
						capwap_timeout_set(0, g_wtp.timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
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
			if (IS_FLAG_K_HEADER(packet->rxmngpacket->header) && capwap_timeout_isenable(g_wtp.timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD)) {
				if (!memcmp(capwap_get_message_element_data(packet, CAPWAP_ELEMENT_SESSIONID), &g_wtp.sessionid, sizeof(struct capwap_sessionid_element))) {
					/* Receive Data Keep-Alive, wait for next packet */
					capwap_timeout_kill(g_wtp.timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD);
					capwap_timeout_set(g_wtp.dfa.rfcDataChannelKeepAlive, g_wtp.timeout, CAPWAP_TIMER_DATA_KEEPALIVE);
				}
			} else {
				/* TODO */

				/* Update data keep-alive timeout */
				if (!capwap_timeout_isenable(g_wtp.timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD)) {
					capwap_timeout_set(g_wtp.dfa.rfcDataChannelKeepAlive, g_wtp.timeout, CAPWAP_TIMER_DATA_KEEPALIVE);
				}
			}
		}
	} else {
		if (capwap_timeout_hasexpired(g_wtp.timeout, CAPWAP_TIMER_CONTROL_CONNECTION)) {
			/* No response received */
			g_wtp.dfa.rfcRetransmitCount++;
			if (g_wtp.dfa.rfcRetransmitCount >= g_wtp.dfa.rfcMaxRetransmit) {
				/* Timeout run state */
				wtp_free_reference_last_request();
				wtp_teardown_connection();
			} else {
				/* Retransmit request */
				if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], g_wtp.requestfragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
					capwap_logging_debug("Warning: error to send request packet");
				}

				/* Update timeout */
				capwap_timeout_set(g_wtp.dfa.rfcRetransmitInterval, g_wtp.timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
			}
		} else if (capwap_timeout_hasexpired(g_wtp.timeout, CAPWAP_TIMER_CONTROL_ECHO)) {
			/* Disable echo timer */
			capwap_timeout_kill(g_wtp.timeout, CAPWAP_TIMER_CONTROL_ECHO);

			if (!send_echo_request()) {
				g_wtp.dfa.rfcRetransmitCount = 0;
				capwap_timeout_set(g_wtp.dfa.rfcRetransmitInterval, g_wtp.timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
			} else {
				wtp_teardown_connection();
			}
		} else if (capwap_timeout_hasexpired(g_wtp.timeout, CAPWAP_TIMER_DATA_KEEPALIVE)) {
			send_data_keepalive_request();
		} else if (capwap_timeout_hasexpired(g_wtp.timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD)) {
			/* Data Keep-Alive timeout */
			capwap_timeout_kill(g_wtp.timeout, CAPWAP_TIMER_DATA_KEEPALIVEDEAD);
			wtp_teardown_connection();
		}
	}
}
