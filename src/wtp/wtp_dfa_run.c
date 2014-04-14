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
static void receive_station_configuration_request(struct capwap_parsed_packet* packet) {
	unsigned short binding;

	ASSERT(packet != NULL);

	/* */
	binding = GET_WBID_HEADER(packet->rxmngpacket->header);
	if ((binding == g_wtp.binding) && IS_SEQUENCE_SMALLER(g_wtp.remoteseqnumber, packet->rxmngpacket->ctrlmsg.seq)) {
		struct capwap_header_data capwapheader;
		struct capwap_packet_txmng* txmngpacket;
		struct capwap_resultcode_element resultcode = { .code = CAPWAP_RESULTCODE_FAILURE };

		/* Parsing request message */
		if (capwap_get_message_element(packet, CAPWAP_ELEMENT_ADDSTATION)) {
			resultcode.code = wtp_radio_add_station(packet);
		} else if (capwap_get_message_element(packet, CAPWAP_ELEMENT_DELETESTATION)) {
			resultcode.code = wtp_radio_delete_station(packet);
		}

		/* Build packet */
		capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
		txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_STATION_CONFIGURATION_RESPONSE, packet->rxmngpacket->ctrlmsg.seq, g_wtp.mtu);

		/* Add message element */
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RESULTCODE, &resultcode);
		/* CAPWAP_ELEMENT_VENDORPAYLOAD */				/* TODO */

		/* Station Configuration response complete, get fragment packets */
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

		/* Send Station Configuration response to AC */
		if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, g_wtp.acctrlsock.socket[g_wtp.acctrlsock.type], g_wtp.responsefragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
			capwap_logging_debug("Warning: error to send Station Configuration response packet");
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
			capwap_timeout_unset(g_wtp.timeout, g_wtp.idtimerkeepalive);
			capwap_timeout_set(g_wtp.timeout, g_wtp.idtimerkeepalivedead, WTP_DATACHANNEL_KEEPALIVEDEAD, wtp_dfa_state_run_keepalivedead_timeout, NULL, NULL);
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
void wtp_send_data_packet(uint8_t radioid, uint8_t wlanid, const uint8_t* data, int length, int leavenativeframe) {
	struct capwap_list* txfragpacket;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;

	/* Build packet */
	capwap_header_init(&capwapheader, radioid, g_wtp.binding);
	capwap_header_set_nativeframe_flag(&capwapheader, (leavenativeframe ? 1: 0));
	txmngpacket = capwap_packet_txmng_create_data_message(&capwapheader, g_wtp.mtu);

	/* */
	if (leavenativeframe) {
		capwap_packet_txmng_add_data(txmngpacket, data, (unsigned short)length);
	} else {
		/* TODO */
	}

	/* Data message complete, get fragment packets into local list */
	txfragpacket = capwap_list_create();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, txfragpacket, g_wtp.fragmentid);
	if (txfragpacket->count > 1) {
		g_wtp.fragmentid++;
	}

	if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.datadtls, g_wtp.acdatasock.socket[g_wtp.acdatasock.type], txfragpacket, &g_wtp.wtpdataaddress, &g_wtp.acdataaddress)) {
		capwap_logging_debug("Warning: error to send data packet");
	}

	/* Free packets manager */
	capwap_list_free(txfragpacket);
	capwap_packet_txmng_free(txmngpacket);
}

/* */
void wtp_dfa_state_run_echo_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	if (!send_echo_request()) {
		g_wtp.retransmitcount = 0;
		capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_RETRANSMIT_INTERVAL, wtp_dfa_retransmition_timeout, NULL, NULL);
	} else {
		wtp_teardown_connection();
	}
}

/* */
void wtp_dfa_state_run_keepalive_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	send_data_keepalive_request();
}

/* */
void wtp_dfa_state_run_keepalivedead_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	wtp_teardown_connection();
}

/* */
void wtp_dfa_state_run(struct capwap_parsed_packet* packet) {
	ASSERT(packet != NULL);

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
						capwap_timeout_unset(g_wtp.timeout, g_wtp.idtimercontrol);
						capwap_timeout_set(g_wtp.timeout, g_wtp.idtimerecho, g_wtp.echointerval, wtp_dfa_state_run_echo_timeout, NULL, NULL);
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
					receive_station_configuration_request(packet);
					break;
				}

				case CAPWAP_RESET_REQUEST: {
					receive_reset_request(packet);
					wtp_dfa_change_state(CAPWAP_RESET_STATE);
					wtp_dfa_state_reset();
					break;
				}

				case CAPWAP_IEEE80211_WLAN_CONFIGURATION_REQUEST: {
					receive_ieee80211_wlan_configuration_request(packet);
					break;
				}
			}
		}
	} else {
		if (IS_FLAG_K_HEADER(packet->rxmngpacket->header)) {
			if (!memcmp(capwap_get_message_element_data(packet, CAPWAP_ELEMENT_SESSIONID), &g_wtp.sessionid, sizeof(struct capwap_sessionid_element))) {
				/* Receive Data Keep-Alive, wait for next packet */
				capwap_timeout_unset(g_wtp.timeout, g_wtp.idtimerkeepalivedead);
				capwap_timeout_set(g_wtp.timeout, g_wtp.idtimerkeepalive, WTP_DATACHANNEL_KEEPALIVE_INTERVAL, wtp_dfa_state_run_keepalive_timeout, NULL, NULL);
			}
		} else {
			/* TODO */
		}
	}
}
