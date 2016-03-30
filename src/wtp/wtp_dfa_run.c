#include "wtp.h"
#include "capwap_dfa.h"
#include "capwap_element.h"
#include "wtp_dfa.h"
#include "wtp_radio.h"
#include "ieee80211.h"

/* ev timer callbacks */
static void wtp_dfa_state_run_echo_timeout(EV_P_ ev_timer *w, int revents);
static void wtp_dfa_state_run_keepalive_timeout(EV_P_ ev_timer *w, int revents);
static void wtp_dfa_state_run_keepalivedead_timeout(EV_P_ ev_timer *w, int revents);

/* */
static int send_echo_request(void)
{
	int result = -1;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_ECHO_REQUEST,
							      g_wtp.localseqnumber, g_wtp.mtu);

	/* Add message element */
	/* CAPWAP_ELEMENT_VENDORPAYLOAD */				/* TODO */

	/* Echo request complete, get fragment packets */
	wtp_free_reference_last_request();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, g_wtp.requestfragmentpacket, g_wtp.fragmentid);
	if (g_wtp.requestfragmentpacket->count > 1)
		g_wtp.fragmentid++;

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send echo request to AC */
	if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.dtls, g_wtp.requestfragmentpacket)) {
		/* Error to send packets */
		capwap_logging_debug("Warning: error to send echo request packet");
		wtp_free_reference_last_request();

		return result;
	}

	return 0;
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
static void receive_reset_request(struct capwap_parsed_packet* packet)
{
	unsigned short binding;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_resultcode_element resultcode = { .code = CAPWAP_RESULTCODE_SUCCESS };

	ASSERT(packet != NULL);

	/* */
	binding = GET_WBID_HEADER(packet->rxmngpacket->header);
	if (binding != g_wtp.binding) {
		capwap_logging_debug("Reset Request for invalid binding");
		return;
	}

	if (!IS_SEQUENCE_SMALLER(g_wtp.remoteseqnumber, packet->rxmngpacket->ctrlmsg.seq)) {
		capwap_logging_debug("Reset Request with invalid sequence (%d < %d)",
				     g_wtp.remoteseqnumber, packet->rxmngpacket->ctrlmsg.seq);
		return;
	}

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader,
							      CAPWAP_RESET_RESPONSE,
							      packet->rxmngpacket->ctrlmsg.seq, g_wtp.mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RESULTCODE, &resultcode);
	/* CAPWAP_ELEMENT_VENDORPAYLOAD */				/* TODO */

	/* Reset response complete, get fragment packets */
	wtp_free_reference_last_response();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, g_wtp.responsefragmentpacket, g_wtp.fragmentid);
	if (g_wtp.responsefragmentpacket->count > 1)
		g_wtp.fragmentid++;

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Save remote sequence number */
	g_wtp.remotetype = packet->rxmngpacket->ctrlmsg.type;
	g_wtp.remoteseqnumber = packet->rxmngpacket->ctrlmsg.seq;

	/* Send Reset response to AC */
	if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.dtls, g_wtp.responsefragmentpacket)) {
		capwap_logging_debug("Warning: error to send reset response packet");
	}
}

/* */
static void receive_station_configuration_request(struct capwap_parsed_packet* packet)
{
	unsigned short binding;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_resultcode_element resultcode = { .code = CAPWAP_RESULTCODE_FAILURE };

	ASSERT(packet != NULL);

	/* */
	binding = GET_WBID_HEADER(packet->rxmngpacket->header);
	if (binding != g_wtp.binding) {
		capwap_logging_debug("Station Configuration Request for invalid binding");
		return;
	}

	if (!IS_SEQUENCE_SMALLER(g_wtp.remoteseqnumber, packet->rxmngpacket->ctrlmsg.seq)) {
		capwap_logging_debug("Station Configuration Request with invalid sequence (%d < %d)",
				     g_wtp.remoteseqnumber, packet->rxmngpacket->ctrlmsg.seq);
		return;
	}

	/* Parsing request message */
	if (capwap_get_message_element(packet, CAPWAP_ELEMENT_ADDSTATION)) {
		resultcode.code = wtp_radio_add_station(packet);
	} else if (capwap_get_message_element(packet, CAPWAP_ELEMENT_DELETESTATION)) {
		resultcode.code = wtp_radio_delete_station(packet);
	}

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, g_wtp.binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader,
							      CAPWAP_STATION_CONFIGURATION_RESPONSE,
							      packet->rxmngpacket->ctrlmsg.seq, g_wtp.mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RESULTCODE, &resultcode);
	/* CAPWAP_ELEMENT_VENDORPAYLOAD */				/* TODO */

	/* Station Configuration response complete, get fragment packets */
	wtp_free_reference_last_response();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, g_wtp.responsefragmentpacket, g_wtp.fragmentid);
	if (g_wtp.responsefragmentpacket->count > 1)
		g_wtp.fragmentid++;

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Save remote sequence number */
	g_wtp.remotetype = packet->rxmngpacket->ctrlmsg.type;
	g_wtp.remoteseqnumber = packet->rxmngpacket->ctrlmsg.seq;

	/* Send Station Configuration response to AC */
	if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.dtls, g_wtp.responsefragmentpacket)) {
		capwap_logging_debug("Warning: error to send Station Configuration response packet");
	}
}

/* */
static void receive_ieee80211_wlan_configuration_request(struct capwap_parsed_packet* packet)
{
	unsigned short binding;
	struct capwap_message_element_id action = {0, 0};
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_80211_assignbssid_element bssid;
	struct capwap_resultcode_element resultcode = { .code = CAPWAP_RESULTCODE_FAILURE };

	ASSERT(packet != NULL);

	/* */
	binding = GET_WBID_HEADER(packet->rxmngpacket->header);
	if (binding != g_wtp.binding) {
		capwap_logging_debug("IEEE 802.11 WLAN Configuration Request for invalid binding");
		return;
	}

	if (!IS_SEQUENCE_SMALLER(g_wtp.remoteseqnumber, packet->rxmngpacket->ctrlmsg.seq)) {
		capwap_logging_debug("IEEE 802.11 WLAN Configuration Request with invalid sequence (%d < %d)",
				     g_wtp.remoteseqnumber, packet->rxmngpacket->ctrlmsg.seq);
		return;
	}

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
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader,
							      CAPWAP_IEEE80211_WLAN_CONFIGURATION_RESPONSE,
							      packet->rxmngpacket->ctrlmsg.seq, g_wtp.mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RESULTCODE, &resultcode);
	if (resultcode.code == CAPWAP_RESULTCODE_SUCCESS &&
	    memcmp(&action, &CAPWAP_ELEMENT_80211_ADD_WLAN, sizeof(CAPWAP_ELEMENT_80211_ADD_WLAN)) == 0)
		capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_ASSIGN_BSSID, &bssid);

	/* CAPWAP_ELEMENT_VENDORPAYLOAD */				/* TODO */

	/* IEEE802.11 WLAN Configuration response complete, get fragment packets */
	wtp_free_reference_last_response();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, g_wtp.responsefragmentpacket, g_wtp.fragmentid);
	if (g_wtp.responsefragmentpacket->count > 1)
		g_wtp.fragmentid++;

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Save remote sequence number */
	g_wtp.remotetype = packet->rxmngpacket->ctrlmsg.type;
	g_wtp.remoteseqnumber = packet->rxmngpacket->ctrlmsg.seq;

	/* Send IEEE802.11 WLAN Configuration response to AC */
	if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.dtls, g_wtp.responsefragmentpacket)) {
		capwap_logging_debug("Warning: error to send IEEE802.11 WLAN Configuration response packet");
	}
}

/* */
static void wtp_dfa_state_run_echo_timeout(EV_P_ ev_timer *w, int revents)
{
	capwap_logging_debug("Send Echo Request");
	if (send_echo_request()) {
		capwap_logging_error("Unable to send Echo Request");
		wtp_teardown_connection();
		return;
	}

	g_wtp.retransmitcount = 0;
	wtp_dfa_start_retransmition_timer();
}

/* */
static void wtp_dfa_state_run_keepalive_timeout(EV_P_ ev_timer *w, int revents)
{
	capwap_logging_debug("Send Keep-Alive");

	ev_timer_again(EV_A_ &g_wtp.timerkeepalivedead);

	if (wtp_kmod_send_keepalive()) {
		capwap_logging_error("Unable to send Keep-Alive");
		wtp_teardown_connection();
	}
}

/* */
static void wtp_dfa_state_run_keepalivedead_timeout(EV_P_ ev_timer *w, int revents)
{
	capwap_logging_info("Keep-Alive timeout, teardown");
	wtp_teardown_connection();
}

/* */
void wtp_recv_data_keepalive(void) {
	capwap_logging_debug("Receive Keep-Alive");

	/* Receive Data Keep-Alive, wait for next packet */
	if (ev_is_active(&g_wtp.timerkeepalivedead))
		ev_timer_stop(EV_DEFAULT_UC_ &g_wtp.timerkeepalivedead);

	ev_timer_again(EV_DEFAULT_UC_ &g_wtp.timerkeepalive);
}

/* */
void wtp_recv_data(uint8_t* buffer, int length) {
	int headersize;
	struct capwap_header* header = (struct capwap_header*)buffer;

	/* */
	if (length < sizeof(struct capwap_header)) {
		return;
	}

	/* */
	headersize = GET_HLEN_HEADER(header) * 4;
	if ((length - headersize) > 0) {
		wtp_radio_receive_data_packet(GET_RID_HEADER(header), GET_WBID_HEADER(header),
					      (buffer + headersize), (length - headersize));
	}
}

/* */
void wtp_dfa_state_run_enter()
{
	ev_timer_init(&g_wtp.timerecho,
		      wtp_dfa_state_run_echo_timeout,
		      0., g_wtp.echointerval / 1000.0);
	ev_timer_init(&g_wtp.timerkeepalivedead,
		      wtp_dfa_state_run_keepalivedead_timeout,
		      0., WTP_DATACHANNEL_KEEPALIVEDEAD / 1000.0);
	ev_timer_init(&g_wtp.timerkeepalive,
		      wtp_dfa_state_run_keepalive_timeout,
		      0., WTP_DATACHANNEL_KEEPALIVE_INTERVAL / 1000.0);

	ev_timer_again(EV_DEFAULT_UC_ &g_wtp.timerecho);
	ev_timer_again(EV_DEFAULT_UC_ &g_wtp.timerkeepalivedead);
}

/* */
void wtp_dfa_state_run(struct capwap_parsed_packet* packet)
{
	ASSERT(packet != NULL);

	if (!capwap_is_request_type(packet->rxmngpacket->ctrlmsg.type) &&
	    g_wtp.localseqnumber != packet->rxmngpacket->ctrlmsg.seq)
		return;

	if (!capwap_is_request_type(packet->rxmngpacket->ctrlmsg.type)) {
		wtp_dfa_stop_retransmition_timer();

		/* Update sequence */
		g_wtp.localseqnumber++;
	}

	/* Parsing message */
	switch (packet->rxmngpacket->ctrlmsg.type) {
	case CAPWAP_CONFIGURATION_UPDATE_REQUEST:
		/* TODO */
		break;

	case CAPWAP_CHANGE_STATE_EVENT_RESPONSE:
		/* TODO */
		break;

	case CAPWAP_ECHO_RESPONSE:
		if (!receive_echo_response(packet)) {
			capwap_logging_debug("Receive Echo Response");

			g_wtp.timerecho.repeat = g_wtp.echointerval / 1000.0;
			ev_timer_again(EV_DEFAULT_UC_ &g_wtp.timerecho);
		}

		break;

	case CAPWAP_CLEAR_CONFIGURATION_REQUEST:
		/* TODO */
		break;

	case CAPWAP_WTP_EVENT_RESPONSE:
		/* TODO */
		break;

	case CAPWAP_DATA_TRANSFER_REQUEST:
		/* TODO */
		break;

	case CAPWAP_DATA_TRANSFER_RESPONSE:
		/* TODO */
		break;

	case CAPWAP_STATION_CONFIGURATION_REQUEST:
		receive_station_configuration_request(packet);
		break;

	case CAPWAP_RESET_REQUEST:
		receive_reset_request(packet);
		wtp_dfa_change_state(CAPWAP_RESET_STATE);
		break;

	case CAPWAP_IEEE80211_WLAN_CONFIGURATION_REQUEST:
		receive_ieee80211_wlan_configuration_request(packet);
		break;
	}
}
