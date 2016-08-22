#include "wtp.h"
#include "dfa.h"
#include "array.h"
#include "capwap_dfa.h"
#include "dtls.h"
#include "radio.h"

#include <signal.h>
#include <ev.h>

#define WTP_RECV_NOERROR_RADIO				-1001

static const struct dfa_states {
	void (*state_enter)(void);
	void (*state_execute)(struct capwap_parsed_packet *packet);
} dfa_states[] = {
	[CAPWAP_IDLE_STATE] = {
		.state_enter   = wtp_dfa_state_idle_enter,
	},
	[CAPWAP_DISCOVERY_STATE] = {
		.state_enter   = wtp_dfa_state_discovery_enter,
		.state_execute = wtp_dfa_state_discovery,
	},
	[CAPWAP_SULKING_STATE] = {
		.state_enter   = wtp_dfa_state_sulking_enter,
		.state_execute = wtp_dfa_state_sulking,
	},
	[CAPWAP_DTLS_CONNECT_STATE] = {
		.state_enter   = wtp_dfa_state_dtlsconnect_enter,
	},
	[CAPWAP_DTLS_TEARDOWN_STATE] = {
		.state_enter   = wtp_dfa_state_dtlsteardown_enter,
		.state_execute = wtp_dfa_state_dtlsteardown,
	},
	[CAPWAP_JOIN_STATE] = {
		.state_enter   = wtp_dfa_state_join_enter,
		.state_execute = wtp_dfa_state_join,
	},
	[CAPWAP_IMAGE_DATA_STATE] = {
	},
	[CAPWAP_CONFIGURE_STATE] = {
		.state_enter   = wtp_dfa_state_configure_enter,
		.state_execute = wtp_dfa_state_configure,
	},
	[CAPWAP_RESET_STATE] = {
		.state_enter   = wtp_dfa_state_reset_enter,
	},
	[CAPWAP_DATA_CHECK_STATE] = {
		.state_enter   = wtp_dfa_state_datacheck_enter,
		.state_execute = wtp_dfa_state_datacheck,
	},
	[CAPWAP_RUN_STATE] = {
		.state_enter   = wtp_dfa_state_run_enter,
		.state_execute = wtp_dfa_state_run,
	},
	[CAPWAP_DEAD_STATE] = {
		.state_enter   = wtp_dfa_state_dead_enter,
	}
};

static inline int is_valid_state(int state)
{
	return (state >= 0) && (state < (sizeof(dfa_states) / sizeof(dfa_states[0])));
}

/* libev handler */
static void signal_cb (EV_P_ ev_signal *w, int revents);
static void capwap_control_cb(EV_P_ ev_io *w, int revents);

/* Handler signal */
static void signal_cb (EV_P_ ev_signal *w, int revents)
{
	g_wtp.running = 0;

	/* Teardown */
	wtp_teardown_connection();
}

/* */
static struct capwap_packet_rxmng* wtp_get_packet_rxmng(void) {
	if (!g_wtp.rxmngpacket) {
		g_wtp.rxmngpacket = capwap_packet_rxmng_create_message();
	}

	return g_wtp.rxmngpacket;
}

/* */
void wtp_free_packet_rxmng(void) {
	if (g_wtp.rxmngpacket) { 
		capwap_packet_rxmng_free(g_wtp.rxmngpacket);
		g_wtp.rxmngpacket = NULL;
	}
}

/* */
static void wtp_send_invalid_request(struct capwap_packet_rxmng* rxmngpacket, uint32_t errorcode) {
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_list* responsefragmentpacket;
	struct capwap_fragment_packet_item* packet;
	struct capwap_header* header;
	struct capwap_resultcode_element resultcode = { .code = errorcode };

	ASSERT(rxmngpacket != NULL);
	ASSERT(rxmngpacket->fragmentlist->first != NULL);

	/* */
	packet = (struct capwap_fragment_packet_item*)rxmngpacket->fragmentlist->first->item;
	header = (struct capwap_header*)packet->buffer;

	/* Odd message type */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, GET_WBID_HEADER(header));
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, rxmngpacket->ctrlmsg.type + 1, rxmngpacket->ctrlmsg.seq, g_wtp.mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RESULTCODE, &resultcode);

	/* Unknown response complete, get fragment packets */
	responsefragmentpacket = capwap_list_create();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, responsefragmentpacket, g_wtp.fragmentid);
	if (responsefragmentpacket->count > 1)
		g_wtp.fragmentid++;

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send unknown response */
	capwap_crypt_sendto_fragmentpacket(&g_wtp.dtls, responsefragmentpacket);

	/* Don't buffering a packets sent */
	capwap_list_free(responsefragmentpacket);
}

/* WTP Execute state */
static void wtp_dfa_execute(struct capwap_parsed_packet* packet)
{
	ASSERT(packet != NULL);

	if (!is_valid_state(g_wtp.state) ||
	    !dfa_states[g_wtp.state].state_execute) {
		log_printf(LOG_DEBUG, "Got packet in invalid WTP state: %lu", g_wtp.state);
		wtp_teardown_connection();
	} else
		dfa_states[g_wtp.state].state_execute(packet);
}

static void wtp_dfa_process_packet(void *buffer, int buffersize,
				   union sockaddr_capwap *fromaddr,
				   union sockaddr_capwap *toaddr)
{
	int check, res;
	char plain[CAPWAP_MAX_PACKET_SIZE];
	struct capwap_packet_rxmng* rxmngpacket;
	struct capwap_parsed_packet packet;

	/* Check source */
	if (g_wtp.state != CAPWAP_DISCOVERY_STATE &&
	    capwap_compare_ip(&g_wtp.dtls.peeraddr, fromaddr)) {
		log_printf(LOG_DEBUG, "CAPWAP packet from unknown WTP when not in DISCOVERY, drop packet");
		return;		/* Unknown source */
	}

	/* Check of packet */
	check = capwap_sanity_check(g_wtp.state, buffer, buffersize, g_wtp.dtls.enable);
	switch (check) {
	case CAPWAP_PLAIN_PACKET:
		break;

	case CAPWAP_DTLS_PACKET: {
		int oldaction = g_wtp.dtls.action;

		/* Decrypt packet */
		buffersize = capwap_decrypt_packet(&g_wtp.dtls, buffer, buffersize, plain, CAPWAP_MAX_PACKET_SIZE);
		if (buffersize > 0) {
			buffer = plain;
			break;
		}

		if (buffersize == CAPWAP_ERROR_AGAIN) {
			/* Check is handshake complete */
			if (oldaction == CAPWAP_DTLS_ACTION_HANDSHAKE &&
			    g_wtp.dtls.action == CAPWAP_DTLS_ACTION_DATA) {
				if (g_wtp.state == CAPWAP_DTLS_CONNECT_STATE) {
					wtp_dfa_change_state(CAPWAP_JOIN_STATE);
				} else
					wtp_teardown_connection();
			}
		} else if (oldaction == CAPWAP_DTLS_ACTION_DATA &&
			   g_wtp.dtls.action == CAPWAP_DTLS_ACTION_SHUTDOWN) {
			wtp_teardown_connection();
		} else if (oldaction == CAPWAP_DTLS_ACTION_HANDSHAKE &&
			   g_wtp.dtls.action == CAPWAP_DTLS_ACTION_ERROR) {
			wtp_abort_connecting();
		}

		return;		/* Next packet */
	}

	case CAPWAP_WRONG_PACKET:
		log_printf(LOG_DEBUG, "Warning: sanity check failure");
		/* Drop packet */
		return;

	default:
		/* TODO: Really? Previosly, this was hidden in the
		 * overly deep indention, check if that is correct */

		log_printf(LOG_DEBUG, "Warning: wtp_dfa_running took default fall through");
		return;
	}

	/* Defragment management */
	rxmngpacket = wtp_get_packet_rxmng();

	/* If request, defragmentation packet */
	check = capwap_packet_rxmng_add_recv_packet(rxmngpacket, buffer, buffersize);
	if (check == CAPWAP_REQUEST_MORE_FRAGMENT)
		return;
	if (check != CAPWAP_RECEIVE_COMPLETE_PACKET) {
		/* Discard fragments */
		wtp_free_packet_rxmng();
		return;
	}

	/* Check for already sent response to packet */
	if (capwap_is_request_type(rxmngpacket->ctrlmsg.type) &&
	    g_wtp.remotetype == rxmngpacket->ctrlmsg.type &&
	    g_wtp.remoteseqnumber == rxmngpacket->ctrlmsg.seq) {
		/* Retransmit response */
		if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.dtls, g_wtp.responsefragmentpacket)) {
			log_printf(LOG_ERR, "Error to resend response packet");
		} else {
			log_printf(LOG_DEBUG, "Retransmitted control packet");
		}

		/* Discard fragments */
		wtp_free_packet_rxmng();
		return;
	}

	/* Check message type */
	res = capwap_check_message_type(rxmngpacket);
	if (res != VALID_MESSAGE_TYPE) {
		if (res == INVALID_REQUEST_MESSAGE_TYPE) {
			log_printf(LOG_WARNING, "Unexpected Unrecognized Request, send Response Packet with error");
			wtp_send_invalid_request(rxmngpacket, CAPWAP_RESULTCODE_MSG_UNEXPECTED_UNRECOGNIZED_REQUEST);
		}

		log_printf(LOG_DEBUG, "Invalid message type");
		wtp_free_packet_rxmng();
		return;
	}

	/* Init */
	memset(&packet, 0, sizeof(struct capwap_parsed_packet));

	/* Parsing packet */
	res = capwap_parsing_packet(rxmngpacket, &packet);
	if (res != PARSING_COMPLETE) {
		if (res == UNRECOGNIZED_MESSAGE_ELEMENT &&
		    capwap_is_request_type(rxmngpacket->ctrlmsg.type)) {
			log_printf(LOG_WARNING, "Unrecognized Message Element, send Response Packet with error");
			wtp_send_invalid_request(rxmngpacket, CAPWAP_RESULTCODE_FAILURE_UNRECOGNIZED_MESSAGE_ELEMENT);
			/* TODO: add the unrecognized message element */
		}

		/* */
		log_printf(LOG_DEBUG, "Failed parsing packet");
		capwap_free_parsed_packet(&packet);
		wtp_free_packet_rxmng();
		return;
	}

	/* Validate packet */
	if (capwap_validate_parsed_packet(&packet, NULL)) {
		if (capwap_is_request_type(rxmngpacket->ctrlmsg.type)) {
			log_printf(LOG_WARNING, "Missing Mandatory Message Element, send Response Packet with error");
			wtp_send_invalid_request(rxmngpacket, CAPWAP_RESULTCODE_FAILURE_MISSING_MANDATORY_MSG_ELEMENT);
		}

		/* */
		log_printf(LOG_DEBUG, "Failed validation parsed packet");
		capwap_free_parsed_packet(&packet);
		wtp_free_packet_rxmng();
		return;
	}

	/* Receive a complete packet */
	wtp_dfa_execute(&packet);

	/* Free packet */
	capwap_free_parsed_packet(&packet);

	wtp_free_packet_rxmng();
}

/* WTP state machine */
int wtp_dfa_running()
{
	int result = CAPWAP_SUCCESSFUL;

	/* Handler signal */
	g_wtp.running = 1;
	ev_signal_init(&g_wtp.sigint_ev, signal_cb, SIGINT);
	ev_signal_init(&g_wtp.sigterm_ev, signal_cb, SIGTERM);
	ev_signal_start(EV_DEFAULT_UC_ &g_wtp.sigint_ev);
	ev_signal_start(EV_DEFAULT_UC_ &g_wtp.sigterm_ev);

	/* Init complete, start DFA */
	wtp_dfa_change_state(CAPWAP_IDLE_STATE);

	ev_run(EV_DEFAULT_UC_ 0);

        return result;
}

void wtp_socket_io_start()
{
	log_printf(LOG_DEBUG, "Start EV_IO on socket %d", g_wtp.net.socket);

	/* Configure libev struct */
	ev_io_init (&g_wtp.socket_ev, capwap_control_cb, g_wtp.net.socket, EV_READ);
	ev_io_start(EV_DEFAULT_UC_ &g_wtp.socket_ev);
}

void wtp_socket_io_stop()
{
	log_printf(LOG_DEBUG, "Stop EV_IO on socket %d", g_wtp.socket_ev.fd);

	ev_io_stop(EV_DEFAULT_UC_ &g_wtp.socket_ev);
}

static void capwap_control_cb(EV_P_ ev_io *w, int revents)
{
	char buffer[CAPWAP_MAX_PACKET_SIZE];
	ssize_t r;
	union sockaddr_capwap fromaddr;
	union sockaddr_capwap toaddr;

	do {
		/* If request wait packet from AC */
		do {
			log_printf(LOG_DEBUG, "Receive CAPWAP Control Channel message");
			r = capwap_recvfrom(w->fd, &buffer, sizeof(buffer),
					    &fromaddr, &toaddr);
		} while (r < 0 && errno == EINTR);
		log_printf(LOG_DEBUG, "WTP got data: r: %zd", r);

		if (!g_wtp.running) {
			log_printf(LOG_DEBUG, "Closing WTP, Teardown connection");

			ev_io_stop (EV_A_ w);
			break;
		}

		if (r < 0) {
			if (errno != EAGAIN) {
				log_printf(LOG_DEBUG, "capwap_control_cb I/O error %m, exiting loop");
				ev_io_stop (EV_A_ w);
				ev_break (EV_A_ EVBREAK_ONE);
			}
			break;
		}

		if (g_wtp.teardown) {
			log_printf(LOG_DEBUG, "WTP is in teardown, drop packet");
			continue;		/* Drop packet */
		}

		wtp_dfa_process_packet(&buffer, r, &fromaddr, &toaddr);
	} while (ev_is_active(w));
}

/* Change WTP state machine */
void wtp_dfa_change_state(int state) {
	if (state != g_wtp.state) {
		log_printf(LOG_DEBUG, "WTP change state from %s to %s",
				     capwap_dfa_getname(g_wtp.state),
				     capwap_dfa_getname(state));
		g_wtp.state = state;

		ev_timer_stop(EV_DEFAULT_UC_ &g_wtp.timercontrol);

		if (is_valid_state(g_wtp.state) &&
		    dfa_states[g_wtp.state].state_enter)
			dfa_states[g_wtp.state].state_enter();
	}
}

/* */
void wtp_free_reference_last_request(void)
{
	capwap_list_flush(g_wtp.requestfragmentpacket);
}

/* */
void wtp_free_reference_last_response(void) {
	capwap_list_flush(g_wtp.responsefragmentpacket);
	g_wtp.remotetype = 0;
	g_wtp.remoteseqnumber = 0;
}

/* */
static void wtp_dfa_retransmition_timeout_cb(EV_P_ ev_timer *w, int revents)
{
	if (!g_wtp.requestfragmentpacket->count) {
		log_printf(LOG_WARNING, "Invalid retransmition request packet");
		wtp_teardown_connection();

		return;
	}

	g_wtp.retransmitcount++;
	if (g_wtp.retransmitcount >= WTP_MAX_RETRANSMIT) {
		log_printf(LOG_INFO, "Retransmition request packet timeout");

		/* Timeout state */
		wtp_free_reference_last_request();
		wtp_teardown_connection();

		return;
	}

	/* Retransmit request */
	log_printf(LOG_DEBUG, "Retransmition request packet");
	if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.dtls, g_wtp.requestfragmentpacket)) {
		log_printf(LOG_ERR, "Error to send request packet");
	}

	/* Update timeout */
	ev_timer_again(EV_A_ w);
}

/* */
void wtp_dfa_start_retransmition_timer()
{
	ev_timer_stop(EV_DEFAULT_UC_ &g_wtp.timercontrol);
	ev_timer_init(&g_wtp.timercontrol, wtp_dfa_retransmition_timeout_cb,
		      0., WTP_RETRANSMIT_INTERVAL / 1000.0);
	ev_timer_again(EV_DEFAULT_UC_ &g_wtp.timercontrol);
}

/* */
void wtp_dfa_stop_retransmition_timer()
{
	ev_timer_stop(EV_DEFAULT_UC_ &g_wtp.timercontrol);
}

/* */
void wtp_timeout_stop_all()
{
	ev_timer_stop(EV_DEFAULT_UC_ &g_wtp.timercontrol);
	ev_timer_stop(EV_DEFAULT_UC_ &g_wtp.timerecho);
	ev_timer_stop(EV_DEFAULT_UC_ &g_wtp.timerkeepalive);
	ev_timer_stop(EV_DEFAULT_UC_ &g_wtp.timerkeepalivedead);
}

void wtp_reset_state(void)
{
	/* reset WTP state */
	wtp_radio_reset();

	wtp_free_reference_last_request();
	wtp_free_reference_last_response();
	wtp_free_packet_rxmng();

	g_wtp.mtu = CAPWAP_MTU_DEFAULT;
	g_wtp.remotetype = 0;
	g_wtp.remoteseqnumber = WTP_INIT_REMOTE_SEQUENCE;

	memset(&g_wtp.dtls.localaddr, 0, sizeof(g_wtp.dtls.localaddr));
	memset(&g_wtp.dtls.peeraddr, 0, sizeof(g_wtp.dtls.peeraddr));

	CAPWAP_SET_NETWORK_PORT(&g_wtp.net.localaddr, 0);
}
