#include "wtp.h"
#include "wtp_dfa.h"
#include "capwap_array.h"
#include "capwap_dfa.h"
#include "capwap_dtls.h"
#include "wtp_radio.h"

#include <signal.h>

#define WTP_RECV_NOERROR_RADIO				-1001

/* Handler signal */
static void wtp_signal_handler(int signum) {
	if ((signum == SIGINT) || (signum == SIGTERM)) {
		g_wtp.running = 0;
	}
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

	switch (g_wtp.state) {
	case CAPWAP_DISCOVERY_STATE:
		wtp_dfa_state_discovery(packet);
		break;

	case CAPWAP_SULKING_STATE:
		wtp_dfa_state_sulking(packet);
		break;

	case CAPWAP_DTLS_CONNECT_STATE:
		wtp_teardown_connection();
		break;

	case CAPWAP_DTLS_TEARDOWN_STATE:
		wtp_dfa_state_dtlsteardown(packet);
		break;

	case CAPWAP_JOIN_STATE:
		wtp_dfa_state_join(packet);
		break;

	case CAPWAP_CONFIGURE_STATE:
		wtp_dfa_state_configure(packet);
		break;

	case CAPWAP_DATA_CHECK_STATE:
		wtp_dfa_state_datacheck(packet);
		break;

	case CAPWAP_RUN_STATE:
		wtp_dfa_state_run(packet);
		break;

	default:
		capwap_logging_debug("Unknown WTP action event: %lu", g_wtp.state);
		wtp_teardown_connection();
		break;
	}
}

/* */
static int wtp_recvfrom(struct wtp_fds* fds, void* buffer, int* size, union sockaddr_capwap* recvfromaddr, union sockaddr_capwap* recvtoaddr) {
	int index;

	ASSERT(fds != NULL);
	ASSERT(fds->fdspoll != NULL);
	ASSERT(fds->fdstotalcount > 0);
	ASSERT(buffer != NULL);
	ASSERT(size != NULL);
	ASSERT(*size > 0);
	ASSERT(recvfromaddr != NULL);
	ASSERT(recvtoaddr != NULL);

	/* Wait packet */
	index = capwap_wait_recvready(fds->fdspoll, fds->fdstotalcount, g_wtp.timeout);
	if (index < 0) {
		return index;
	} else if ((fds->wifieventsstartpos >= 0) && (index >= fds->wifieventsstartpos)) {
		int pos = index - fds->wifieventsstartpos;

		if (pos < fds->wifieventscount) {
			if (!fds->wifievents[pos].event_handler) {
				return CAPWAP_RECV_ERROR_SOCKET;
			}

			fds->wifievents[pos].event_handler(fds->fdspoll[index].fd, fds->wifievents[pos].params, fds->wifievents[pos].paramscount);
		}

		return WTP_RECV_NOERROR_RADIO;
	} else if ((fds->kmodeventsstartpos >= 0) && (index >= fds->kmodeventsstartpos)) {
		int pos = index - fds->kmodeventsstartpos;

		if (pos < fds->kmodeventscount) {
			if (!fds->kmodevents[pos].event_handler) {
				return CAPWAP_RECV_ERROR_SOCKET;
			}

			fds->kmodevents[pos].event_handler(fds->fdspoll[index].fd, fds->kmodevents[pos].params, fds->kmodevents[pos].paramscount);
		}

		return WTP_RECV_NOERROR_RADIO;
	}

	/* Receive packet */
	if (capwap_recvfrom(fds->fdspoll[index].fd, buffer, size, recvfromaddr, recvtoaddr)) {
		return CAPWAP_RECV_ERROR_SOCKET;
	}

	return index;
}

/* */
static int wtp_dfa_init_fdspool(struct wtp_fds* fds, struct capwap_network* net) {
	ASSERT(fds != NULL);
	ASSERT(net != NULL);

	/* */
	memset(fds, 0, sizeof(struct wtp_fds));
	fds->fdsnetworkcount = capwap_network_set_pollfd(net, NULL, 0);
	fds->fdspoll = (struct pollfd*)capwap_alloc(sizeof(struct pollfd) * fds->fdsnetworkcount);

	/* Retrive all socket for polling */
	fds->fdstotalcount = capwap_network_set_pollfd(net, fds->fdspoll, fds->fdsnetworkcount);
	if (fds->fdsnetworkcount != fds->fdstotalcount) {
		capwap_free(fds->fdspoll);
		return -1;
	}

	/* Update Event File Descriptor */
	wtp_dfa_update_fdspool(fds);
	return 0;
}

/* */
int wtp_dfa_update_fdspool(struct wtp_fds* fds) {
	int totalcount;
	int kmodcount;
	int wificount;
	struct pollfd* fdsbuffer;

	ASSERT(fds != NULL);

	/* Retrieve number of Dynamic File Descriptor Event */
	kmodcount = wtp_kmod_getfd(NULL, NULL, 0);
	wificount = wifi_event_getfd(NULL, NULL, 0);
	if ((kmodcount < 0) || (wificount < 0)) {
		return -1;
	}

	/* Kernel Module Events Callback */
	fds->kmodeventsstartpos = -1;
	if (kmodcount != fds->kmodeventscount) {
		if (fds->kmodevents) {
			capwap_free(fds->kmodevents);
		}

		/* */
		fds->kmodeventscount = kmodcount;
		fds->kmodevents = (struct wtp_kmod_event*)((kmodcount > 0) ? capwap_alloc(sizeof(struct wtp_kmod_event) * kmodcount) : NULL);
	}

	/* Wifi Events Callback */
	fds->wifieventsstartpos = -1;
	if (wificount != fds->wifieventscount) {
		if (fds->wifievents) {
			capwap_free(fds->wifievents);
		}

		/* */
		fds->wifieventscount = wificount;
		fds->wifievents = (struct wifi_event*)((wificount > 0) ? capwap_alloc(sizeof(struct wifi_event) * wificount) : NULL);
	}

	/* Resize poll */
	totalcount = fds->fdsnetworkcount + fds->kmodeventscount + fds->wifieventscount;
	if (fds->fdstotalcount != totalcount) {
		fdsbuffer = (struct pollfd*)capwap_alloc(sizeof(struct pollfd) * totalcount);
		if (fds->fdspoll) {
			if (fds->fdsnetworkcount > 0) {
				memcpy(fdsbuffer, fds->fdspoll, sizeof(struct pollfd) * fds->fdsnetworkcount);
			}

			capwap_free(fds->fdspoll);
		}

		/* */
		fds->fdspoll = fdsbuffer;
		fds->fdstotalcount = totalcount;
	}

	/* Retrieve File Descriptor Kernel Module Event */
	if (fds->kmodeventscount > 0) {
		fds->kmodeventsstartpos = fds->fdsnetworkcount;
		wtp_kmod_getfd(&fds->fdspoll[fds->kmodeventsstartpos], fds->kmodevents, fds->kmodeventscount);
	}

	/* Retrieve File Descriptor Wifi Event */
	if (fds->wifieventscount > 0) {
		fds->wifieventsstartpos = fds->fdsnetworkcount + fds->kmodeventscount;
		wifi_event_getfd(&fds->fdspoll[fds->wifieventsstartpos], fds->wifievents, fds->wifieventscount);
	}

	return fds->fdstotalcount;
}

/* */
void wtp_dfa_free_fdspool(struct wtp_fds* fds) {
	ASSERT(fds != NULL);

	if (fds->fdspoll) {
		capwap_free(fds->fdspoll);
	}

	if (fds->kmodevents) {
		capwap_free(fds->kmodevents);
	}

	if (fds->wifievents) {
		capwap_free(fds->wifievents);
	}
}

/* */
static void wtp_dfa_closeapp(void) {
	g_wtp.running = 0;

	/* Teardown */
	wtp_teardown_connection();

	/* Wait RFC teardown timeout */
	for (;;) {
		if (capwap_timeout_wait(capwap_timeout_getcoming(g_wtp.timeout)) < 0) {
			break;
		}

		if (capwap_timeout_hasexpired(g_wtp.timeout) == g_wtp.idtimercontrol) {
			break;
		}
	}

	/* */
	ASSERT(g_wtp.state == CAPWAP_DEAD_STATE);
}

/* WTP state machine */
int wtp_dfa_running(void) {
	int res;
	int result = CAPWAP_SUCCESSFUL;

	char bufferencrypt[CAPWAP_MAX_PACKET_SIZE];
	char bufferplain[CAPWAP_MAX_PACKET_SIZE];
	char* buffer;
	int buffersize;

	struct capwap_parsed_packet packet;

	int index;
	union sockaddr_capwap fromaddr;
	union sockaddr_capwap toaddr;

	/* Init */
	memset(&packet, 0, sizeof(struct capwap_parsed_packet));

	/* Configure poll struct */
	if (wtp_dfa_init_fdspool(&g_wtp.fds, &g_wtp.net)) {
		return CAPWAP_GENERIC_ERROR;
	}

	/* Handler signal */
	g_wtp.running = 1;
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, wtp_signal_handler);
	signal(SIGTERM, wtp_signal_handler);

	/* Init complete, start DFA */
	wtp_dfa_change_state(CAPWAP_IDLE_STATE);
	wtp_dfa_state_idle();

	/* */
	while (g_wtp.state != CAPWAP_DEAD_STATE) {
		/* If request wait packet from AC */
		buffer = bufferencrypt;
		buffersize = CAPWAP_MAX_PACKET_SIZE;
		index = wtp_recvfrom(&g_wtp.fds, buffer, &buffersize, &fromaddr, &toaddr);
		capwap_logging_debug("WTP got data: idx: %d, size: %d", index, buffersize);
		if (!g_wtp.running) {
			capwap_logging_debug("Closing WTP, Teardown connection");
			wtp_dfa_closeapp();
			break;
		} else if (index >= 0) {
			if (g_wtp.teardown) {
				capwap_logging_debug("WTP is in teardown, drop packet");
				continue;		/* Drop packet */
			} else {
				int check;

				/* Check source */
				if (g_wtp.state != CAPWAP_DISCOVERY_STATE &&
				    capwap_compare_ip(&g_wtp.dtls.peeraddr, &fromaddr)) {
					capwap_logging_debug("CAPWAP packet from unknown WTP when not in DISCOVERY, drop packet");
					continue;		/* Unknown source */
				}

				/* Check of packet */
				check = capwap_sanity_check(g_wtp.state, buffer, buffersize, g_wtp.dtls.enable);
				if (check == CAPWAP_DTLS_PACKET) {
					int oldaction = g_wtp.dtls.action;

					/* Decrypt packet */
					buffersize = capwap_decrypt_packet(&g_wtp.dtls, buffer, buffersize, bufferplain, CAPWAP_MAX_PACKET_SIZE);
					if (buffersize > 0) {
						buffer = bufferplain;
						check = CAPWAP_PLAIN_PACKET;
					} else if (buffersize == CAPWAP_ERROR_AGAIN) {
						/* Check is handshake complete */
						if ((oldaction == CAPWAP_DTLS_ACTION_HANDSHAKE) && (g_wtp.dtls.action == CAPWAP_DTLS_ACTION_DATA)) {
							if (g_wtp.state == CAPWAP_DTLS_CONNECT_STATE) {
								wtp_send_join();
							} else {
								wtp_teardown_connection();
							}
						}

						continue;		/* Next packet */
					} else {
						if ((oldaction == CAPWAP_DTLS_ACTION_DATA) && (g_wtp.dtls.action == CAPWAP_DTLS_ACTION_SHUTDOWN)) {
							wtp_teardown_connection();
						}

						continue;		/* Next packet */
					}
				} else if (check == CAPWAP_WRONG_PACKET) {
					capwap_logging_debug("Warning: sanity check failure");
					/* Drop packet */
					continue;
				}

				/* */
				if (check == CAPWAP_PLAIN_PACKET) {
					struct capwap_packet_rxmng* rxmngpacket;

					/* Defragment management */
					rxmngpacket = wtp_get_packet_rxmng();

					/* If request, defragmentation packet */
					check = capwap_packet_rxmng_add_recv_packet(rxmngpacket, buffer, buffersize);
					if (check == CAPWAP_REQUEST_MORE_FRAGMENT) {
						continue;
					} else if (check != CAPWAP_RECEIVE_COMPLETE_PACKET) {
						/* Discard fragments */
						wtp_free_packet_rxmng();
						continue;
					}

					/* Check for already response to packet */
					if (capwap_is_request_type(rxmngpacket->ctrlmsg.type) && (g_wtp.remotetype == rxmngpacket->ctrlmsg.type) && (g_wtp.remoteseqnumber == rxmngpacket->ctrlmsg.seq)) {
						/* Retransmit response */
						if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.dtls, g_wtp.responsefragmentpacket)) {
							capwap_logging_error("Error to resend response packet");
						} else {
							capwap_logging_debug("Retrasmitted control packet");
						}

						/* Discard fragments */
						wtp_free_packet_rxmng();
						continue;
					}

					/* Check message type */
					res = capwap_check_message_type(rxmngpacket);
					if (res != VALID_MESSAGE_TYPE) {
						if (res == INVALID_REQUEST_MESSAGE_TYPE) {
							capwap_logging_warning("Unexpected Unrecognized Request, send Response Packet with error");
							wtp_send_invalid_request(rxmngpacket, CAPWAP_RESULTCODE_MSG_UNEXPECTED_UNRECOGNIZED_REQUEST);
						}

						capwap_logging_debug("Invalid message type");
						wtp_free_packet_rxmng();
						continue;
					}

					/* Parsing packet */
					res = capwap_parsing_packet(rxmngpacket, &packet);
					if (res != PARSING_COMPLETE) {
						if ((res == UNRECOGNIZED_MESSAGE_ELEMENT) && capwap_is_request_type(rxmngpacket->ctrlmsg.type)) {
							capwap_logging_warning("Unrecognized Message Element, send Response Packet with error");
							wtp_send_invalid_request(rxmngpacket, CAPWAP_RESULTCODE_FAILURE_UNRECOGNIZED_MESSAGE_ELEMENT);
							/* TODO: add the unrecognized message element */
						}

						/* */
						capwap_logging_debug("Failed parsing packet");
						capwap_free_parsed_packet(&packet);
						wtp_free_packet_rxmng();
						continue;
					}

					/* Validate packet */
					if (capwap_validate_parsed_packet(&packet, NULL)) {
						if (capwap_is_request_type(rxmngpacket->ctrlmsg.type)) {
							capwap_logging_warning("Missing Mandatory Message Element, send Response Packet with error");
							wtp_send_invalid_request(rxmngpacket, CAPWAP_RESULTCODE_FAILURE_MISSING_MANDATORY_MSG_ELEMENT);
						}

						/* */
						capwap_logging_debug("Failed validation parsed packet");
						capwap_free_parsed_packet(&packet);
						wtp_free_packet_rxmng();
						continue;
					}

					/* Receive a complete packet */
					wtp_dfa_execute(&packet);

					/* Free packet */
					capwap_free_parsed_packet(&packet);
					wtp_free_packet_rxmng();
				}
			}
		} else if ((index == CAPWAP_RECV_ERROR_INTR) || (index == WTP_RECV_NOERROR_RADIO)) {
			/* Ignore recv */
			continue;
		} else if (index == CAPWAP_RECV_ERROR_SOCKET) {
			/* Socket close */
			break;
		}
	}

	/* Free memory */
	wtp_dfa_free_fdspool(&g_wtp.fds);
	return result;
}

/* Change WTP state machine */
void wtp_dfa_change_state(int state) {
	if (state != g_wtp.state) {
		capwap_logging_debug("WTP change state from %s to %s", capwap_dfa_getname(g_wtp.state), capwap_dfa_getname(state));
		g_wtp.state = state;
	}
}

/* */
void wtp_free_reference_last_request(void) {
	capwap_list_flush(g_wtp.requestfragmentpacket);
}

/* */
void wtp_free_reference_last_response(void) {
	capwap_list_flush(g_wtp.responsefragmentpacket);
	g_wtp.remotetype = 0;
	g_wtp.remoteseqnumber = 0;
}

/* */
void wtp_dfa_retransmition_timeout(struct capwap_timeout* timeout, unsigned long index,
				   void* context, void* param)
{
	if (!g_wtp.requestfragmentpacket->count) {
		capwap_logging_warning("Invalid retransmition request packet");
		wtp_teardown_connection();
	} else {
		g_wtp.retransmitcount++;
		if (g_wtp.retransmitcount >= WTP_MAX_RETRANSMIT) {
			capwap_logging_info("Retransmition request packet timeout");

			/* Timeout state */
			wtp_free_reference_last_request();
			wtp_teardown_connection();
		} else {
			/* Retransmit request */
			capwap_logging_debug("Retransmition request packet");
			if (!capwap_crypt_sendto_fragmentpacket(&g_wtp.dtls, g_wtp.requestfragmentpacket)) {
				capwap_logging_error("Error to send request packet");
			}

			/* Update timeout */
			capwap_timeout_set(g_wtp.timeout, g_wtp.idtimercontrol, WTP_RETRANSMIT_INTERVAL, wtp_dfa_retransmition_timeout, NULL, NULL);
		}
	}
}
