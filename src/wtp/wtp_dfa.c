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
static struct capwap_packet_rxmng* wtp_get_packet_rxmng(int isctrlmsg) {
	struct capwap_packet_rxmng* rxmngpacket = NULL;

	if (isctrlmsg) {
		if (!g_wtp.rxmngctrlpacket) {
			g_wtp.rxmngctrlpacket = capwap_packet_rxmng_create_message(1);
		}

		rxmngpacket = g_wtp.rxmngctrlpacket;
	} else {
		if (!g_wtp.rxmngdatapacket) {
			g_wtp.rxmngdatapacket = capwap_packet_rxmng_create_message(0);
		}

		rxmngpacket = g_wtp.rxmngdatapacket;
	}

	return rxmngpacket;
}

/* */
void wtp_free_packet_rxmng(int isctrlmsg) {
	if (isctrlmsg && g_wtp.rxmngctrlpacket) { 
		capwap_packet_rxmng_free(g_wtp.rxmngctrlpacket);
		g_wtp.rxmngctrlpacket = NULL;
	} else if (!isctrlmsg && g_wtp.rxmngdatapacket) {
		capwap_packet_rxmng_free(g_wtp.rxmngdatapacket);
		g_wtp.rxmngdatapacket = NULL;
	}
}

/* */
static void wtp_send_invalid_request(struct capwap_packet_rxmng* rxmngpacket, struct capwap_connection* connection, uint32_t errorcode) {
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_list* responsefragmentpacket;
	struct capwap_fragment_packet_item* packet;
	struct capwap_header* header;
	struct capwap_resultcode_element resultcode = { .code = errorcode };

	ASSERT(rxmngpacket != NULL);
	ASSERT(rxmngpacket->fragmentlist->first != NULL);
	ASSERT(connection != NULL);

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
	if (responsefragmentpacket->count > 1) {
		g_wtp.fragmentid++;
	}

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send unknown response */
	capwap_crypt_sendto_fragmentpacket(&g_wtp.ctrldtls, connection->socket.socket[connection->socket.type], responsefragmentpacket, &connection->localaddr, &connection->remoteaddr);

	/* Don't buffering a packets sent */
	capwap_list_free(responsefragmentpacket);
}

/* WTP Execute state */
static void wtp_dfa_execute(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	switch (g_wtp.dfa.state) {
		case CAPWAP_IDLE_STATE: {
			wtp_dfa_state_idle(packet, timeout);
			break;
		}

		case CAPWAP_DISCOVERY_STATE: {
			wtp_dfa_state_discovery(packet, timeout);
			break;
		}

		case CAPWAP_SULKING_STATE: {
			wtp_dfa_state_sulking(packet, timeout);
			break;
		}

		case CAPWAP_DTLS_CONNECT_STATE: {
			wtp_teardown_connection(timeout);
			break;
		}

		case CAPWAP_DTLS_TEARDOWN_STATE: {
			wtp_dfa_state_dtlsteardown(packet, timeout);
			break;
		}

		case CAPWAP_JOIN_STATE: {
			wtp_dfa_state_join(packet, timeout);
			break;
		}

		case CAPWAP_CONFIGURE_STATE: {
			wtp_dfa_state_configure(packet, timeout);
			break;
		}

		case CAPWAP_RESET_STATE: {
			wtp_dfa_state_reset(packet, timeout);
			break;
		}

		case CAPWAP_DATA_CHECK_STATE: {
			wtp_dfa_state_datacheck(packet, timeout);
			break;
		}

		case CAPWAP_RUN_STATE: {
			wtp_dfa_state_run(packet, timeout);
			break;
		}

		default: {
			capwap_logging_debug("Unknown action event: %lu", g_wtp.dfa.state);
			break;
		}
	}
}

/* */
static int wtp_recvfrom(struct pollfd* fds, int fdscount, void* buffer, int* size, struct sockaddr_storage* recvfromaddr, struct sockaddr_storage* recvtoaddr, struct timeout_control* timeout) {
	int index;

	ASSERT(fds);
	ASSERT(fdscount > 0);
	ASSERT(buffer != NULL);
	ASSERT(size != NULL);
	ASSERT(*size > 0);
	ASSERT(recvfromaddr != NULL);
	ASSERT(recvtoaddr != NULL);

	/* Wait packet */
	index = capwap_wait_recvready(fds, fdscount, timeout);
	if (index < 0) {
		return index;
	} else if (index >= g_wtp.fdsnetworkcount) {
		int pos = index - g_wtp.fdsnetworkcount;

		if (pos < g_wtp.eventscount) {
			if (!g_wtp.events[pos].event_handler) {
				return CAPWAP_RECV_ERROR_SOCKET;
			}

			g_wtp.events[pos].event_handler(fds[index].fd, g_wtp.events[pos].param1, g_wtp.events[pos].param2);
		}

		return WTP_RECV_NOERROR_RADIO;
	}

	/* Receive packet */
	if (!capwap_recvfrom_fd(fds[index].fd, buffer, size, recvfromaddr, recvtoaddr)) {
		return CAPWAP_RECV_ERROR_SOCKET;
	}

	return index;
}

/* WTP state machine */
int wtp_dfa_running(void) {
	int res;
	int result = CAPWAP_SUCCESSFUL;
	struct timeout_control timeout;

	char bufferencrypt[CAPWAP_MAX_PACKET_SIZE];
	char bufferplain[CAPWAP_MAX_PACKET_SIZE];
	char* buffer;
	int buffersize;

	struct capwap_socket socket;
	struct capwap_connection connection;
	struct capwap_parsed_packet packet;

	int index;
	struct sockaddr_storage recvfromaddr;
	struct sockaddr_storage recvtoaddr;
	int isrecvpacket = 0;

	/* Init */
	capwap_init_timeout(&timeout);
	capwap_set_timeout(0, &timeout, CAPWAP_TIMER_CONTROL_CONNECTION);	/* Start DFA with timeout */

	memset(&packet, 0, sizeof(struct capwap_parsed_packet));

	/* Configure poll struct */
	g_wtp.fdstotalcount = CAPWAP_MAX_SOCKETS * 2;
	g_wtp.fds = (struct pollfd*)capwap_alloc(sizeof(struct pollfd) * g_wtp.fdstotalcount);

	/* Retrive all socket for polling */
	g_wtp.fdsnetworkcount = capwap_network_set_pollfd(&g_wtp.net, g_wtp.fds, g_wtp.fdstotalcount);
	g_wtp.fdstotalcount = g_wtp.fdsnetworkcount;
	ASSERT(g_wtp.fdstotalcount > 0);

	/* Update Event File Descriptor */
	wtp_radio_update_fdevent();

	/* Handler signal */
	g_wtp.running = 1;
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, wtp_signal_handler);
	signal(SIGTERM, wtp_signal_handler);

	/* Init complete, start DFA */
	wtp_dfa_change_state(CAPWAP_IDLE_STATE);
	wtp_dfa_state_idle(NULL, &timeout);

	/* */
	while (g_wtp.dfa.state != CAPWAP_DEAD_STATE) {
		/* If request wait packet from AC */
		isrecvpacket = 0;
		buffer = bufferencrypt;
		buffersize = CAPWAP_MAX_PACKET_SIZE;
		index = wtp_recvfrom(g_wtp.fds, g_wtp.fdstotalcount, buffer, &buffersize, &recvfromaddr, &recvtoaddr, &timeout);
		if (!g_wtp.running) {
			capwap_logging_debug("Closing WTP, Teardown connection");

			/* Manual teardown */
			index = CAPWAP_RECV_ERROR_TIMEOUT;
			wtp_teardown_connection(&timeout);

			/* Wait RFC teardown timeout */
			capwap_wait_timeout(&timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
		}

		if (index >= 0) {
			if (g_wtp.teardown) {
				/* Drop packet */
				continue;
			} else {
				int check;

				/* Retrieve network information */
				capwap_get_network_socket(&g_wtp.net, &socket, g_wtp.fds[index].fd);

				/* Check source */
				if (socket.isctrlsocket && (g_wtp.acctrladdress.ss_family != AF_UNSPEC)) {
					if (capwap_compare_ip(&g_wtp.acctrladdress, &recvfromaddr)) {
						/* Unknown source */
						continue;
					}
				} else if (!socket.isctrlsocket && (g_wtp.acdataaddress.ss_family != AF_UNSPEC)) {
					if (capwap_compare_ip(&g_wtp.acdataaddress, &recvfromaddr)) {
						/* Unknown source */
						continue;
					}
				}

				/* Check of packet */
				check = capwap_sanity_check(socket.isctrlsocket, g_wtp.dfa.state, buffer, buffersize, g_wtp.ctrldtls.enable, g_wtp.datadtls.enable);
				if (check == CAPWAP_DTLS_PACKET) {
					struct capwap_dtls* dtls = (socket.isctrlsocket ? &g_wtp.ctrldtls : &g_wtp.datadtls);

					if (dtls->enable) {
						int oldaction = dtls->action;

						/* Decrypt packet */
						buffersize = capwap_decrypt_packet(dtls, buffer, buffersize, bufferplain, CAPWAP_MAX_PACKET_SIZE);
						if (buffersize > 0) {
							buffer = bufferplain;
							check = CAPWAP_PLAIN_PACKET;
						} else if (buffersize == CAPWAP_ERROR_AGAIN) {
							/* Check is handshake complete */
							if ((oldaction == CAPWAP_DTLS_ACTION_HANDSHAKE) && (dtls->action == CAPWAP_DTLS_ACTION_DATA)) {
								if (socket.isctrlsocket) {
									if (g_wtp.dfa.state == CAPWAP_DTLS_CONNECT_STATE) {
										check = CAPWAP_NONE_PACKET;
										wtp_send_join(&timeout);
									} else {
										check = CAPWAP_WRONG_PACKET;
										wtp_teardown_connection(&timeout);
									}
								} else {
									if (g_wtp.dfa.state == CAPWAP_DATA_CHECK_STATE) {
										check = CAPWAP_NONE_PACKET;
										wtp_start_datachannel(&timeout);
									} else {
										check = CAPWAP_WRONG_PACKET;
										wtp_teardown_connection(&timeout);
									}
								}
							}

							continue;		/* Next packet */
						} else {
							if ((oldaction == CAPWAP_DTLS_ACTION_DATA) && (dtls->action == CAPWAP_DTLS_ACTION_SHUTDOWN)) {
								wtp_teardown_connection(&timeout);
							}

							continue;		/* Next packet */
						}
					} else {
						continue;		/* Drop packet */
					}
				} else if (check == CAPWAP_WRONG_PACKET) {
					capwap_logging_debug("Warning: sanity check failure");
					/* Drop packet */
					continue;
				}

				/* */
				if (check == CAPWAP_PLAIN_PACKET) {
					struct capwap_packet_rxmng* rxmngpacket;

					/* Detect local address */
					if (recvtoaddr.ss_family == AF_UNSPEC) {
						if (capwap_get_localaddress_by_remoteaddress(&recvtoaddr, &recvfromaddr, g_wtp.net.bind_interface, (!(g_wtp.net.bind_ctrl_flags & CAPWAP_IPV6ONLY_FLAG) ? 1 : 0))) {
							struct sockaddr_storage sockinfo;
							socklen_t sockinfolen = sizeof(struct sockaddr_storage);

							memset(&sockinfo, 0, sizeof(struct sockaddr_storage));
							if (getsockname(g_wtp.fds[index].fd, (struct sockaddr*)&sockinfo, &sockinfolen) < 0) {
								break; 
							}

							CAPWAP_SET_NETWORK_PORT(&recvtoaddr, CAPWAP_GET_NETWORK_PORT(&sockinfo));
						}
					}

					/* */
					if (socket.isctrlsocket) {
						capwap_logging_debug("Receive control packet");
					} else {
						capwap_logging_debug("Receive data packet");
					}

					/* Defragment management */
					rxmngpacket = wtp_get_packet_rxmng(socket.isctrlsocket);

					/* If request, defragmentation packet */
					check = capwap_packet_rxmng_add_recv_packet(rxmngpacket, buffer, buffersize);
					if (check == CAPWAP_REQUEST_MORE_FRAGMENT) {
						continue;
					} else if (check != CAPWAP_RECEIVE_COMPLETE_PACKET) {
						/* Discard fragments */
						wtp_free_packet_rxmng(socket.isctrlsocket);
						continue;
					}

					/* Receive all fragment */
					memcpy(&connection.socket, &socket, sizeof(struct capwap_socket));
					memcpy(&connection.localaddr, &recvtoaddr, sizeof(struct sockaddr_storage));
					memcpy(&connection.remoteaddr, &recvfromaddr, sizeof(struct sockaddr_storage));

					/* Check for already response to packet */
					if (socket.isctrlsocket) {
						if (capwap_recv_retrasmitted_request(&g_wtp.ctrldtls, rxmngpacket, &connection, g_wtp.lastrecvpackethash, g_wtp.responsefragmentpacket)) {
							wtp_free_packet_rxmng(socket.isctrlsocket);
							capwap_logging_debug("Retrasmitted packet");
							continue;
						}

						/* Check message type */
						res = capwap_check_message_type(rxmngpacket);
						if (res != VALID_MESSAGE_TYPE) {
							if (res == INVALID_REQUEST_MESSAGE_TYPE) {
								capwap_logging_warning("Unexpected Unrecognized Request, send Response Packet with error");
								wtp_send_invalid_request(rxmngpacket, &connection, CAPWAP_RESULTCODE_MSG_UNEXPECTED_UNRECOGNIZED_REQUEST);
							}

							capwap_logging_debug("Invalid message type");
							wtp_free_packet_rxmng(socket.isctrlsocket);
							continue;
						}
					}

					/* Parsing packet */
					res = capwap_parsing_packet(rxmngpacket, &connection, &packet);
					if (res != PARSING_COMPLETE) {
						if (socket.isctrlsocket && (res == UNRECOGNIZED_MESSAGE_ELEMENT) && capwap_is_request_type(rxmngpacket->ctrlmsg.type)) {
							capwap_logging_warning("Unrecognized Message Element, send Response Packet with error");
							wtp_send_invalid_request(rxmngpacket, &connection, CAPWAP_RESULTCODE_FAILURE_UNRECOGNIZED_MESSAGE_ELEMENT);
							/* TODO: add the unrecognized message element */
						}

						/* */
						capwap_free_parsed_packet(&packet);
						wtp_free_packet_rxmng(socket.isctrlsocket);
						capwap_logging_debug("Failed parsing packet");
						continue;
					}

					/* Validate packet */
					if (capwap_validate_parsed_packet(&packet, NULL)) {
						if (socket.isctrlsocket && capwap_is_request_type(rxmngpacket->ctrlmsg.type)) {
							capwap_logging_warning("Missing Mandatory Message Element, send Response Packet with error");
							wtp_send_invalid_request(rxmngpacket, &connection, CAPWAP_RESULTCODE_FAILURE_MISSING_MANDATORY_MSG_ELEMENT);
						}

						/* */
						capwap_free_parsed_packet(&packet);
						wtp_free_packet_rxmng(socket.isctrlsocket);
						capwap_logging_debug("Failed validation parsed packet");
						continue;
					}

					/* Receive a complete packet */
					isrecvpacket = 1;
				}
			}
		} else if ((index == CAPWAP_RECV_ERROR_INTR) || (index == WTP_RECV_NOERROR_RADIO)) {
			/* Ignore recv */
			continue;
		} else if (index == CAPWAP_RECV_ERROR_SOCKET) {
			/* Socket close */
			break;
		}

		/* Execute state */
		wtp_dfa_execute((isrecvpacket ? &packet : NULL), &timeout);

		/* Free memory */
		capwap_free_parsed_packet(&packet);
		if (isrecvpacket) {
			wtp_free_packet_rxmng(socket.isctrlsocket);
		}
	}

	/* Free memory */
	capwap_free(g_wtp.fds);

	return result;
}

/* Change WTP state machine */
void wtp_dfa_change_state(int state) {
	if (state != g_wtp.dfa.state) {
		capwap_logging_debug("WTP change state from %s to %s", capwap_dfa_getname(g_wtp.dfa.state), capwap_dfa_getname(state));
		g_wtp.dfa.state = state;
	}
}

/* */
void wtp_free_reference_last_request(void) {
	capwap_list_flush(g_wtp.requestfragmentpacket);
}

/* */
void wtp_free_reference_last_response(void) {
	capwap_list_flush(g_wtp.responsefragmentpacket);
	memset(&g_wtp.lastrecvpackethash[0], 0, sizeof(g_wtp.lastrecvpackethash));
}
