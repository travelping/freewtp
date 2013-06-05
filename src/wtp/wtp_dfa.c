#include "wtp.h"
#include "wtp_dfa.h"
#include "capwap_array.h"
#include "capwap_dfa.h"
#include "capwap_dtls.h"

#include <signal.h>

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
void wtp_send_invalid_request(struct capwap_packet_rxmng* rxmngpacket, struct capwap_connection* connection) {
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_list* responsefragmentpacket;
	struct capwap_fragment_packet_item* packet;
	struct capwap_header* header;
	struct capwap_resultcode_element resultcode = { .code = CAPWAP_RESULTCODE_MSG_UNEXPECTED_UNRECOGNIZED_REQUEST };

	ASSERT(rxmngpacket != NULL);
	ASSERT(rxmngpacket->fragmentlist->first != NULL);
	ASSERT(connection != NULL);

	/* */
	packet = (struct capwap_fragment_packet_item*)rxmngpacket->fragmentlist->first->item;
	header = (struct capwap_header*)packet->buffer;

	/* Odd message type, response with "Unrecognized Request" */
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
static int wtp_dfa_execute(struct capwap_parsed_packet* packet, struct timeout_control* timeout) {
	int action = WTP_DFA_NO_PACKET;

	switch (g_wtp.dfa.state) {
		case CAPWAP_IDLE_STATE: {
			action = wtp_dfa_state_idle(packet, timeout);
			break;
		}

		case CAPWAP_IDLE_TO_DISCOVERY_STATE: {
			action = wtp_dfa_state_idle_to_discovery(packet, timeout);
			break;
		}
		
		case CAPWAP_IDLE_TO_DTLS_SETUP_STATE: {
			action = wtp_dfa_state_idle_to_dtlssetup(packet, timeout);
			break;
		}
		
		case CAPWAP_DISCOVERY_STATE: {
			action = wtp_dfa_state_discovery(packet, timeout);
			break;
		}
					
		case CAPWAP_DISCOVERY_TO_SULKING_STATE: {
			action = wtp_dfa_state_discovery_to_sulking(packet, timeout);
			break;
		}
		
		case CAPWAP_DISCOVERY_TO_DTLS_SETUP_STATE: {
			action = wtp_dfa_state_discovery_to_dtlssetup(packet, timeout);
			break;
		}
		
		case CAPWAP_SULKING_STATE: {
			action = wtp_dfa_state_sulking(packet, timeout);
			break;
		}

		case CAPWAP_SULKING_TO_IDLE_STATE: {
			action = wtp_dfa_state_sulking_to_idle(packet, timeout);
			break;
		}
		
		case CAPWAP_DTLS_SETUP_STATE: {
			action = wtp_dfa_state_dtlssetup(packet, timeout);
			break;
		}
		
		case CAPWAP_DTLS_SETUP_TO_IDLE_STATE: {
			/* Never called with this state */
			ASSERT(0);
			break;
		}
		
		case CAPWAP_DTLS_SETUP_TO_SULKING_STATE: {
			/* Never called with this state */
			ASSERT(0);
			break;
		}
		
		case CAPWAP_DTLS_SETUP_TO_AUTHORIZE_STATE: {
			/* Never called with this state */
			ASSERT(0);
			break;
		}
		
		case CAPWAP_AUTHORIZE_STATE: {
			/* Never called with this state */
			ASSERT(0);
			break;
		}
		
		case CAPWAP_AUTHORIZE_TO_DTLS_SETUP_STATE: {
			/* Never called with this state */
			ASSERT(0);
			break;
		}
		
		case CAPWAP_AUTHORIZE_TO_DTLS_CONNECT_STATE: {
			/* Never called with this state */
			ASSERT(0);
			break;
		}
		
		case CAPWAP_AUTHORIZE_TO_DTLS_TEARDOWN_STATE: {
			/* Never called with this state */
			ASSERT(0);
			break;
		}
					
		case CAPWAP_DTLS_CONNECT_STATE: {
			action = wtp_dfa_state_dtlsconnect(packet, timeout);
			break;
		}
		
		case CAPWAP_DTLS_CONNECT_TO_DTLS_TEARDOWN_STATE: {
			action = wtp_dfa_state_dtlsconnect_to_dtlsteardown(packet, timeout);
			break;
		}
		
		case CAPWAP_DTLS_CONNECT_TO_JOIN_STATE: {
			action = wtp_dfa_state_dtlsconnect_to_join(packet, timeout);
			break;
		}
		
		case CAPWAP_DTLS_TEARDOWN_STATE: {
			action = wtp_dfa_state_dtlsteardown(packet, timeout);
			break;
		}
		
		case CAPWAP_DTLS_TEARDOWN_TO_IDLE_STATE: {
			action = wtp_dfa_state_dtlsteardown_to_idle(packet, timeout);
			break;
		}
		
		case CAPWAP_DTLS_TEARDOWN_TO_SULKING_STATE: {
			action = wtp_dfa_state_dtlsteardown_to_sulking(packet, timeout);
			break;
		}
		
		case CAPWAP_JOIN_STATE: {
			action = wtp_dfa_state_join(packet, timeout);
			break;
		}
		
		case CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE: {
			action = wtp_dfa_state_join_to_dtlsteardown(packet, timeout);
			break;
		}
		
		case CAPWAP_JOIN_TO_IMAGE_DATA_STATE: {
			/* Never called with this state */
			ASSERT(0);
			break;
		}
		
		case CAPWAP_JOIN_TO_CONFIGURE_STATE: {
			action = wtp_dfa_state_join_to_configure(packet, timeout);
			break;
		}
		
		case CAPWAP_IMAGE_DATA_STATE: {
			/* Never called with this state */
			ASSERT(0);
			break;
		}
		
		case CAPWAP_IMAGE_DATA_TO_RESET_STATE: {
			/* Never called with this state */
			ASSERT(0);
			break;
		}
		
		case CAPWAP_IMAGE_DATA_TO_DTLS_TEARDOWN_STATE: {
			action = wtp_dfa_state_imagedata_to_dtlsteardown(packet, timeout);
			break;
		}
		
		case CAPWAP_CONFIGURE_STATE: {
			action = wtp_dfa_state_configure(packet, timeout);
			break;
		}
		
		case CAPWAP_CONFIGURE_TO_RESET_STATE: {
			/* Never called with this state */
			ASSERT(0);
			break;
		}
		
		case CAPWAP_CONFIGURE_TO_DTLS_TEARDOWN_STATE: {
			action = wtp_dfa_state_configure_to_dtlsteardown(packet, timeout);
			break;
		}
		
		case CAPWAP_CONFIGURE_TO_DATA_CHECK_STATE: {
			action = wtp_dfa_state_configure_to_datacheck(packet, timeout);
			break;
		}
		
		case CAPWAP_RESET_STATE: {
			action = wtp_dfa_state_reset(packet, timeout);
			break;
		}
		
		case CAPWAP_RESET_TO_DTLS_TEARDOWN_STATE: {
			/* Never called with this state */
			ASSERT(0);
			break;
		}
		
		case CAPWAP_DATA_CHECK_STATE: {
			action = wtp_dfa_state_datacheck(packet, timeout);
			break;
		}
		
		case CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE: {
			action = wtp_dfa_state_datacheck_to_dtlsteardown(packet, timeout);
			break;
		}
		
		case CAPWAP_DATA_CHECK_TO_RUN_STATE: {
			action = wtp_dfa_state_datacheck_to_run(packet, timeout);
			break;
		}
		
		case CAPWAP_RUN_STATE: {
			action = wtp_dfa_state_run(packet, timeout);
			break;
		}
		
		case CAPWAP_RUN_TO_DTLS_TEARDOWN_STATE: {
			action = wtp_dfa_state_run_to_dtlsteardown(packet, timeout);
			break;
		}
		
		case CAPWAP_RUN_TO_RESET_STATE: {
			/* Never called with this state */
			ASSERT(0);
			break;
		}

		case CAPWAP_DEAD_STATE: {
			/* Never called with this state */
			ASSERT(0);
			break;
		}

		default: {
			capwap_logging_debug("Unknown action event: %lu", g_wtp.dfa.state);
			break;
		}
	}

	return action;
}

/* WTP state machine */
int wtp_dfa_running(void) {
	int res;
	int result = CAPWAP_SUCCESSFUL;
	int action = WTP_DFA_NO_PACKET;
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
	
	struct pollfd* fds;
	int fdscount;
	
	/* Init */
	capwap_init_timeout(&timeout);
	capwap_set_timeout(0, &timeout, CAPWAP_TIMER_CONTROL_CONNECTION);	/* Start DFA with timeout */
	
	memset(&packet, 0, sizeof(struct capwap_parsed_packet));
	
	/* Configure poll struct */
	fdscount = CAPWAP_MAX_SOCKETS * 2;
	fds = (struct pollfd*)capwap_alloc(sizeof(struct pollfd) * fdscount);
	if (!fds) {
		capwap_outofmemory();
	}
	
	/* Retrive all socket for polling */
	fdscount = capwap_network_set_pollfd(&g_wtp.net, fds, fdscount);
	ASSERT(fdscount > 0);

	/* Handler signal */
	g_wtp.running = 1;
	signal(SIGINT, wtp_signal_handler);
	signal(SIGTERM, wtp_signal_handler);

	while (action != WTP_DFA_EXIT) {
		/* If request wait packet from AC */
		isrecvpacket = 0;
		if ((action == WTP_DFA_ACCEPT_PACKET) || (action == WTP_DFA_DROP_PACKET)) {
			buffer = bufferencrypt;
			buffersize = CAPWAP_MAX_PACKET_SIZE;
			index = capwap_recvfrom(fds, fdscount, buffer, &buffersize, &recvfromaddr, &recvtoaddr, &timeout);
			if (!g_wtp.running) {
				capwap_logging_debug("Closing WTP, Teardown connection");

				/* Manual teardown */
				index = CAPWAP_RECV_ERROR_TIMEOUT;
				wtp_teardown_connection(&timeout);

				/* Wait RFC teardown timeout */
				capwap_wait_timeout(&timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
			}

			if (index >= 0) {
				if (action == WTP_DFA_DROP_PACKET) {
					/* Drop packet */
					continue;
				} else {
					int check;

					/* Check of packet */
					capwap_get_network_socket(&g_wtp.net, &socket, fds[index].fd);
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
											wtp_dfa_change_state(CAPWAP_DTLS_CONNECT_TO_JOIN_STATE);
											action = WTP_DFA_NO_PACKET;
										} else {
											/* TODO */ 		/* Connection error */
											check = CAPWAP_WRONG_PACKET;
										}
									} else {
										if (g_wtp.dfa.state == CAPWAP_DATA_CHECK_TO_RUN_STATE) {
											check = CAPWAP_NONE_PACKET;
											action = WTP_DFA_NO_PACKET;
										} else {
											/* TODO */ 		/* Connection error */
											check = CAPWAP_WRONG_PACKET;
										}
									}
								}

								continue;		/* Next packet */
							} else {
								if ((oldaction == CAPWAP_DTLS_ACTION_DATA) && (dtls->action == CAPWAP_DTLS_ACTION_SHUTDOWN)) {
									action = wtp_teardown_connection(&timeout);
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
								if (getsockname(fds[index].fd, (struct sockaddr*)&sockinfo, &sockinfolen) < 0) {
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
									wtp_send_invalid_request(rxmngpacket, &connection);
								}

								capwap_logging_debug("Invalid message type");
								wtp_free_packet_rxmng(socket.isctrlsocket);
								continue;
							}
						}

						/* Parsing packet */
						if (capwap_parsing_packet(rxmngpacket, &connection, &packet)) {
							capwap_free_parsed_packet(&packet);
							wtp_free_packet_rxmng(socket.isctrlsocket);
							capwap_logging_debug("Failed parsing packet");
							continue;
						}

						/* Validate packet */
						if (capwap_validate_parsed_packet(&packet, NULL)) {
							/* TODO gestione errore risposta */
							capwap_free_parsed_packet(&packet);
							wtp_free_packet_rxmng(socket.isctrlsocket);
							capwap_logging_debug("Failed validation parsed packet");
							continue;
						}

						/* Receive a complete packet */
						isrecvpacket = 1;
					}
				}
			} else if (index == CAPWAP_RECV_ERROR_INTR) {
				/* Ignore recv */
				continue;
			} else if (index == CAPWAP_RECV_ERROR_SOCKET) {
				/* Socket close */
				break;
			}
		}

		/* Execute state */
		action = wtp_dfa_execute((isrecvpacket ? &packet : NULL), &timeout);

		/* Free memory */
		capwap_free_parsed_packet(&packet);
		if (isrecvpacket) {
			wtp_free_packet_rxmng(socket.isctrlsocket);
		}
	}

	/* Free memory */
	capwap_free(fds);

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
