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

/* WTP state machine */
int wtp_dfa_execute(void) {
	int result = CAPWAP_SUCCESSFUL;
	int action = WTP_DFA_NO_PACKET;
	struct timeout_control timeout;

	struct capwap_packet packet;
	capwap_fragment_list* defraglist;
	char buffer[CAPWAP_MAX_PACKET_SIZE];
	int buffersize;

	int index;
	struct sockaddr_storage recvfromaddr;
	struct sockaddr_storage recvtoaddr;
	int isrecvpacket = 0;
	
	struct pollfd* fds;
	int fdscount;
	
	/* Init */
	capwap_init_timeout(&timeout);
	capwap_set_timeout(0, &timeout, CAPWAP_TIMER_CONTROL_CONNECTION);	/* Start DFA with timeout */
	
	memset(&packet, 0, sizeof(struct capwap_packet));
	defraglist = capwap_defragment_init_list();
	
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

	for (;;) {
		/* If request wait packet from AC */
		isrecvpacket = 0;
		if ((action == WTP_DFA_ACCEPT_PACKET) || (action == WTP_DFA_DROP_PACKET)) {
			buffersize = CAPWAP_MAX_PACKET_SIZE;
			index = capwap_recvfrom(fds, fdscount, buffer, &buffersize, &recvfromaddr, &recvtoaddr, &timeout);
			if (!g_wtp.running) {
				break;
			}

			if (index >= 0) {
				if (action == WTP_DFA_DROP_PACKET) {
					/* Drop packet */
					continue;
				} else {
					int check;
					
					/* Check of packet */
					capwap_get_network_socket(&g_wtp.net, &packet.socket, fds[index].fd);
					check = capwap_sanity_check(packet.socket.isctrlsocket, g_wtp.dfa.state, buffer, buffersize, g_wtp.ctrldtls.enable, g_wtp.datadtls.enable);
					if (check == CAPWAP_DTLS_PACKET) {
						struct capwap_dtls* dtls = (packet.socket.isctrlsocket ? &g_wtp.ctrldtls : &g_wtp.datadtls);
						
						if (dtls->enable) {
							int oldaction = dtls->action;
							
							/* Decrypt packet */
							buffersize = capwap_decrypt_packet(dtls, buffer, buffersize, NULL, CAPWAP_MAX_PACKET_SIZE);
							if (buffersize > 0) {
								check = CAPWAP_PLAIN_PACKET;
							} else if (buffersize == CAPWAP_ERROR_AGAIN) {
								/* Check is handshake complete */
								if ((oldaction == CAPWAP_DTLS_ACTION_HANDSHAKE) && (dtls->action == CAPWAP_DTLS_ACTION_DATA)) {
									if (packet.socket.isctrlsocket) {
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
						/* If request, defragmentation packet */
						check = capwap_defragment_packets(&recvfromaddr, buffer, buffersize, defraglist, &packet);
						if (check == CAPWAP_REQUEST_MORE_FRAGMENT) {
							continue;
						} else if (check != CAPWAP_RECEIVE_COMPLETE_PACKET) {
							/* Discard fragments */
							capwap_defragment_remove_sender(defraglist, &recvfromaddr);
							continue;
						}
						
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
						
						/* Receive a complete packet */
						isrecvpacket = 1;
						memcpy(&packet.localaddr, &recvtoaddr, sizeof(struct sockaddr_storage));
						memcpy(&packet.remoteaddr, &recvfromaddr, sizeof(struct sockaddr_storage));

						/* Check for already response to packet */
						if (packet.socket.isctrlsocket) {
							if (capwap_recv_retrasmitted_request(&g_wtp.ctrldtls, &packet, g_wtp.remoteseqnumber, g_wtp.lastrecvpackethash, &g_wtp.acctrlsock, g_wtp.responsefragmentpacket, &g_wtp.wtpctrladdress, &g_wtp.acctrladdress)) {
								capwap_free_packet(&packet);
								continue;
							}

							/* Check message type */
							if (!capwap_check_message_type(&g_wtp.ctrldtls, &packet, g_wtp.mtu)) {
								capwap_free_packet(&packet);
								continue;
							}
						}
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
		switch (g_wtp.dfa.state) {
			case CAPWAP_IDLE_STATE: {
				action = wtp_dfa_state_idle((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
	
			case CAPWAP_IDLE_TO_DISCOVERY_STATE: {
				action = wtp_dfa_state_idle_to_discovery((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_IDLE_TO_DTLS_SETUP_STATE: {
				action = wtp_dfa_state_idle_to_dtlssetup((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_DISCOVERY_STATE: {
				action = wtp_dfa_state_discovery((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
						
			case CAPWAP_DISCOVERY_TO_SULKING_STATE: {
				action = wtp_dfa_state_discovery_to_sulking((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_DISCOVERY_TO_DTLS_SETUP_STATE: {
				action = wtp_dfa_state_discovery_to_dtlssetup((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_SULKING_STATE: {
				action = wtp_dfa_state_sulking((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
	
			case CAPWAP_SULKING_TO_IDLE_STATE: {
				action = wtp_dfa_state_sulking_to_idle((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_DTLS_SETUP_STATE: {
				action = wtp_dfa_state_dtlssetup((isrecvpacket ? &packet : NULL), &timeout);
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
				action = wtp_dfa_state_dtlsconnect((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_DTLS_CONNECT_TO_DTLS_TEARDOWN_STATE: {
				action = wtp_dfa_state_dtlsconnect_to_dtlsteardown((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_DTLS_CONNECT_TO_JOIN_STATE: {
				action = wtp_dfa_state_dtlsconnect_to_join((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_DTLS_TEARDOWN_STATE: {
				action = wtp_dfa_state_dtlsteardown((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_DTLS_TEARDOWN_TO_IDLE_STATE: {
				action = wtp_dfa_state_dtlsteardown_to_idle((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_DTLS_TEARDOWN_TO_SULKING_STATE: {
				action = wtp_dfa_state_dtlsteardown_to_sulking((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_JOIN_STATE: {
				action = wtp_dfa_state_join((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_JOIN_TO_DTLS_TEARDOWN_STATE: {
				action = wtp_dfa_state_join_to_dtlsteardown((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_JOIN_TO_IMAGE_DATA_STATE: {
				/* Never called with this state */
				ASSERT(0);
				break;
			}
			
			case CAPWAP_JOIN_TO_CONFIGURE_STATE: {
				action = wtp_dfa_state_join_to_configure((isrecvpacket ? &packet : NULL), &timeout);
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
				action = wtp_dfa_state_imagedata_to_dtlsteardown((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_CONFIGURE_STATE: {
				action = wtp_dfa_state_configure((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_CONFIGURE_TO_RESET_STATE: {
				/* Never called with this state */
				ASSERT(0);
				break;
			}
			
			case CAPWAP_CONFIGURE_TO_DTLS_TEARDOWN_STATE: {
				action = wtp_dfa_state_configure_to_dtlsteardown((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_CONFIGURE_TO_DATA_CHECK_STATE: {
				action = wtp_dfa_state_configure_to_datacheck((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_RESET_STATE: {
				action = wtp_dfa_state_reset((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_RESET_TO_DTLS_TEARDOWN_STATE: {
				/* Never called with this state */
				ASSERT(0);
				break;
			}
			
			case CAPWAP_DATA_CHECK_STATE: {
				action = wtp_dfa_state_datacheck((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_DATA_CHECK_TO_DTLS_TEARDOWN_STATE: {
				action = wtp_dfa_state_datacheck_to_dtlsteardown((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_DATA_CHECK_TO_RUN_STATE: {
				action = wtp_dfa_state_datacheck_to_run((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_RUN_STATE: {
				action = wtp_dfa_state_run((isrecvpacket ? &packet : NULL), &timeout);
				break;
			}
			
			case CAPWAP_RUN_TO_DTLS_TEARDOWN_STATE: {
				action = wtp_dfa_state_run_to_dtlsteardown((isrecvpacket ? &packet : NULL), &timeout);
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
		
		/* Free memory */
		if (isrecvpacket) {
			capwap_free_packet(&packet);
		} else {
			capwap_defragment_flush_list(defraglist);
		}
	}

	/* Free DTSL Control */
	if (g_wtp.ctrldtls.enable) {
		capwap_crypt_close(&g_wtp.ctrldtls);
		capwap_crypt_freesession(&g_wtp.ctrldtls);
	}
	
	/* Free DTLS Data */
	if (g_wtp.datadtls.enable) {
		capwap_crypt_close(&g_wtp.datadtls);
		capwap_crypt_freesession(&g_wtp.datadtls);
	}

	/* Free memory */
	capwap_defragment_free_list(defraglist);
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
	capwap_fragment_free(g_wtp.requestfragmentpacket);
}

/* */
void wtp_free_reference_last_response(void) {
	capwap_fragment_free(g_wtp.responsefragmentpacket);
	memset(&g_wtp.lastrecvpackethash[0], 0, sizeof(g_wtp.lastrecvpackethash));
}
