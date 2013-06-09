#include "ac.h"
#include "capwap_dfa.h"
#include "capwap_event.h"
#include "ac_session.h"
#include "ac_discovery.h"

#include <signal.h>

/* Add packet to session */
static void ac_session_add_packet(struct ac_session_t* session, char* buffer, int size, int isctrlsocket, int plainbuffer) {
	struct capwap_list_item* item;
	struct ac_packet* packet;
	
	ASSERT(session != NULL);
	ASSERT(buffer != NULL);
	ASSERT(size > 0);

	/* Copy packet */
	item = capwap_itemlist_create(sizeof(struct ac_packet) + size);
	packet = (struct ac_packet*)item->item;
	packet->plainbuffer = plainbuffer;
	memcpy(packet->buffer, buffer, size);
	
	/* Append to packets list */
	capwap_lock_enter(&session->packetslock);
	capwap_itemlist_insert_after((isctrlsocket ? session->controlpackets : session->datapackets), NULL, item);
	capwap_event_signal(&session->waitpacket);
	capwap_lock_exit(&session->packetslock);
}

/* Find AC sessions */
static struct ac_session_t* ac_search_session_from_wtpaddress(struct sockaddr_storage* address, int isctrlsocket) {
	struct ac_session_t* result = NULL;
	struct capwap_list_item* search;
	
	ASSERT(address != NULL);
	
	capwap_lock_enter(&g_ac.sessionslock);
	
	search = g_ac.sessions->first;
	while (search != NULL) {
		struct ac_session_t* session = (struct ac_session_t*)search->item;
		ASSERT(session != NULL);
		
		if (!capwap_compare_ip(address, (isctrlsocket ? &session->wtpctrladdress : &session->wtpdataaddress))) {
			session->count++;
			result = session;
			break;
		}
	
		search = search->next;	
	}
	
	capwap_lock_exit(&g_ac.sessionslock);
	
	return result;
}

/* */
static struct ac_session_t* ac_get_session_from_keepalive(void* buffer, int buffersize) {
	struct capwap_parsed_packet packet;
	struct capwap_packet_rxmng* rxmngpacket;
	struct ac_session_t* result = NULL;

	ASSERT(buffer != NULL);
	ASSERT(buffersize > 0);

	/* Build receive manager CAPWAP message */
	rxmngpacket = capwap_packet_rxmng_create_message(0);
	if (capwap_packet_rxmng_add_recv_packet(rxmngpacket, buffer, buffersize) != CAPWAP_RECEIVE_COMPLETE_PACKET) {
		/* Accept only keep alive without fragmentation */
		capwap_packet_rxmng_free(rxmngpacket);
		capwap_logging_debug("Receive data keep alive packet fragmentated");
		return NULL;
	}

	/* Validate message */
	if (capwap_check_message_type(rxmngpacket) != VALID_MESSAGE_TYPE) {
		/* Invalid message */
		capwap_packet_rxmng_free(rxmngpacket);
		capwap_logging_debug("Invalid data packet message type");
		return NULL;
	}

	/* Parsing packet */
	if (!capwap_parsing_packet(rxmngpacket, NULL, &packet)) {
		/* Validate packet */
		if (!capwap_validate_parsed_packet(&packet, NULL)) {
			struct capwap_list_item* search;
			struct capwap_sessionid_element* sessionid = (struct capwap_sessionid_element*)capwap_get_message_element_data(&packet, CAPWAP_ELEMENT_SESSIONID);

			capwap_lock_enter(&g_ac.sessionslock);

			search = g_ac.sessions->first;
			while (search != NULL) {
				struct ac_session_t* session = (struct ac_session_t*)search->item;

				ASSERT(session != NULL);

				if (!memcmp(sessionid, &session->sessionid, sizeof(struct capwap_sessionid_element))) {
					session->count++;
					result = session;
					break;
				}

				search = search->next;
			}

			capwap_lock_exit(&g_ac.sessionslock);
		} else {
			capwap_logging_debug("Failed validation parsed data packet");
		}
	} else {
		capwap_logging_debug("Failed parsing data packet");
	}

	/* Free resource */
	capwap_free_parsed_packet(&packet);
	capwap_packet_rxmng_free(rxmngpacket);

	return result;
}

/* Close session */
static void ac_close_session(struct ac_session_t* session) {
	session->closesession = 1;
	capwap_event_signal(&session->waitpacket);
}

/* Close sessions */
static void ac_close_sessions() {
	struct capwap_list_item* search;

	capwap_lock_enter(&g_ac.sessionslock);

	search = g_ac.sessions->first;
	while (search != NULL) {
		struct ac_session_t* session = (struct ac_session_t*)search->item;
		ASSERT(session != NULL);

		ac_close_session(session);

		search = search->next;
	}

	capwap_lock_exit(&g_ac.sessionslock);
}

/* DTLS Handshake BIO send */
static int ac_bio_handshake_send(struct capwap_dtls* dtls, char* buffer, int length, void* param) {
	struct ac_data_session_handshake* handshake = (struct ac_data_session_handshake*)param;
	return capwap_sendto(handshake->socket.socket[handshake->socket.type], buffer, length, &handshake->acaddress, &handshake->wtpaddress);
}

/* Find AC sessions */
static void ac_update_session_from_datapacket(struct capwap_socket* socket, struct sockaddr_storage* recvfromaddr, struct sockaddr_storage* recvtoaddr, void* buffer, int buffersize) {
	struct ac_session_t* session = NULL;
	struct capwap_preamble* preamble = (struct capwap_preamble*)buffer;

	ASSERT(buffer != NULL);
	ASSERT(buffersize > sizeof(struct capwap_preamble));
	ASSERT(socket != NULL);
	ASSERT(recvfromaddr != NULL);
	ASSERT(recvtoaddr != NULL);

	/* */
	if (preamble->type == CAPWAP_PREAMBLE_HEADER) {
		if ((g_ac.descriptor.dtlspolicy & CAPWAP_ACDESC_CLEAR_DATA_CHANNEL_ENABLED) != 0) {
			session = ac_get_session_from_keepalive(buffer, buffersize);
			if (session) {
				/* Update data session */
				memcpy(&session->datasocket, socket, sizeof(struct capwap_socket));
				memcpy(&session->acdataaddress, recvtoaddr, sizeof(struct sockaddr_storage));
				memcpy(&session->wtpdataaddress, recvfromaddr, sizeof(struct sockaddr_storage));
	
				/* Add packet*/
				ac_session_add_packet(session, buffer, buffersize, 0, 1);
				ac_session_release_reference(session);
			}
		}
	} else if (preamble->type == CAPWAP_PREAMBLE_DTLS_HEADER) {
		if ((g_ac.descriptor.dtlspolicy & CAPWAP_ACDESC_DTLS_DATA_CHANNEL_ENABLED) != 0) {
			struct capwap_list_item* itemlist;
			struct ac_data_session_handshake* handshake;
			
			/* Search active data dtls handshake */
			itemlist = g_ac.datasessionshandshake->first;
			while (itemlist != NULL) {
				handshake = (struct ac_data_session_handshake*)itemlist->item;
				
				if (!capwap_compare_ip(recvfromaddr, &handshake->wtpaddress) && !capwap_compare_ip(recvtoaddr, &handshake->acaddress)) {
					break;
				}
				
				/* Next */
				itemlist = itemlist->next;
			}
			
			/* Create new DTLS handshake */
			if (!itemlist) {
				itemlist = capwap_itemlist_create(sizeof(struct ac_data_session_handshake));
				handshake = (struct ac_data_session_handshake*)itemlist->item;
				memset(handshake, 0, sizeof(struct ac_data_session_handshake));
				
				/* */
				memcpy(&handshake->socket, socket, sizeof(struct capwap_socket));
				memcpy(&handshake->acaddress, recvtoaddr, sizeof(struct sockaddr_storage));
				memcpy(&handshake->wtpaddress, recvfromaddr, sizeof(struct sockaddr_storage));

				/* Create DTLS session */
				if (!capwap_crypt_createsession(&handshake->dtls, CAPWAP_DTLS_DATA_SESSION, &g_ac.dtlscontext, ac_bio_handshake_send, handshake)) {
					capwap_itemlist_free(itemlist);
					itemlist = NULL;
				} else {
					if (capwap_crypt_open(&handshake->dtls, recvfromaddr) == CAPWAP_HANDSHAKE_ERROR) {
						capwap_crypt_freesession(&handshake->dtls);
						capwap_itemlist_free(itemlist);
						itemlist = NULL;
					} else {
						/* Add item to list */
						capwap_itemlist_insert_after(g_ac.datasessionshandshake, NULL, itemlist);
					}
				}
			}
			
			/* Decrypt packet */
			if (itemlist) {
				char temp[CAPWAP_MAX_PACKET_SIZE];

				/* */
				handshake = (struct ac_data_session_handshake*)itemlist->item;
				buffersize = capwap_decrypt_packet(&handshake->dtls, buffer, buffersize, temp, CAPWAP_MAX_PACKET_SIZE);
				if (buffersize > 0) {
					session = ac_get_session_from_keepalive(temp, buffersize);
					if (!session) {
						capwap_itemlist_remove(g_ac.datasessionshandshake, itemlist);
						capwap_crypt_close(&handshake->dtls);
						capwap_crypt_freesession(&handshake->dtls);
						capwap_itemlist_free(itemlist);
					} else {
						/* Update DTLS session */
						capwap_crypt_change_dtls(&handshake->dtls, &session->datadtls);
						memcpy(&session->datasocket, &handshake->socket, sizeof(struct capwap_socket));
						memcpy(&session->acdataaddress, &handshake->acaddress, sizeof(struct sockaddr_storage));
						memcpy(&session->wtpdataaddress, &handshake->wtpaddress, sizeof(struct sockaddr_storage));
						capwap_crypt_change_bio_send(&session->datadtls, ac_bio_send, session);

						/* Remove temp element */
						capwap_itemlist_remove(g_ac.datasessionshandshake, itemlist);
						capwap_itemlist_free(itemlist);

						/* Add packet*/
						ac_session_add_packet(session, temp, buffersize, 0, 1);		/* Packet already decrypt */
						ac_session_release_reference(session);
					}
				} else if ((buffersize == CAPWAP_ERROR_SHUTDOWN) || (buffersize == CAPWAP_ERROR_CLOSE)) {
					capwap_itemlist_remove(g_ac.datasessionshandshake, itemlist);
					capwap_crypt_close(&handshake->dtls);
					capwap_crypt_freesession(&handshake->dtls);
					capwap_itemlist_free(itemlist);
				}
			}
		}
	}
}

/* Create new session */
static struct ac_session_t* ac_create_session(struct sockaddr_storage* wtpaddress, struct sockaddr_storage* acaddress, struct capwap_socket* ctrlsock) {
	int result;
	struct capwap_list_item* itemlist;
	struct ac_session_t* session;

	ASSERT(acaddress != NULL);
	ASSERT(wtpaddress != NULL);
	ASSERT(ctrlsock != NULL);

	/* Create new session */
	itemlist = capwap_itemlist_create(sizeof(struct ac_session_t));
	session = (struct ac_session_t*)itemlist->item;
	memset(session, 0, sizeof(struct ac_session_t));

	session->count = 2;
	memcpy(&session->acctrladdress, acaddress, sizeof(struct sockaddr_storage));
	memcpy(&session->wtpctrladdress, wtpaddress, sizeof(struct sockaddr_storage));
	memcpy(&session->ctrlsocket, ctrlsock, sizeof(struct capwap_socket));
	
	/* Duplicate state for DFA */
	memcpy(&session->dfa, &g_ac.dfa, sizeof(struct ac_state));
	session->dfa.acipv4list.addresses = capwap_array_clone(g_ac.dfa.acipv4list.addresses);
	session->dfa.acipv6list.addresses = capwap_array_clone(g_ac.dfa.acipv6list.addresses);

	session->dfa.rfcRetransmitInterval = AC_DEFAULT_RETRANSMIT_INTERVAL;
	session->dfa.rfcMaxRetransmit = AC_MAX_RETRANSMIT;
	session->dfa.rfcDTLSSessionDelete = AC_DEFAULT_DTLS_SESSION_DELETE;

	/* Add default AC list if empty*/
	if ((session->dfa.acipv4list.addresses->count == 0) && (session->dfa.acipv6list.addresses->count == 0)) {
		if (session->acctrladdress.ss_family == AF_INET) {
			struct in_addr* acip = (struct in_addr*)capwap_array_get_item_pointer(session->dfa.acipv4list.addresses, 0);
			memcpy(acip, &((struct sockaddr_in*)&session->acctrladdress)->sin_addr, sizeof(struct in_addr));
		} else if (session->acctrladdress.ss_family == AF_INET6) {
			struct in6_addr* acip = (struct in6_addr*)capwap_array_get_item_pointer(session->dfa.acipv6list.addresses, 0);
			memcpy(acip, &((struct sockaddr_in6*)&session->acctrladdress)->sin6_addr, sizeof(struct in6_addr));
		}
	}

	/* Init */
	capwap_event_init(&session->waitpacket);
	capwap_lock_init(&session->packetslock);

	session->controlpackets = capwap_list_create();
	session->datapackets = capwap_list_create();
	session->requestfragmentpacket = capwap_list_create();
	session->responsefragmentpacket = capwap_list_create();

	session->mtu = g_ac.mtu;
	session->state = CAPWAP_IDLE_STATE;

	/* Update session list */
	capwap_lock_enter(&g_ac.sessionslock);
	capwap_itemlist_insert_after(g_ac.sessions, NULL, itemlist);
	capwap_lock_exit(&g_ac.sessionslock);

	/* Create thread */
	result = pthread_create(&session->threadid, NULL, ac_session_thread, (void*)session);
	if (!result) {
		pthread_detach(session->threadid);

		/* Notify change session list */
		capwap_event_signal(&g_ac.changesessionlist);
	} else {
		capwap_logging_debug("Unable create session thread, error code %d", result);
		
		/* Destroy element */
		capwap_lock_enter(&g_ac.sessionslock);
		capwap_itemlist_free(capwap_itemlist_remove(g_ac.sessions, itemlist));
		capwap_lock_exit(&g_ac.sessionslock);
		
		session = NULL;
	}

	return session;
}

/* Update statistics */
void ac_update_statistics(void) {
	
	g_ac.descriptor.stations = 0; /* TODO */
	
	capwap_lock_enter(&g_ac.sessionslock);
	g_ac.descriptor.activewtp = g_ac.sessions->count;
	capwap_lock_exit(&g_ac.sessionslock);
}

/* Handler signal */
static void ac_signal_handler(int signum) {
	if ((signum == SIGINT) || (signum == SIGTERM)) {
		g_ac.running = 0;
	}
}

/* AC running */
int ac_execute(void) {
	int fdscount = CAPWAP_MAX_SOCKETS * 2;
	struct pollfd* fds;
	int result = CAPWAP_SUCCESSFUL;
	
	int index;
	int check;
	int isctrlsocket = 0;
	struct sockaddr_storage recvfromaddr;
	struct sockaddr_storage recvtoaddr;
	int isrecvpacket = 0;

	struct ac_session_t* session;
	struct capwap_socket ctrlsock;

	char buffer[CAPWAP_MAX_PACKET_SIZE];
	int buffersize;

	/* Configure poll struct */
	fds = (struct pollfd*)capwap_alloc(sizeof(struct pollfd) * fdscount);
	if (!fds) {
		capwap_outofmemory();
	}
	
	/* Retrive all socket for polling */
	fdscount = capwap_network_set_pollfd(&g_ac.net, fds, fdscount);
	ASSERT(fdscount > 0);

	/* Handler signal */
	g_ac.running = 1;
	signal(SIGINT, ac_signal_handler);
	signal(SIGTERM, ac_signal_handler);

	/* Start discovery thread */
	if (!ac_discovery_start()) {
		capwap_free(fds);
		capwap_logging_debug("Unable to start discovery thread");
		return AC_ERROR_SYSTEM_FAILER;
	}

	/* */
	for (;;) {
		/* Receive packet */
		isrecvpacket = 0;
		buffersize = sizeof(buffer);
		index = capwap_recvfrom(fds, fdscount, buffer, &buffersize, &recvfromaddr, &recvtoaddr, NULL);
		if (!g_ac.running) {
			break;
		}
		
		/* */
		if (index >= 0) {
			/* Detect local address */
			if (recvtoaddr.ss_family == AF_UNSPEC) {
				if (capwap_get_localaddress_by_remoteaddress(&recvtoaddr, &recvfromaddr, g_ac.net.bind_interface, (!(g_ac.net.bind_ctrl_flags & CAPWAP_IPV6ONLY_FLAG) ? 1 : 0))) {
					struct sockaddr_storage sockinfo;
					socklen_t sockinfolen = sizeof(struct sockaddr_storage);

					memset(&sockinfo, 0, sizeof(struct sockaddr_storage));
					if (getsockname(fds[index].fd, (struct sockaddr*)&sockinfo, &sockinfolen) < 0) {
						break; 
					}

					CAPWAP_SET_NETWORK_PORT(&recvtoaddr, CAPWAP_GET_NETWORK_PORT(&sockinfo));
				}
			}

			/* Search the AC session */
			isctrlsocket = ((index < (fdscount / 2)) ? 1 : 0);
			session = ac_search_session_from_wtpaddress(&recvfromaddr, isctrlsocket);

			if (session) {
				/* Add packet*/
				ac_session_add_packet(session, buffer, buffersize, isctrlsocket, 0);

				/* Release reference */
				ac_session_release_reference(session);
			} else {
				if (isctrlsocket) {
					unsigned short sessioncount;

					/* Get current session number */
					capwap_lock_enter(&g_ac.sessionslock);
					sessioncount = g_ac.sessions->count;
					capwap_lock_exit(&g_ac.sessionslock);

					/* PreParsing packet for reduce a DoS attack */
					check = capwap_sanity_check(isctrlsocket, CAPWAP_UNDEF_STATE, buffer, buffersize, g_ac.enabledtls, 0);
					if (check == CAPWAP_PLAIN_PACKET) {
						struct capwap_header* header = (struct capwap_header*)buffer;

						/* Accepted only packet without fragmentation */
						if (!IS_FLAG_F_HEADER(header)) {
							int headersize = GET_HLEN_HEADER(header) * 4;
							if (buffersize >= (headersize + sizeof(struct capwap_control_message))) {
								struct capwap_control_message* control = (struct capwap_control_message*)((char*)buffer + headersize);
								unsigned long type = ntohl(control->type);

								if (type == CAPWAP_DISCOVERY_REQUEST) {
									if (sessioncount < g_ac.descriptor.maxwtp) {
										ac_discovery_add_packet(buffer, buffersize, fds[index].fd, &recvfromaddr);
									}
								} else if (!g_ac.enabledtls && (type == CAPWAP_JOIN_REQUEST)) {
									if (sessioncount < g_ac.descriptor.maxwtp) {
										/* Retrive socket info */
										capwap_get_network_socket(&g_ac.net, &ctrlsock, fds[index].fd);

										/* Create a new session */
										session = ac_create_session(&recvfromaddr, &recvtoaddr, &ctrlsock);
										if (session) {
											ac_session_add_packet(session, buffer, buffersize, isctrlsocket, 1);

											/* Release reference */
											ac_session_release_reference(session);
										}
									}
								}
							}
						}
					} else if (check == CAPWAP_DTLS_PACKET) {
						/* Need create a new sessione for check if it is a valid DTLS handshake */
						if (sessioncount < g_ac.descriptor.maxwtp) {
							/* TODO prevent dos attack add filtering ip for multiple error */
	
							/* Retrive socket info */
							capwap_get_network_socket(&g_ac.net, &ctrlsock, fds[index].fd);
	
							/* Create a new session */
							session = ac_create_session(&recvfromaddr, &recvtoaddr, &ctrlsock);
							if (session) {
								ac_session_add_packet(session, buffer, buffersize, isctrlsocket, 0);
	
								/* Release reference */
								ac_session_release_reference(session);
							}
						}
					}
				} else {
					struct capwap_socket datasocket;

					/* Retrieve session by sessionid of data packet */
					capwap_get_network_socket(&g_ac.net, &datasocket, fds[index].fd);
					ac_update_session_from_datapacket(&datasocket, &recvfromaddr, &recvtoaddr, buffer, buffersize);
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
	
	/* Terminate discovery thread */
	ac_discovery_stop();

	/* Close all sessions */
	ac_close_sessions();

	/* Wait to terminate all sessions */
	for (;;) {
		int count;
		
		capwap_lock_enter(&g_ac.sessionslock);
		count = g_ac.sessions->count;
		capwap_lock_exit(&g_ac.sessionslock);
		
		if (!count) {
			break;
		}
		
		/* Wait that list is changed */
		capwap_logging_debug("Waiting for %d session terminate", count);
		capwap_event_wait(&g_ac.changesessionlist);
	}

	/* Free handshark session */
	while (g_ac.datasessionshandshake->first != NULL) {
		struct ac_data_session_handshake* handshake = (struct ac_data_session_handshake*)g_ac.datasessionshandshake->first->item;

		if (handshake->dtls.enable) {
			capwap_crypt_freesession(&handshake->dtls);
		}

		capwap_itemlist_free(capwap_itemlist_remove(g_ac.datasessionshandshake, g_ac.datasessionshandshake->first));
	}

	/* Free memory */
	capwap_free(fds);
	return result;
}
