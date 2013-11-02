#include "ac.h"
#include "capwap_dfa.h"
#include "ac_session.h"
#include "ac_discovery.h"
#include "ac_backend.h"

#include <signal.h>

#define AC_RECV_NOERROR_MSGQUEUE			-1001

/* */
static int ac_recvmsgqueue(int fd, struct ac_session_msgqueue_item_t* item) {
	int packetsize = -1;

	do {
		packetsize = recv(fd, (void*)item, sizeof(struct ac_session_msgqueue_item_t), 0);
	} while ((packetsize < 0) && ((errno == EAGAIN) || (errno == EINTR)));

	return ((packetsize == sizeof(struct ac_session_msgqueue_item_t)) ? 1 : 0);
}

/* */
static void ac_session_msgqueue_parsing_item(struct ac_session_msgqueue_item_t* item) {
	switch (item->message) {
		case AC_MESSAGE_QUEUE_CLOSE_THREAD: {
			struct capwap_list_item* search = g_ac.sessionsthread->first;
			while (search != NULL) {
				struct ac_session_thread_t* sessionthread = (struct ac_session_thread_t*)search->item;
				ASSERT(sessionthread != NULL);

				if (sessionthread->threadid == item->message_close_thread.threadid) {
					void* dummy;

					/* Clean thread resource */
					pthread_join(sessionthread->threadid, &dummy);
					capwap_itemlist_free(capwap_itemlist_remove(g_ac.sessionsthread, search));
					break;
				}

				/* */
				search = search->next;
			}

			break;
		}

		default: {
			capwap_logging_debug("Unknown message queue item: %lu", item->message);
			break;
		}
	}
}

/* */
static void ac_wait_terminate_allsessions(void) {
	struct ac_session_msgqueue_item_t item;

	/* Wait that list is empty */
	while (g_ac.sessionsthread->count > 0) {
		capwap_logging_debug("Waiting for %d session terminate", g_ac.sessionsthread->count);

		/* Receive message queue packet */
		if (!ac_recvmsgqueue(g_ac.fdmsgsessions[1], &item)) {
			capwap_logging_debug("Unable to receive message queue");
			break;
		}

		/* Parsing message queue packet */
		if (item.message == AC_MESSAGE_QUEUE_CLOSE_THREAD) {
			ac_session_msgqueue_parsing_item(&item);
		}
	}
}

/* Initialize message queue */
int ac_session_msgqueue_init(void) {
	if (socketpair(AF_LOCAL, SOCK_DGRAM, 0, g_ac.fdmsgsessions)) {
		return 0;
	}

	return 1;
}

/* Free sessions message queue */
void ac_session_msgqueue_free(void) {
	close(g_ac.fdmsgsessions[1]);
	close(g_ac.fdmsgsessions[0]);
}

/* */
void ac_session_msgqueue_notify_closethread(pthread_t threadid) {
	struct ac_session_msgqueue_item_t item;

	/* Send message */
	memset(&item, 0, sizeof(struct ac_session_msgqueue_item_t));
	item.message = AC_MESSAGE_QUEUE_CLOSE_THREAD;
	item.message_close_thread.threadid = threadid;

	send(g_ac.fdmsgsessions[0], (void*)&item, sizeof(struct ac_session_msgqueue_item_t), 0);
}

/* */
static int ac_recvfrom(struct pollfd* fds, int fdscount, void* buffer, int* size, struct sockaddr_storage* recvfromaddr, struct sockaddr_storage* recvtoaddr, struct timeout_control* timeout) {
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
	} else if (index == (fdscount - 1)) {
		struct ac_session_msgqueue_item_t item;

		/* Receive message queue packet */
		if (!ac_recvmsgqueue(fds[index].fd, &item)) {
			return CAPWAP_RECV_ERROR_SOCKET;
		}

		/* Parsing message queue packet */
		ac_session_msgqueue_parsing_item(&item);

		return AC_RECV_NOERROR_MSGQUEUE;
	}

	/* Receive packet */
	if (!capwap_recvfrom_fd(fds[index].fd, buffer, size, recvfromaddr, recvtoaddr)) {
		return CAPWAP_RECV_ERROR_SOCKET;
	}

	return index;
}

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
	capwap_lock_enter(&session->sessionlock);
	capwap_itemlist_insert_after((isctrlsocket ? session->controlpackets : session->datapackets), NULL, item);
	capwap_event_signal(&session->waitpacket);
	capwap_lock_exit(&session->sessionlock);
}

/* Add action to session */
static void ac_session_send_action(struct ac_session_t* session, long action, long param, void* data, long length) {
	struct capwap_list_item* item;
	struct ac_session_action* actionsession;

	ASSERT(session != NULL);
	ASSERT(length >= 0);

	/* */
	item = capwap_itemlist_create(sizeof(struct ac_session_action) + length);
	actionsession = (struct ac_session_action*)item->item;
	actionsession->action = action;
	actionsession->param = param;
	actionsession->length = length;
	if (length > 0) {
		ASSERT(data != NULL);
		memcpy(actionsession->data, data, length);
	}

	/* Append to actions list */
	capwap_lock_enter(&session->sessionlock);
	capwap_itemlist_insert_after(session->actionsession, NULL, item);
	capwap_event_signal(&session->waitpacket);
	capwap_lock_exit(&session->sessionlock);
}

/* Find AC sessions */
static struct ac_session_t* ac_search_session_from_wtpaddress(struct sockaddr_storage* address, int isctrlsocket) {
	struct ac_session_t* result = NULL;
	struct capwap_list_item* search;

	ASSERT(address != NULL);

	capwap_rwlock_rdlock(&g_ac.sessionslock);

	search = g_ac.sessions->first;
	while (search != NULL) {
		struct ac_session_t* session = (struct ac_session_t*)search->item;
		ASSERT(session != NULL);
		
		if (!capwap_compare_ip(address, (isctrlsocket ? &session->wtpctrladdress : &session->wtpdataaddress))) {
			/* Increment session count */
			capwap_lock_enter(&session->sessionlock);
			session->count++;
			capwap_lock_exit(&session->sessionlock);

			/*  */
			result = session;
			break;
		}

		search = search->next;
	}

	capwap_rwlock_exit(&g_ac.sessionslock);

	return result;
}

/* Find WTP session id */
struct ac_session_t* ac_search_session_from_sessionid(struct capwap_sessionid_element* sessionid) {
	struct ac_session_t* result = NULL;
	struct capwap_list_item* search;

	ASSERT(sessionid != NULL);

	capwap_rwlock_rdlock(&g_ac.sessionslock);

	search = g_ac.sessions->first;
	while (search != NULL) {
		struct ac_session_t* session = (struct ac_session_t*)search->item;
		ASSERT(session != NULL);
		
		if (!memcmp(sessionid, &session->sessionid, sizeof(struct capwap_sessionid_element))) {
			/* Increment session count */
			capwap_lock_enter(&session->sessionlock);
			session->count++;
			capwap_lock_exit(&session->sessionlock);

			/*  */
			result = session;
			break;
		}

		search = search->next;
	}

	capwap_rwlock_exit(&g_ac.sessionslock);

	return result;
}

/* */
int ac_has_sessionid(struct capwap_sessionid_element* sessionid) {
	int result = 0;
	struct capwap_list_item* search;

	ASSERT(sessionid != NULL);

	capwap_rwlock_rdlock(&g_ac.sessionslock);

	search = g_ac.sessions->first;
	while (search != NULL) {
		struct ac_session_t* session = (struct ac_session_t*)search->item;
		ASSERT(session != NULL);

		if (!memcmp(sessionid, &session->sessionid, sizeof(struct capwap_sessionid_element))) {
			result = 1;
			break;
		}

		search = search->next;
	}

	capwap_rwlock_exit(&g_ac.sessionslock);

	return result;
}

/* */
int ac_has_wtpid(char* wtpid) {
	int result = 0;
	struct capwap_list_item* search;

	if (!wtpid || !wtpid[0]) {
		return -1;
	}

	capwap_rwlock_rdlock(&g_ac.sessionslock);

	search = g_ac.sessions->first;
	while (search != NULL) {
		struct ac_session_t* session = (struct ac_session_t*)search->item;
		ASSERT(session != NULL);

		if (session->wtpid && !strcmp(session->wtpid, wtpid)) {
			result = 1;
			break;
		}

		search = search->next;
	}

	capwap_rwlock_exit(&g_ac.sessionslock);

	return result;
}

/* */
char* ac_get_printable_wtpid(struct capwap_wtpboarddata_element* wtpboarddata) {
	char* wtpid = NULL;
	struct capwap_wtpboarddata_board_subelement* wtpboarddatamacaddress;

	ASSERT(wtpboarddata != NULL);

	/* TODO: build printable wtpid depending on the model device */

	/* Get macaddress */
	wtpboarddatamacaddress = capwap_wtpboarddata_get_subelement(wtpboarddata, CAPWAP_BOARD_SUBELEMENT_MACADDRESS);
	if (wtpboarddatamacaddress != NULL) {
		wtpid = capwap_alloc(((wtpboarddatamacaddress->length == MACADDRESS_EUI48_LENGTH) ? 18 : 24));
		capwap_printf_macaddress(wtpid, (unsigned char*)wtpboarddatamacaddress->data, wtpboarddatamacaddress->length);
	}

	return wtpid;
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

			capwap_rwlock_rdlock(&g_ac.sessionslock);

			search = g_ac.sessions->first;
			while (search != NULL) {
				struct ac_session_t* session = (struct ac_session_t*)search->item;
				ASSERT(session != NULL);

				if (!memcmp(sessionid, &session->sessionid, sizeof(struct capwap_sessionid_element))) {
					/* Increment session count */
					capwap_lock_enter(&session->sessionlock);
					session->count++;
					capwap_lock_exit(&session->sessionlock);

					/*  */
					result = session;
					break;
				}

				search = search->next;
			}

			capwap_rwlock_exit(&g_ac.sessionslock);
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

/* Close sessions */
static void ac_close_sessions() {
	struct capwap_list_item* search;

	capwap_rwlock_rdlock(&g_ac.sessionslock);

	search = g_ac.sessions->first;
	while (search != NULL) {
		struct ac_session_t* session = (struct ac_session_t*)search->item;
		ASSERT(session != NULL);

		ac_session_send_action(session, AC_SESSION_ACTION_CLOSE, 0, NULL, 0);

		search = search->next;
	}

	capwap_rwlock_exit(&g_ac.sessionslock);
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

	session->itemlist = itemlist;
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
	capwap_lock_init(&session->sessionlock);

	session->actionsession = capwap_list_create();
	session->controlpackets = capwap_list_create();
	session->datapackets = capwap_list_create();
	session->requestfragmentpacket = capwap_list_create();
	session->responsefragmentpacket = capwap_list_create();

	session->mtu = g_ac.mtu;
	session->state = CAPWAP_IDLE_STATE;

	/* Update session list */
	capwap_rwlock_wrlock(&g_ac.sessionslock);
	capwap_itemlist_insert_after(g_ac.sessions, NULL, itemlist);
	capwap_rwlock_exit(&g_ac.sessionslock);

	/* Create thread */
	result = pthread_create(&session->threadid, NULL, ac_session_thread, (void*)session);
	if (!result) {
		struct ac_session_thread_t* sessionthread;

		/* Keeps trace of active threads */
		itemlist = capwap_itemlist_create(sizeof(struct ac_session_thread_t));
		sessionthread = (struct ac_session_thread_t*)itemlist->item;
		sessionthread->threadid = session->threadid;

		/* */
		capwap_itemlist_insert_after(g_ac.sessionsthread, NULL, itemlist);
	} else {
		capwap_logging_fatal("Unable create session thread, error code %d", result);
		capwap_exit(CAPWAP_OUT_OF_MEMORY);
	}

	return session;
}

/* Release reference of session */
void ac_session_release_reference(struct ac_session_t* session) {
	ASSERT(session != NULL);

	capwap_lock_enter(&session->sessionlock);

	/* Release reference must not destroy device, reference count > 0 */
	session->count--;
	ASSERT(session->count > 0);

	capwap_lock_exit(&session->sessionlock);
}

/* Update statistics */
void ac_update_statistics(void) {
	
	g_ac.descriptor.stations = 0; /* TODO */
	
	capwap_rwlock_rdlock(&g_ac.sessionslock);
	g_ac.descriptor.activewtp = g_ac.sessions->count;
	capwap_rwlock_exit(&g_ac.sessionslock);
}

/* Handler signal */
static void ac_signal_handler(int signum) {
	if ((signum == SIGINT) || (signum == SIGTERM)) {
		g_ac.running = 0;
	}
}

/* AC running */
int ac_execute(void) {
	struct pollfd* fds;
	int result = CAPWAP_SUCCESSFUL;
	int fdscount = CAPWAP_MAX_SOCKETS * 2 + 1;

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

	/* Retrive all socket for polling */
	fdscount = capwap_network_set_pollfd(&g_ac.net, fds, fdscount);
	ASSERT(fdscount > 0);

	/* Unix socket message queue */
	fds[fdscount].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
	fds[fdscount].fd = g_ac.fdmsgsessions[1];
	fdscount++;

	/* Handler signal */
	g_ac.running = 1;
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, ac_signal_handler);
	signal(SIGTERM, ac_signal_handler);

	/* Start discovery thread */
	if (!ac_discovery_start()) {
		capwap_free(fds);
		capwap_logging_debug("Unable to start discovery thread");
		return AC_ERROR_SYSTEM_FAILER;
	}

	/* Enable Backend Management */
	if (!ac_backend_start()) {
		capwap_free(fds);
		ac_discovery_stop();
		capwap_logging_error("Unable start backend management");
		return AC_ERROR_SYSTEM_FAILER;
	}

	/* */
	while (g_ac.running) {
		/* Receive packet */
		isrecvpacket = 0;
		buffersize = sizeof(buffer);
		index = ac_recvfrom(fds, fdscount, buffer, &buffersize, &recvfromaddr, &recvtoaddr, NULL);
		if (!g_ac.running) {
			capwap_logging_debug("Closing AC");
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
					capwap_rwlock_rdlock(&g_ac.sessionslock);
					sessioncount = g_ac.sessions->count;
					capwap_rwlock_exit(&g_ac.sessionslock);

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
									if (ac_backend_isconnect() && (sessioncount < g_ac.descriptor.maxwtp)) {
										ac_discovery_add_packet(buffer, buffersize, fds[index].fd, &recvfromaddr);
									}
								} else if (!g_ac.enabledtls && (type == CAPWAP_JOIN_REQUEST)) {
									if (ac_backend_isconnect() && (sessioncount < g_ac.descriptor.maxwtp)) {
										/* Retrive socket info */
										capwap_get_network_socket(&g_ac.net, &ctrlsock, fds[index].fd);

										/* Create a new session */
										session = ac_create_session(&recvfromaddr, &recvtoaddr, &ctrlsock);
										ac_session_add_packet(session, buffer, buffersize, isctrlsocket, 1);

										/* Release reference */
										ac_session_release_reference(session);
									}
								}
							}
						}
					} else if (check == CAPWAP_DTLS_PACKET) {
						/* Before create new session check if receive DTLS Client Hello */
						if (capwap_sanity_check_dtls_clienthello(&((char*)buffer)[sizeof(struct capwap_dtls_header)], buffersize - sizeof(struct capwap_dtls_header))) {
							/* Need create a new session for check if it is a valid DTLS handshake */
							if (ac_backend_isconnect() && (sessioncount < g_ac.descriptor.maxwtp)) {
								/* TODO prevent dos attack add filtering ip for multiple error */

								/* Retrive socket info */
								capwap_get_network_socket(&g_ac.net, &ctrlsock, fds[index].fd);

								/* Create a new session */
								session = ac_create_session(&recvfromaddr, &recvtoaddr, &ctrlsock);
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
		} else if ((index == CAPWAP_RECV_ERROR_INTR) || (index == AC_RECV_NOERROR_MSGQUEUE)) {
			/* Ignore recv */
			continue;
		} else if (index == CAPWAP_RECV_ERROR_SOCKET) {
			/* Socket close */
			break;
		}
	}
	
	/* Disable Backend Management */
	ac_backend_stop();

	/* Terminate discovery thread */
	ac_discovery_stop();

	/* Close all sessions */
	ac_close_sessions();

	/* Wait to terminate all sessions */
	ac_wait_terminate_allsessions();

	/* Free handshake session */
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
