#include "ac.h"
#include "capwap_dfa.h"
#include "ac_session.h"
#include "ac_discovery.h"
#include "ac_backend.h"
#include "ac_wlans.h"

#include <signal.h>

#define AC_RECV_NOERROR_MSGQUEUE			-1001
#define AC_RECV_NOERROR_KMODEVENT			-1002

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

	capwap_logging_debug("Close all sessions");
}

/* Initialize message queue */
int ac_msgqueue_init(void) {
	if (socketpair(AF_LOCAL, SOCK_DGRAM, 0, g_ac.fdmsgsessions)) {
		return 0;
	}

	return 1;
}

/* Free sessions message queue */
void ac_msgqueue_free(void) {
	close(g_ac.fdmsgsessions[1]);
	close(g_ac.fdmsgsessions[0]);
}

/* */
void ac_msgqueue_notify_closethread(pthread_t threadid) {
	struct ac_session_msgqueue_item_t item;

	/* Send message */
	memset(&item, 0, sizeof(struct ac_session_msgqueue_item_t));
	item.message = AC_MESSAGE_QUEUE_CLOSE_THREAD;
	item.message_close_thread.threadid = threadid;

	send(g_ac.fdmsgsessions[0], (void*)&item, sizeof(struct ac_session_msgqueue_item_t), 0);
}

/* */
static int ac_recvfrom(struct ac_fds* fds, void* buffer, int* size, struct sockaddr_storage* recvfromaddr, struct sockaddr_storage* recvtoaddr) {
	int index;

	ASSERT(fds);
	ASSERT(fds->fdspoll != NULL);
	ASSERT(fds->fdstotalcount > 0);
	ASSERT(buffer != NULL);
	ASSERT(size != NULL);
	ASSERT(*size > 0);
	ASSERT(recvfromaddr != NULL);
	ASSERT(recvtoaddr != NULL);

	/* Wait packet */
	index = capwap_wait_recvready(fds->fdspoll, fds->fdstotalcount, NULL);
	if (index < 0) {
		return index;
	} else if ((fds->kmodeventsstartpos >= 0) && (index >= fds->kmodeventsstartpos)) {
		int pos = index - fds->kmodeventsstartpos;

		if (pos < fds->kmodeventscount) {
			if (!fds->kmodevents[pos].event_handler) {
				return CAPWAP_RECV_ERROR_SOCKET;
			}

			fds->kmodevents[pos].event_handler(fds->fdspoll[index].fd, fds->kmodevents[pos].params, fds->kmodevents[pos].paramscount);
		}

		return AC_RECV_NOERROR_KMODEVENT;
	} else if ((fds->msgqueuestartpos >= 0) && (index >= fds->msgqueuestartpos)) {
		struct ac_session_msgqueue_item_t item;

		/* Receive message queue packet */
		if (!ac_recvmsgqueue(fds->fdspoll[index].fd, &item)) {
			return CAPWAP_RECV_ERROR_SOCKET;
		}

		/* Parsing message queue packet */
		ac_session_msgqueue_parsing_item(&item);
		return AC_RECV_NOERROR_MSGQUEUE;
	}

	/* Receive packet */
	if (!capwap_recvfrom_fd(fds->fdspoll[index].fd, buffer, size, recvfromaddr, recvtoaddr)) {
		return CAPWAP_RECV_ERROR_SOCKET;
	}

	return index;
}

/* Add packet to session */
static void ac_session_add_packet(struct ac_session_t* session, char* buffer, int size, int plainbuffer) {
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
	capwap_itemlist_insert_after(session->packets, NULL, item);
	capwap_event_signal(&session->waitpacket);
	capwap_lock_exit(&session->sessionlock);
}

/* Add packet to session data */
static void ac_session_data_add_packet(struct ac_session_data_t* sessiondata, char* buffer, int size, int plainbuffer) {
	struct capwap_list_item* item;
	struct ac_packet* packet;

	ASSERT(sessiondata != NULL);
	ASSERT(buffer != NULL);
	ASSERT(size > 0);

	/* Copy packet */
	item = capwap_itemlist_create(sizeof(struct ac_packet) + size);
	packet = (struct ac_packet*)item->item;
	packet->plainbuffer = plainbuffer;
	memcpy(packet->buffer, buffer, size);

	/* Append to packets list */
	capwap_lock_enter(&sessiondata->sessionlock);
	capwap_itemlist_insert_after(sessiondata->packets, NULL, item);
	capwap_event_signal(&sessiondata->waitpacket);
	capwap_lock_exit(&sessiondata->sessionlock);
}

/* Add action to session */
void ac_session_send_action(struct ac_session_t* session, long action, long param, const void* data, long length) {
	struct capwap_list_item* item;
	struct ac_session_action* actionsession;
	struct capwap_list_item* search;

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

	/* Validate session before use */
	capwap_rwlock_rdlock(&g_ac.sessionslock);

	search = g_ac.sessions->first;
	while (search != NULL) {
		if (session == (struct ac_session_t*)search->item) {
			/* Append to actions list */
			capwap_lock_enter(&session->sessionlock);
			capwap_itemlist_insert_after(session->action, NULL, item);
			capwap_event_signal(&session->waitpacket);
			capwap_lock_exit(&session->sessionlock);

			break;
		}

		/* */
		search = search->next;
	}

	capwap_rwlock_exit(&g_ac.sessionslock);
}

/* Add action to session data */
void ac_session_data_send_action(struct ac_session_data_t* sessiondata, long action, long param, void* data, long length) {
	struct capwap_list_item* item;
	struct ac_session_action* actionsession;
	struct capwap_list_item* search;

	ASSERT(sessiondata != NULL);
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

	/* Validate session data before use */
	capwap_rwlock_rdlock(&g_ac.sessionslock);

	search = g_ac.sessionsdata->first;
	while (search != NULL) {
		struct ac_session_data_t* sessiondata = (struct ac_session_data_t*)search->item;
		
		if (sessiondata == (struct ac_session_data_t*)search->item) {
			/* Append to actions list */
			capwap_lock_enter(&sessiondata->sessionlock);
			capwap_itemlist_insert_after(sessiondata->action, NULL, item);
			capwap_event_signal(&sessiondata->waitpacket);
			capwap_lock_exit(&sessiondata->sessionlock);

			break;
		}

		/* */
		search = search->next;
	}

	capwap_rwlock_exit(&g_ac.sessionslock);
}

/* Find AC sessions */
static struct ac_session_t* ac_search_session_from_wtpaddress(struct sockaddr_storage* address) {
	struct ac_session_t* result = NULL;
	struct capwap_list_item* search;

	ASSERT(address != NULL);

	capwap_rwlock_rdlock(&g_ac.sessionslock);

	search = g_ac.sessions->first;
	while (search != NULL) {
		struct ac_session_t* session = (struct ac_session_t*)search->item;
		ASSERT(session != NULL);
		
		if (!capwap_compare_ip(address, &session->connection.remoteaddr)) {
			/* Increment session count */
			capwap_lock_enter(&session->sessionlock);
			session->count++;
			capwap_event_signal(&session->changereference);
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

/* Find AC sessions data */
static struct ac_session_data_t* ac_search_session_data_from_wtpaddress(struct sockaddr_storage* address) {
	struct ac_session_data_t* result = NULL;
	struct capwap_list_item* search;

	ASSERT(address != NULL);

	capwap_rwlock_rdlock(&g_ac.sessionslock);

	search = g_ac.sessionsdata->first;
	while (search != NULL) {
		struct ac_session_data_t* sessiondata = (struct ac_session_data_t*)search->item;
		ASSERT(sessiondata != NULL);
		
		if (!capwap_compare_ip(address, &sessiondata->connection.remoteaddr)) {
			/* Increment session data count */
			capwap_lock_enter(&sessiondata->sessionlock);
			sessiondata->count++;
			capwap_event_signal(&sessiondata->changereference);
			capwap_lock_exit(&sessiondata->sessionlock);

			/*  */
			result = sessiondata;
			break;
		}

		search = search->next;
	}

	capwap_rwlock_exit(&g_ac.sessionslock);

	return result;
}

/* Find session from wtp id */
struct ac_session_t* ac_search_session_from_wtpid(const char* wtpid) {
	struct ac_session_t* result = NULL;
	struct capwap_list_item* search;

	ASSERT(wtpid != NULL);

	capwap_rwlock_rdlock(&g_ac.sessionslock);

	search = g_ac.sessions->first;
	while (search != NULL) {
		struct ac_session_t* session = (struct ac_session_t*)search->item;
		ASSERT(session != NULL);
		
		if (!strcmp(session->wtpid, wtpid)) {
			/* Increment session count */
			capwap_lock_enter(&session->sessionlock);
			session->count++;
			capwap_event_signal(&session->changereference);
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
int ac_has_wtpid(const char* wtpid) {
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
		wtpid = capwap_alloc(((wtpboarddatamacaddress->length == MACADDRESS_EUI48_LENGTH) ? CAPWAP_MACADDRESS_EUI48_BUFFER : CAPWAP_MACADDRESS_EUI64_BUFFER));
		capwap_printf_macaddress(wtpid, (unsigned char*)wtpboarddatamacaddress->data, wtpboarddatamacaddress->length);
	}

	return wtpid;
}

/* */
void ac_session_close(struct ac_session_t* session) {
	capwap_lock_enter(&session->sessionlock);
	session->running = 0;
	capwap_event_signal(&session->waitpacket);
	capwap_lock_exit(&session->sessionlock);
}

/* */
void ac_session_data_close(struct ac_session_data_t* sessiondata) {
	capwap_lock_enter(&sessiondata->sessionlock);
	sessiondata->running = 0;
	capwap_event_signal(&sessiondata->waitpacket);
	capwap_lock_exit(&sessiondata->sessionlock);
}

/* Close sessions */
static void ac_close_sessions() {
	struct capwap_list_item* search;

	capwap_rwlock_rdlock(&g_ac.sessionslock);

	/* Session */
	search = g_ac.sessions->first;
	while (search != NULL) {
		struct ac_session_t* session = (struct ac_session_t*)search->item;
		ASSERT(session != NULL);

		ac_session_close(session);

		search = search->next;
	}

	/* Session data */
	search = g_ac.sessionsdata->first;
	while (search != NULL) {
		struct ac_session_data_t* sessiondata = (struct ac_session_data_t*)search->item;
		ASSERT(sessiondata != NULL);

		ac_session_data_close(sessiondata);

		search = search->next;
	}

	capwap_rwlock_exit(&g_ac.sessionslock);
}

/* Detect data channel */
static int ac_is_plain_datachannel(void* buffer, int buffersize) {
	struct capwap_preamble* preamble = (struct capwap_preamble*)buffer;

	ASSERT(buffer != NULL);
	ASSERT(buffersize > sizeof(struct capwap_preamble));

	if ((preamble->type == CAPWAP_PREAMBLE_HEADER) && ((g_ac.descriptor.dtlspolicy & CAPWAP_ACDESC_CLEAR_DATA_CHANNEL_ENABLED) != 0)) {
		return 1;
	} else if ((preamble->type == CAPWAP_PREAMBLE_DTLS_HEADER) && ((g_ac.descriptor.dtlspolicy & CAPWAP_ACDESC_DTLS_DATA_CHANNEL_ENABLED) != 0)) {
		return 0;
	}

	return -1;
}

/* Create new session */
static struct ac_session_t* ac_create_session(struct sockaddr_storage* wtpaddress, struct sockaddr_storage* acaddress, struct capwap_socket* sock) {
	int result;
	struct capwap_list_item* itemlist;
	struct ac_session_t* session;

	ASSERT(acaddress != NULL);
	ASSERT(wtpaddress != NULL);
	ASSERT(sock != NULL);

	/* Create new session */
	itemlist = capwap_itemlist_create(sizeof(struct ac_session_t));
	session = (struct ac_session_t*)itemlist->item;
	memset(session, 0, sizeof(struct ac_session_t));

	session->itemlist = itemlist;
	session->running = 1;

	memcpy(&session->connection.socket, sock, sizeof(struct capwap_socket));
	memcpy(&session->connection.localaddr, acaddress, sizeof(struct sockaddr_storage));
	memcpy(&session->connection.remoteaddr, wtpaddress, sizeof(struct sockaddr_storage));

	/* */
	ac_wlans_init(session);

	/* */
	session->count = 2;
	capwap_event_init(&session->changereference);

	/* */
	session->timeout = capwap_timeout_init();
	session->idtimercontrol = capwap_timeout_createtimer(session->timeout);

	/* Duplicate state for DFA */
	memcpy(&session->dfa, &g_ac.dfa, sizeof(struct ac_state));
	session->dfa.acipv4list.addresses = capwap_array_clone(g_ac.dfa.acipv4list.addresses);
	session->dfa.acipv6list.addresses = capwap_array_clone(g_ac.dfa.acipv6list.addresses);

	/* Add default AC list if empty*/
	if ((session->dfa.acipv4list.addresses->count == 0) && (session->dfa.acipv6list.addresses->count == 0)) {
		if (acaddress->ss_family == AF_INET) {
			struct in_addr* acip = (struct in_addr*)capwap_array_get_item_pointer(session->dfa.acipv4list.addresses, 0);
			memcpy(acip, &((struct sockaddr_in*)acaddress)->sin_addr, sizeof(struct in_addr));
		} else if (acaddress->ss_family == AF_INET6) {
			struct in6_addr* acip = (struct in6_addr*)capwap_array_get_item_pointer(session->dfa.acipv6list.addresses, 0);
			memcpy(acip, &((struct sockaddr_in6*)acaddress)->sin6_addr, sizeof(struct in6_addr));
		}
	}

	/* Init */
	capwap_event_init(&session->waitpacket);
	capwap_lock_init(&session->sessionlock);

	session->action = capwap_list_create();
	session->packets = capwap_list_create();
	session->requestfragmentpacket = capwap_list_create();
	session->responsefragmentpacket = capwap_list_create();
	session->notifyevent = capwap_list_create();

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

/* Create new session data */
static struct ac_session_data_t* ac_create_session_data(struct sockaddr_storage* wtpaddress, struct sockaddr_storage* acaddress, struct capwap_socket* sock, int plain) {
	int result;
	struct capwap_list_item* itemlist;
	struct ac_session_data_t* sessiondata;

	ASSERT(acaddress != NULL);
	ASSERT(wtpaddress != NULL);
	ASSERT(sock != NULL);

	/* Create new session data */
	itemlist = capwap_itemlist_create(sizeof(struct ac_session_data_t));
	sessiondata = (struct ac_session_data_t*)itemlist->item;
	memset(sessiondata, 0, sizeof(struct ac_session_data_t));

	/* */
	sessiondata->itemlist = itemlist;
	sessiondata->running = 1;
	sessiondata->enabledtls = (plain ? 0 : 1);

	/* */
	sessiondata->count = 2;
	capwap_event_init(&sessiondata->changereference);

	/* */
	sessiondata->timeout = capwap_timeout_init();
	sessiondata->idtimercontrol = capwap_timeout_createtimer(sessiondata->timeout);
	sessiondata->idtimerkeepalivedead = capwap_timeout_createtimer(sessiondata->timeout);

	/* Connection info */
	memcpy(&sessiondata->connection.socket, sock, sizeof(struct capwap_socket));
	memcpy(&sessiondata->connection.localaddr, acaddress, sizeof(struct sockaddr_storage));
	memcpy(&sessiondata->connection.remoteaddr, wtpaddress, sizeof(struct sockaddr_storage));
	sessiondata->mtu = g_ac.mtu;

	/* Init */
	capwap_event_init(&sessiondata->waitpacket);
	capwap_lock_init(&sessiondata->sessionlock);

	sessiondata->action = capwap_list_create();
	sessiondata->packets = capwap_list_create();

	/* Update session data list */
	capwap_rwlock_wrlock(&g_ac.sessionslock);
	capwap_itemlist_insert_after(g_ac.sessionsdata, NULL, itemlist);
	capwap_rwlock_exit(&g_ac.sessionslock);

	/* Create thread */
	result = pthread_create(&sessiondata->threadid, NULL, ac_session_data_thread, (void*)sessiondata);
	if (!result) {
		struct ac_session_thread_t* sessionthread;

		/* Keeps trace of active threads */
		itemlist = capwap_itemlist_create(sizeof(struct ac_session_thread_t));
		sessionthread = (struct ac_session_thread_t*)itemlist->item;
		sessionthread->threadid = sessiondata->threadid;

		/* */
		capwap_itemlist_insert_after(g_ac.sessionsthread, NULL, itemlist);
	} else {
		capwap_logging_fatal("Unable create session data thread, error code %d", result);
		capwap_exit(CAPWAP_OUT_OF_MEMORY);
	}

	return sessiondata;
}

/* Release reference of session */
void ac_session_release_reference(struct ac_session_t* session) {
	ASSERT(session != NULL);

	capwap_lock_enter(&session->sessionlock);
	ASSERT(session->count > 0);
	session->count--;
	capwap_event_signal(&session->changereference);
	capwap_lock_exit(&session->sessionlock);
}

/* Release reference of session data */
void ac_session_data_release_reference(struct ac_session_data_t* sessiondata) {
	ASSERT(sessiondata != NULL);

	capwap_lock_enter(&sessiondata->sessionlock);
	ASSERT(sessiondata->count > 0);
	sessiondata->count--;
	capwap_event_signal(&sessiondata->changereference);
	capwap_lock_exit(&sessiondata->sessionlock);
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

/* */
static int ac_execute_init_fdspool(struct ac_fds* fds, struct capwap_network* net, int fdmsgqueue) {
	ASSERT(fds != NULL);
	ASSERT(net != NULL);
	ASSERT(fdmsgqueue > 0);

	/* */
	memset(fds, 0, sizeof(struct ac_fds));
	fds->fdsnetworkcount = capwap_network_set_pollfd(net, NULL, 0);
	fds->msgqueuecount = 1;
	fds->fdspoll = (struct pollfd*)capwap_alloc(sizeof(struct pollfd) * (fds->fdsnetworkcount + fds->msgqueuecount));

	/* Retrive all socket for polling */
	fds->fdstotalcount = capwap_network_set_pollfd(net, fds->fdspoll, fds->fdsnetworkcount);
	if (fds->fdsnetworkcount != fds->fdstotalcount) {
		capwap_free(fds->fdspoll);
		return -1;
	}

	/* Unix socket message queue */
	fds->msgqueuestartpos = fds->fdsnetworkcount;
	fds->fdspoll[fds->msgqueuestartpos].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
	fds->fdspoll[fds->msgqueuestartpos].fd = fdmsgqueue;
	fds->fdstotalcount += fds->msgqueuecount;

	return ac_execute_update_fdspool(fds);
}

/* */
static void ac_execute_free_fdspool(struct ac_fds* fds) {
	ASSERT(fds != NULL);

	if (fds->fdspoll) {
		capwap_free(fds->fdspoll);
	}

	if (fds->kmodevents) {
		capwap_free(fds->kmodevents);
	}
}

/* */
int ac_execute_update_fdspool(struct ac_fds* fds) {
	int totalcount;
	int kmodcount;
	struct pollfd* fdsbuffer;

	ASSERT(fds != NULL);

	/* Retrieve number of Dynamic File Descriptor Event */
	kmodcount = ac_kmod_getfd(NULL, NULL, 0);
	if (kmodcount < 0) {
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
		fds->kmodevents = (struct ac_kmod_event*)((kmodcount > 0) ? capwap_alloc(sizeof(struct ac_kmod_event) * kmodcount) : NULL);
	}

	/* Resize poll */
	totalcount = fds->fdsnetworkcount + fds->msgqueuecount + fds->kmodeventscount;
	if (fds->fdstotalcount != totalcount) {
		fdsbuffer = (struct pollfd*)capwap_alloc(sizeof(struct pollfd) * totalcount);
		if (fds->fdspoll) {
			int count = fds->fdsnetworkcount + fds->msgqueuecount;
			if (count > 0) {
				memcpy(fdsbuffer, fds->fdspoll, sizeof(struct pollfd) * count);
			}

			capwap_free(fds->fdspoll);
		}

		/* */
		fds->fdspoll = fdsbuffer;
		fds->fdstotalcount = totalcount;
	}

	/* Retrieve File Descriptor Kernel Module Event */
	if (fds->kmodeventscount > 0) {
		fds->kmodeventsstartpos = fds->fdsnetworkcount + fds->msgqueuecount;
		ac_kmod_getfd(&fds->fdspoll[fds->kmodeventsstartpos], fds->kmodevents, fds->kmodeventscount);
	}

	return fds->fdstotalcount;
}

/* AC running */
int ac_execute(void) {
	int result = CAPWAP_SUCCESSFUL;

	int index;
	int check;
	struct capwap_socket socket;
	struct sockaddr_storage recvfromaddr;
	struct sockaddr_storage recvtoaddr;

	char buffer[CAPWAP_MAX_PACKET_SIZE];
	int buffersize;

	/* Set file descriptor pool */
	if (ac_execute_init_fdspool(&g_ac.fds, &g_ac.net, g_ac.fdmsgsessions[1]) <= 0) {
		capwap_logging_debug("Unable to initialize file descriptor pool");
		return AC_ERROR_SYSTEM_FAILER;
	}

	/* Handler signal */
	g_ac.running = 1;
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, ac_signal_handler);
	signal(SIGTERM, ac_signal_handler);

	/* Start discovery thread */
	if (!ac_discovery_start()) {
		ac_execute_free_fdspool(&g_ac.fds);
		capwap_logging_debug("Unable to start discovery thread");
		return AC_ERROR_SYSTEM_FAILER;
	}

	/* Enable Backend Management */
	if (!ac_backend_start()) {
		ac_execute_free_fdspool(&g_ac.fds);
		ac_discovery_stop();
		capwap_logging_error("Unable start backend management");
		return AC_ERROR_SYSTEM_FAILER;
	}

	/* */
	while (g_ac.running) {
		/* Receive packet */
		buffersize = sizeof(buffer);
		index = ac_recvfrom(&g_ac.fds, buffer, &buffersize, &recvfromaddr, &recvtoaddr);
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
					if (getsockname(g_ac.fds.fdspoll[index].fd, (struct sockaddr*)&sockinfo, &sockinfolen) < 0) {
						break; 
					}

					CAPWAP_SET_NETWORK_PORT(&recvtoaddr, CAPWAP_GET_NETWORK_PORT(&sockinfo));
				}
			}

			/* Retrieve network information */
			capwap_get_network_socket(&g_ac.net, &socket, g_ac.fds.fdspoll[index].fd);

			/* Search the AC session / session data */
			if (socket.isctrlsocket) {
				struct ac_session_t* session = ac_search_session_from_wtpaddress(&recvfromaddr);

				if (session) {
					/* Add packet*/
					ac_session_add_packet(session, buffer, buffersize, 0);

					/* Release reference */
					ac_session_release_reference(session);
				} else {
					unsigned short sessioncount;

					/* TODO prevent dos attack add filtering ip for multiple error */

					/* Get current session number */
					capwap_rwlock_rdlock(&g_ac.sessionslock);
					sessioncount = g_ac.sessions->count;
					capwap_rwlock_exit(&g_ac.sessionslock);

					/* */
					if (ac_backend_isconnect() && (sessioncount < g_ac.descriptor.maxwtp)) {
						check = capwap_sanity_check(1, CAPWAP_UNDEF_STATE, buffer, buffersize, g_ac.enabledtls, 0);
						if (check == CAPWAP_PLAIN_PACKET) {
							struct capwap_header* header = (struct capwap_header*)buffer;

							/* Accepted only packet without fragmentation */
							if (!IS_FLAG_F_HEADER(header)) {
								int headersize = GET_HLEN_HEADER(header) * 4;
								if (buffersize >= (headersize + sizeof(struct capwap_control_message))) {
									struct capwap_control_message* control = (struct capwap_control_message*)((char*)buffer + headersize);
									unsigned long type = ntohl(control->type);

									if (type == CAPWAP_DISCOVERY_REQUEST) {
										ac_discovery_add_packet(buffer, buffersize, g_ac.fds.fdspoll[index].fd, &recvfromaddr);
									} else if (!g_ac.enabledtls && (type == CAPWAP_JOIN_REQUEST)) {
										/* Create a new session */
										session = ac_create_session(&recvfromaddr, &recvtoaddr, &socket);
										ac_session_add_packet(session, buffer, buffersize, 1);

										/* Release reference */
										ac_session_release_reference(session);
									}
								}
							}
						} else if (check == CAPWAP_DTLS_PACKET) {
							/* Before create new session check if receive DTLS Client Hello */
							if (capwap_crypt_has_dtls_clienthello(&((char*)buffer)[sizeof(struct capwap_dtls_header)], buffersize - sizeof(struct capwap_dtls_header))) {
								/* Create a new session */
								session = ac_create_session(&recvfromaddr, &recvtoaddr, &socket);
								ac_session_add_packet(session, buffer, buffersize, 0);

								/* Release reference */
								ac_session_release_reference(session);
							}
						}
					}
				} 
			} else {
				struct ac_session_data_t* sessiondata = ac_search_session_data_from_wtpaddress(&recvfromaddr);

				if (sessiondata) {
					/* Add packet*/
					ac_session_data_add_packet(sessiondata, buffer, buffersize, 0);

					/* Release reference */
					ac_session_data_release_reference(sessiondata);
				} else {
					int plain;

					/* TODO prevent dos attack add filtering ip for multiple error */

					/* Detect type data channel */
					plain = ac_is_plain_datachannel(buffer, buffersize);

					/* Before create new session check if receive DTLS Client Hello */
					if (!plain) {
						if (buffersize <= sizeof(struct capwap_dtls_header)) {
							plain = -1;
						} else if (!capwap_crypt_has_dtls_clienthello(&((char*)buffer)[sizeof(struct capwap_dtls_header)], buffersize - sizeof(struct capwap_dtls_header))) {
							plain = -1;
						}
					}

					/* */
					if (plain >= 0) {
						/* Create a new session */
						sessiondata = ac_create_session_data(&recvfromaddr, &recvtoaddr, &socket, plain);
						ac_session_data_add_packet(sessiondata, buffer, buffersize, 0);

						/* Release reference */
						ac_session_data_release_reference(sessiondata);
					}
				}
			}
		} else if ((index == CAPWAP_RECV_ERROR_INTR) || (index == AC_RECV_NOERROR_MSGQUEUE) || (index == AC_RECV_NOERROR_KMODEVENT)) {
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

	/* Free Backend Management */
	ac_backend_free();

	/* Free file description pool */
	ac_execute_free_fdspool(&g_ac.fds);
	return result;
}
