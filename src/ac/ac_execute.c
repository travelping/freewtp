#include "ac.h"
#include "capwap_dfa.h"
#include "ac_session.h"
#include "ac_discovery.h"
#include "ac_backend.h"
#include "ac_wlans.h"

#include <signal.h>

#define MAX_MTU						9000
#define MIN_MTU						500

#define AC_RECV_NOERROR_MSGQUEUE			-1001
#define AC_RECV_NOERROR_KMODEVENT			-1002
#define AC_RECV_NOERROR_BACKENDNOCONNECT	-1003

#define AC_IFACE_MAX_INDEX					256
#define AC_IFACE_NAME						"capwap%lu"

/* */
static void ac_close_sessions(void);

/* */
static int ac_update_configuration_create_datachannelinterfaces(struct ac_if_datachannel* datachannel) {
	/* Create virtual interface */
	sprintf(datachannel->ifname, AC_IFACE_NAME, datachannel->index);
	datachannel->ifindex = ac_kmod_create_iface(datachannel->ifname, datachannel->mtu);
	if (datachannel->ifindex < 0) {
		return datachannel->ifindex;
	}

	/* TODO manage bridge */

	return 0;
}

/* */
static int ac_update_configuration_getdatachannel_params(struct json_object* jsonvalue, int* mtu, const char** bridge) {
	int result = -1;
	struct json_object* jsonmtu;

	/* */
	jsonmtu = compat_json_object_object_get(jsonvalue, "MTU");
	if (jsonmtu && (json_object_get_type(jsonmtu) == json_type_int)) {
		*mtu = json_object_get_int(jsonmtu);
		if ((*mtu >= MIN_MTU) && (*mtu <= MAX_MTU)) {
			struct json_object* jsonbridge = compat_json_object_object_get(jsonvalue, "Bridge");

			*bridge = ((jsonbridge && (json_object_get_type(jsonmtu) == json_type_string)) ? json_object_get_string(jsonbridge) : NULL);
			result = 0;
		}
	}

	return result;
}

/* */
static int ac_update_configuration_datachannelinterfaces(void* data, void* param) {
	int i;
	int mtu;
	int length;
	const char* bridge;
	struct ac_if_datachannel* iface = (struct ac_if_datachannel*)data;
	struct array_list* interfaces = (struct array_list*)param;

	/* Search interface */
	length = array_list_length(interfaces);
	for (i = 0; i < length; i++) {
		struct json_object* jsonvalue = array_list_get_idx(interfaces, i);
		if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_object)) {
			struct json_object* jsonindex = compat_json_object_object_get(jsonvalue, "Index");
			if (jsonindex && (json_object_get_type(jsonindex) == json_type_int)) {
				if (iface->index == (unsigned long)json_object_get_int(jsonindex)) {
					if (!ac_update_configuration_getdatachannel_params(jsonvalue, &mtu, &bridge)) {
						/* TODO */
					}

					/* Interface found */
					array_list_put_idx(interfaces, i, NULL);
					break;
				}
			}
		}
	}

	return ((i == length) ? HASH_DELETE_AND_CONTINUE : HASH_CONTINUE);
}

/* */
static void ac_update_configuration(struct json_object* jsonroot) {
	int i;
	int mtu;
	int length;
	const char* bridge;
	struct json_object* jsonelement;
	struct ac_if_datachannel* datachannel;

	ASSERT(jsonroot != NULL);

	/* Params
		{
			DataChannelInterfaces: [
				{
					Index: [int],
					MTU: [int],
					Bridge: [string]
				}
			]
		}
	*/

	/* DataChannelInterfaces */
	jsonelement = compat_json_object_object_get(jsonroot, "DataChannelInterfaces");
	if (jsonelement && (json_object_get_type(jsonelement) == json_type_array)) {
		struct array_list* interfaces = json_object_get_array(jsonelement);

		capwap_rwlock_wrlock(&g_ac.ifdatachannellock);

		/* Update and Remove active interfaces*/
		capwap_hash_foreach(g_ac.ifdatachannel, ac_update_configuration_datachannelinterfaces, interfaces);

		/* Add new interfaces*/
		length = array_list_length(interfaces);
		for (i = 0; i < length; i++) {
			struct json_object* jsonvalue = array_list_get_idx(interfaces, i);
			if (jsonvalue && (json_object_get_type(jsonvalue) == json_type_object)) {
				struct json_object* jsonindex = compat_json_object_object_get(jsonvalue, "Index");
				if (jsonindex && (json_object_get_type(jsonindex) == json_type_int)) {
					int index = json_object_get_int(jsonindex);
					if ((index >= 0) && (index < AC_IFACE_MAX_INDEX) && !ac_update_configuration_getdatachannel_params(jsonvalue, &mtu, &bridge)) {
						datachannel = (struct ac_if_datachannel*)capwap_alloc(sizeof(struct ac_if_datachannel));
						memset(datachannel, 0, sizeof(struct ac_if_datachannel));

						/* */
						datachannel->index = (unsigned long)index;
						datachannel->mtu = mtu;
						if (bridge && (strlen(bridge) < IFNAMSIZ)) {
							strcpy(datachannel->bridge, bridge);
						}

						/* */
						if (!ac_update_configuration_create_datachannelinterfaces(datachannel)) {
							capwap_hash_add(g_ac.ifdatachannel, (void*)datachannel);
						} else {
							capwap_free(datachannel);
						}
					}
				}
			}
		}

		capwap_rwlock_unlock(&g_ac.ifdatachannellock);
	}
}

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

		case AC_MESSAGE_QUEUE_UPDATE_CONFIGURATION: {
			ac_update_configuration(item->message_configuration.jsonroot);

			/* Free JSON */
			json_object_put(item->message_configuration.jsonroot);
			break;
		}

		case AC_MESSAGE_QUEUE_CLOSE_ALLSESSIONS: {
			ac_close_sessions();		/* Close all sessions */
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
int ac_msgqueue_notify_closethread(pthread_t threadid) {
	struct ac_session_msgqueue_item_t item;

	/* Send message */
	memset(&item, 0, sizeof(struct ac_session_msgqueue_item_t));
	item.message = AC_MESSAGE_QUEUE_CLOSE_THREAD;
	item.message_close_thread.threadid = threadid;

	send(g_ac.fdmsgsessions[0], (void*)&item, sizeof(struct ac_session_msgqueue_item_t), 0);
	return ((send(g_ac.fdmsgsessions[0], (void*)&item, sizeof(struct ac_session_msgqueue_item_t), 0) == sizeof(struct ac_session_msgqueue_item_t)) ? 0 : -1);
}

/* */
int ac_msgqueue_update_configuration(struct json_object* jsonroot) {
	struct ac_session_msgqueue_item_t item;

	ASSERT(jsonroot != NULL);

	/* Send message */
	memset(&item, 0, sizeof(struct ac_session_msgqueue_item_t));
	item.message = AC_MESSAGE_QUEUE_UPDATE_CONFIGURATION;
	item.message_configuration.jsonroot = jsonroot;

	return ((send(g_ac.fdmsgsessions[0], (void*)&item, sizeof(struct ac_session_msgqueue_item_t), 0) == sizeof(struct ac_session_msgqueue_item_t)) ? 0 : -1);
}

/* */
int ac_msgqueue_close_allsessions(void) {
	struct ac_session_msgqueue_item_t item;

	/* Send message */
	memset(&item, 0, sizeof(struct ac_session_msgqueue_item_t));
	item.message = AC_MESSAGE_QUEUE_CLOSE_ALLSESSIONS;

	return ((send(g_ac.fdmsgsessions[0], (void*)&item, sizeof(struct ac_session_msgqueue_item_t), 0) == sizeof(struct ac_session_msgqueue_item_t)) ? 0 : -1);
}

/* */
static int ac_recvfrom(struct ac_fds* fds, void* buffer, int* size, union sockaddr_capwap* fromaddr, union sockaddr_capwap* toaddr) {
	int index;

	ASSERT(fds);
	ASSERT(fds->fdspoll != NULL);
	ASSERT(fds->fdstotalcount > 0);
	ASSERT(buffer != NULL);
	ASSERT(size != NULL);
	ASSERT(*size > 0);
	ASSERT(fromaddr != NULL);

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
	} else if (!ac_backend_isconnect()) {
		return AC_RECV_NOERROR_BACKENDNOCONNECT;
	}

	/* Receive packet */
	if (capwap_recvfrom(fds->fdspoll[index].fd, buffer, size, fromaddr, toaddr)) {
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

	capwap_rwlock_unlock(&g_ac.sessionslock);
}

/* Find AC sessions */
static struct ac_session_t* ac_search_session_from_wtpaddress(union sockaddr_capwap* address) {
	struct ac_session_t* result = NULL;
	struct capwap_list_item* search;

	ASSERT(address != NULL);

	capwap_rwlock_rdlock(&g_ac.sessionslock);

	search = g_ac.sessions->first;
	while (search != NULL) {
		struct ac_session_t* session = (struct ac_session_t*)search->item;
		ASSERT(session != NULL);
		
		if (!capwap_compare_ip(address, &session->dtls.peeraddr)) {
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

	capwap_rwlock_unlock(&g_ac.sessionslock);

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
		
		if (session->wtpid && !strcmp(session->wtpid, wtpid)) {
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

	capwap_rwlock_unlock(&g_ac.sessionslock);

	return result;
}

/* Find session from wtp id */
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
			capwap_event_signal(&session->changereference);
			capwap_lock_exit(&session->sessionlock);

			/*  */
			result = session;
			break;
		}

		search = search->next;
	}

	capwap_rwlock_unlock(&g_ac.sessionslock);

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

	capwap_rwlock_unlock(&g_ac.sessionslock);

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

	capwap_rwlock_unlock(&g_ac.sessionslock);

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

/* Close sessions */
static void ac_close_sessions(void) {
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

	capwap_rwlock_unlock(&g_ac.sessionslock);
}

/* Create new session */
static struct ac_session_t* ac_create_session(int sock, union sockaddr_capwap* fromaddr, union sockaddr_capwap* toaddr) {
	int result;
	struct capwap_list_item* itemlist;
	struct ac_session_t* session;

	ASSERT(sock >= 0);
	ASSERT(fromaddr != NULL);
	ASSERT(toaddr != NULL);

	/* Create new session */
	itemlist = capwap_itemlist_create(sizeof(struct ac_session_t));
	session = (struct ac_session_t*)itemlist->item;
	memset(session, 0, sizeof(struct ac_session_t));

	session->itemlist = itemlist;
	session->running = 1;

	/* */
	capwap_crypt_setconnection(&session->dtls, sock, toaddr, fromaddr);

	/* */
	ac_wlans_init(session);

	/* */
	session->count = 2;
	capwap_event_init(&session->changereference);

	/* */
	session->timeout = capwap_timeout_init();
	session->idtimercontrol = capwap_timeout_createtimer(session->timeout);
	session->idtimerkeepalivedead = capwap_timeout_createtimer(session->timeout);

	/* Duplicate state for DFA */
	memcpy(&session->dfa, &g_ac.dfa, sizeof(struct ac_state));

	session->dfa.acipv4list.addresses = capwap_array_clone(g_ac.dfa.acipv4list.addresses);
	if (!session->dfa.acipv4list.addresses->count && (session->dtls.localaddr.ss.ss_family == AF_INET)) {
		memcpy(capwap_array_get_item_pointer(session->dfa.acipv4list.addresses, 0), &session->dtls.localaddr.sin.sin_addr, sizeof(struct in_addr));
	}

	session->dfa.acipv6list.addresses = capwap_array_clone(g_ac.dfa.acipv6list.addresses);
	if (!session->dfa.acipv6list.addresses->count && (session->dtls.localaddr.ss.ss_family == AF_INET6)) {
		memcpy(capwap_array_get_item_pointer(session->dfa.acipv6list.addresses, 0), &session->dtls.localaddr.sin6.sin6_addr, sizeof(struct in6_addr));
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
	capwap_rwlock_unlock(&g_ac.sessionslock);

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
	ASSERT(session->count > 0);
	session->count--;
	capwap_event_signal(&session->changereference);
	capwap_lock_exit(&session->sessionlock);
}

/* Update statistics */
void ac_update_statistics(void) {
	
	g_ac.descriptor.stations = 0; /* TODO */
	
	capwap_rwlock_rdlock(&g_ac.sessionslock);
	g_ac.descriptor.activewtp = g_ac.sessions->count;
	capwap_rwlock_unlock(&g_ac.sessionslock);
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
	union sockaddr_capwap fromaddr;
	union sockaddr_capwap toaddr;
	struct ac_session_t* session;

	char buffer[CAPWAP_MAX_PACKET_SIZE];
	int buffersize;

	struct ac_fds fds;

	/* Set file descriptor pool */
	if (ac_execute_init_fdspool(&fds, &g_ac.net, g_ac.fdmsgsessions[1]) <= 0) {
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
		ac_execute_free_fdspool(&fds);
		capwap_logging_debug("Unable to start discovery thread");
		return AC_ERROR_SYSTEM_FAILER;
	}

	/* Enable Backend Management */
	if (!ac_backend_start()) {
		ac_execute_free_fdspool(&fds);
		ac_discovery_stop();
		capwap_logging_error("Unable start backend management");
		return AC_ERROR_SYSTEM_FAILER;
	}

	/* */
	while (g_ac.running) {
		/* Receive packet */
		buffersize = sizeof(buffer);
		index = ac_recvfrom(&fds, buffer, &buffersize, &fromaddr, &toaddr);
		if (!g_ac.running) {
			capwap_logging_debug("Closing AC");
			break;
		}
		
		/* */
		if (index >= 0) {
			/* Search the AC session */
			session = ac_search_session_from_wtpaddress(&fromaddr);
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
				capwap_rwlock_unlock(&g_ac.sessionslock);

				/* */
				if (ac_backend_isconnect() && (sessioncount < g_ac.descriptor.maxwtp)) {
					check = capwap_sanity_check(CAPWAP_UNDEF_STATE, buffer, buffersize, g_ac.enabledtls);
					if (check == CAPWAP_PLAIN_PACKET) {
						struct capwap_header* header = (struct capwap_header*)buffer;

						/* Accepted only packet without fragmentation */
						if (!IS_FLAG_F_HEADER(header)) {
							int headersize = GET_HLEN_HEADER(header) * 4;
							if (buffersize >= (headersize + sizeof(struct capwap_control_message))) {
								struct capwap_control_message* control = (struct capwap_control_message*)((char*)buffer + headersize);
								unsigned long type = ntohl(control->type);

								if (type == CAPWAP_DISCOVERY_REQUEST) {
									ac_discovery_add_packet(buffer, buffersize, fds.fdspoll[index].fd, &fromaddr);
								} else if (!g_ac.enabledtls && (type == CAPWAP_JOIN_REQUEST)) {
									/* Create a new session */
									session = ac_create_session(fds.fdspoll[index].fd, &fromaddr, &toaddr);
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
							session = ac_create_session(fds.fdspoll[index].fd, &fromaddr, &toaddr);
							ac_session_add_packet(session, buffer, buffersize, 0);

							/* Release reference */
							ac_session_release_reference(session);
						}
					}
				}
			} 
		} else if (index == CAPWAP_RECV_ERROR_SOCKET) {
			break;		/* Socket close */
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

	/* Close data channel interfaces */
	capwap_hash_deleteall(g_ac.ifdatachannel);

	/* Free Backend Management */
	ac_backend_free();

	/* Free file description pool */
	ac_execute_free_fdspool(&fds);
	return result;
}
