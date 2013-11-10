#include <stdarg.h>
#include "ac.h"
#include "capwap_dfa.h"
#include "ac_session.h"
#include "ac_backend.h"

#define PACKET_TIMEOUT			-1
#define DTLS_SHUTDOWN			-2
#define ACTION_SESSION			-3

/* */
static int ac_session_action_execute(struct ac_session_t* session, struct ac_session_action* action) {
	int result = ACTION_SESSION;

	switch (action->action) {
		case AC_SESSION_ACTION_RESET_WTP: {
			struct ac_notify_reset_t* reset = (struct ac_notify_reset_t*)action->data;

			/* Send reset command */
			ac_session_reset(session, &reset->startupimage);

			/* Free resource */
			if (reset->startupimage.name) {
				capwap_free(reset->startupimage.name);
			}

			break;
		}
	}

	return result;
}

/* */
static int ac_network_read(struct ac_session_t* session, void* buffer, int length, int* isctrlpacket, struct timeout_control* timeout) {
	int result = 0;
	long indextimer;
	long waittimeout;
	
	ASSERT(session != NULL);
	ASSERT(buffer != NULL);
	ASSERT(length > 0);
	ASSERT(isctrlpacket != NULL);

	for (;;) {
		capwap_lock_enter(&session->sessionlock);

		if (!session->running) {
			capwap_lock_exit(&session->sessionlock);
			return DTLS_SHUTDOWN;
		} else if (!session->waitresponse && (session->actionsession->count > 0)) {
			struct capwap_list_item* itemaction;

			itemaction = capwap_itemlist_remove_head(session->actionsession);
			capwap_lock_exit(&session->sessionlock);

			/* */
			result = ac_session_action_execute(session, (struct ac_session_action*)itemaction->item);

			/* Free packet */
			capwap_itemlist_free(itemaction);
			return result;
		} else if ((session->controlpackets->count > 0) || (session->datapackets->count > 0)) {
			struct capwap_list_item* itempacket;

			*isctrlpacket = ((session->controlpackets->count > 0) ? 1 : 0);
			if (*isctrlpacket) {
				capwap_logging_debug("Receive control packet");
			} else {
				capwap_logging_debug("Receive data packet");
			}

			/* Get packet */
			itempacket = capwap_itemlist_remove_head((*isctrlpacket ? session->controlpackets : session->datapackets));
			capwap_lock_exit(&session->sessionlock);

			if (itempacket) {
				struct ac_packet* packet = (struct ac_packet*)itempacket->item;
				long packetlength = itempacket->itemsize - sizeof(struct ac_packet);
				struct capwap_dtls* dtls = (*isctrlpacket ? &session->ctrldtls : &session->datadtls);
				
				if (!packet->plainbuffer && dtls->enable) {
					int oldaction = dtls->action;

					/* Decrypt packet */
					result = capwap_decrypt_packet(dtls, packet->buffer, packetlength, buffer, length);
					if (result == CAPWAP_ERROR_AGAIN) {
						/* Check is handshake complete */
						if ((oldaction == CAPWAP_DTLS_ACTION_HANDSHAKE) && (dtls->action == CAPWAP_DTLS_ACTION_DATA)) {
							if (*isctrlpacket) {
								if (session->state == CAPWAP_DTLS_CONNECT_STATE) {
									ac_dfa_change_state(session, CAPWAP_JOIN_STATE);
									capwap_set_timeout(session->dfa.rfcWaitJoin, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
								}
							}
						}
					} else if (result == CAPWAP_ERROR_SHUTDOWN) {
						if ((oldaction == CAPWAP_DTLS_ACTION_DATA) && (dtls->action == CAPWAP_DTLS_ACTION_SHUTDOWN)) {
							result = DTLS_SHUTDOWN;
						}
					}
				} else {
					if (packetlength <= length) {
						memcpy(buffer, packet->buffer, packetlength);
						result = packetlength;
					}
				}

				/* Free packet */
				capwap_itemlist_free(itempacket);
			}

			return result;
		}

		capwap_lock_exit(&session->sessionlock);

		/* Update timeout */
		capwap_update_timeout(timeout);
		waittimeout = capwap_get_timeout(timeout, &indextimer);
		if ((waittimeout <= 0) && (indextimer != CAPWAP_TIMER_UNDEF)) {
			return PACKET_TIMEOUT;
		}

		/* Wait packet */
		capwap_event_wait_timeout(&session->waitpacket, waittimeout);
	}

	return 0;
}

/* */
static void ac_dfa_execute(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	ASSERT(session != NULL);

	/* Execute state */
	switch (session->state) {
		case CAPWAP_DTLS_CONNECT_STATE: {
			ac_session_teardown(session);
			break;
		}

		case CAPWAP_JOIN_STATE: {
			ac_dfa_state_join(session, packet);
			break;
		}
		
		case CAPWAP_POSTJOIN_STATE: {
			ac_dfa_state_postjoin(session, packet);
			break;
		}

		case CAPWAP_IMAGE_DATA_STATE: {
			ac_dfa_state_imagedata(session, packet);
			break;
		}

		case CAPWAP_CONFIGURE_STATE: {
			ac_dfa_state_configure(session, packet);
			break;
		}

		case CAPWAP_RESET_STATE: {
			ac_dfa_state_reset(session, packet);
			break;
		}

		case CAPWAP_DATA_CHECK_STATE: {
			ac_dfa_state_datacheck(session, packet);
			break;
		}

		case CAPWAP_DATA_CHECK_TO_RUN_STATE: {
			ac_dfa_state_datacheck_to_run(session, packet);
			break;
		}

		case CAPWAP_RUN_STATE: {
			ac_dfa_state_run(session, packet);
			break;
		}

		default: {
			capwap_logging_debug("Unknown action event: %lu", session->state);
			break;
		}
	}
}

/* */
static struct capwap_packet_rxmng* ac_get_packet_rxmng(struct ac_session_t* session, int isctrlmsg) {
	struct capwap_packet_rxmng* rxmngpacket = NULL;

	if (isctrlmsg) {
		if (!session->rxmngctrlpacket) {
			session->rxmngctrlpacket = capwap_packet_rxmng_create_message(1);
		}

		rxmngpacket = session->rxmngctrlpacket;
	} else {
		if (!session->rxmngdatapacket) {
			session->rxmngdatapacket = capwap_packet_rxmng_create_message(0);
		}

		rxmngpacket = session->rxmngdatapacket;
	}

	return rxmngpacket;
}

/* */
static void ac_free_packet_rxmng(struct ac_session_t* session, int isctrlmsg) {
	if (isctrlmsg && session->rxmngctrlpacket) {
		capwap_packet_rxmng_free(session->rxmngctrlpacket);
		session->rxmngctrlpacket = NULL;
	} else if (!isctrlmsg && session->rxmngdatapacket) {
		capwap_packet_rxmng_free(session->rxmngdatapacket);
		session->rxmngdatapacket = NULL;
	}
}

/* */
static void ac_send_invalid_request(struct ac_session_t* session, struct capwap_packet_rxmng* rxmngpacket, struct capwap_connection* connection, uint32_t errorcode) {
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
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, rxmngpacket->ctrlmsg.type + 1, rxmngpacket->ctrlmsg.seq, session->mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_RESULTCODE, &resultcode);

	/* Unknown response complete, get fragment packets */
	responsefragmentpacket = capwap_list_create();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, responsefragmentpacket, session->fragmentid);
	if (responsefragmentpacket->count > 1) {
		session->fragmentid++;
	}

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send unknown response */
	capwap_crypt_sendto_fragmentpacket(&session->ctrldtls, connection->socket.socket[connection->socket.type], responsefragmentpacket, &connection->localaddr, &connection->remoteaddr);

	/* Don't buffering a packets sent */
	capwap_list_free(responsefragmentpacket);
}

/* Release reference of session */
static void ac_session_destroy(struct ac_session_t* session) {
	ASSERT(session != NULL);

	/* Free resource */
#ifdef DEBUG
	char sessionname[33];

	/* */
	capwap_sessionid_printf(&session->sessionid, sessionname);
	capwap_logging_debug("Release Session AC %s", sessionname);
#endif

	/* Release last reference */
	capwap_lock_enter(&session->sessionlock);
	session->count--;

	/* Terminate SOAP request pending */
	if (session->soaprequest) {
		ac_soapclient_shutdown_request(session->soaprequest);
	}

	/* Check if all reference is release */
	while (session->count > 0) {
#ifdef DEBUG
		capwap_logging_debug("Wait for release Session AC %s (count=%d)", sessionname, session->count);
#endif

		/* Wait */
		capwap_lock_exit(&session->sessionlock);
		sleep(10);
		capwap_lock_enter(&session->sessionlock);
	}

	capwap_lock_exit(&session->sessionlock);

	/* Free DTSL Control */
	capwap_crypt_freesession(&session->ctrldtls);

	/* Free DTLS Data */
	capwap_crypt_freesession(&session->datadtls);

	/* Free resource */
	while ((session->controlpackets->count > 0) || (session->datapackets->count > 0)) {
		capwap_itemlist_free(capwap_itemlist_remove_head(((session->controlpackets->count > 0) ? session->controlpackets : session->datapackets)));
	}

	/* */
	capwap_event_destroy(&session->waitpacket);
	capwap_lock_destroy(&session->sessionlock);
	capwap_list_free(session->actionsession);
	capwap_list_free(session->controlpackets);
	capwap_list_free(session->datapackets);

	/* Free fragments packet */
	ac_free_packet_rxmng(session, 1);
	ac_free_packet_rxmng(session, 0);

	capwap_list_free(session->requestfragmentpacket);
	capwap_list_free(session->responsefragmentpacket);

	/* Free DFA resource */
	capwap_array_free(session->dfa.acipv4list.addresses);
	capwap_array_free(session->dfa.acipv6list.addresses);

	if (session->wtpid) {
		capwap_free(session->wtpid);
	}

	/* Free item */
	capwap_itemlist_free(session->itemlist);
}

/* */
static void ac_session_run(struct ac_session_t* session) {
	int res;
	int check;
	int length;
	int isctrlsocket;
	struct capwap_connection connection;
	char buffer[CAPWAP_MAX_PACKET_SIZE];

	ASSERT(session != NULL);

	/* Configure DFA */
	if (g_ac.enabledtls) {
		if (!ac_dtls_setup(session)) {
			ac_session_teardown(session);			/* Teardown connection */
		}
	} else {
		/* Wait Join request */
		ac_dfa_change_state(session, CAPWAP_JOIN_STATE);
		capwap_set_timeout(session->dfa.rfcWaitJoin, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
	}

	while (session->state != CAPWAP_DTLS_TEARDOWN_STATE) {
		/* Get packet */
		length = ac_network_read(session, buffer, sizeof(buffer), &isctrlsocket, &session->timeout);
		if (length < 0) {
			if (length == PACKET_TIMEOUT) {
				ac_dfa_execute(session, NULL);
			} else if (length == DTLS_SHUTDOWN) {
				ac_session_teardown(session);
			} else if (length == ACTION_SESSION) {
				/* Nothing */
			}
		} else if (length > 0) {
			/* Accept data packet only in running state */
			if (isctrlsocket || (session->state == CAPWAP_DATA_CHECK_TO_RUN_STATE) || (session->state == CAPWAP_RUN_STATE)) {
				/* Check generic capwap packet */
				check = capwap_sanity_check(isctrlsocket, CAPWAP_UNDEF_STATE, buffer, length, 0, 0);
				if (check == CAPWAP_PLAIN_PACKET) {
					struct capwap_parsed_packet packet;
					struct capwap_packet_rxmng* rxmngpacket;

					/* Defragment management */
					rxmngpacket = ac_get_packet_rxmng(session, isctrlsocket);

					/* If request, defragmentation packet */
					check = capwap_packet_rxmng_add_recv_packet(rxmngpacket, buffer, length);
					if (check == CAPWAP_RECEIVE_COMPLETE_PACKET) {
						int ignorepacket = 0;

						/* Receive all fragment */
						memcpy(&connection.socket, (isctrlsocket ? &session->ctrlsocket : &session->datasocket), sizeof(struct capwap_socket));
						memcpy(&connection.localaddr, (isctrlsocket ? &session->acctrladdress : &session->acdataaddress), sizeof(struct sockaddr_storage));
						memcpy(&connection.remoteaddr, (isctrlsocket ? &session->wtpctrladdress : &session->wtpdataaddress), sizeof(struct sockaddr_storage));

						if (isctrlsocket) {
							if (!capwap_recv_retrasmitted_request(&session->ctrldtls, rxmngpacket, &connection, session->lastrecvpackethash, session->responsefragmentpacket)) {
								/* Check message type */
								res = capwap_check_message_type(rxmngpacket);
								if (res != VALID_MESSAGE_TYPE) {
									if (res == INVALID_REQUEST_MESSAGE_TYPE) {
										capwap_logging_warning("Unexpected Unrecognized Request, send Response Packet with error");
										ac_send_invalid_request(session, rxmngpacket, &connection, CAPWAP_RESULTCODE_MSG_UNEXPECTED_UNRECOGNIZED_REQUEST);
									}
	
									ignorepacket = 1;
									capwap_logging_debug("Invalid message type");
								}
							} else {
								ignorepacket = 1;
								capwap_logging_debug("Retrasmitted packet");
							}
						}

						/* Parsing packet */
						if (!ignorepacket) {
							res = capwap_parsing_packet(rxmngpacket, &connection, &packet);
							if (res == PARSING_COMPLETE) {
								/* Validate packet */
								if (capwap_validate_parsed_packet(&packet, NULL)) {
									if (isctrlsocket && capwap_is_request_type(rxmngpacket->ctrlmsg.type)) {
										capwap_logging_warning("Missing Mandatory Message Element, send Response Packet with error");
										ac_send_invalid_request(session, rxmngpacket, &connection, CAPWAP_RESULTCODE_FAILURE_MISSING_MANDATORY_MSG_ELEMENT);
									}

									ignorepacket = 1;
									capwap_logging_debug("Failed validation parsed packet");
								}
							} else {
								if (isctrlsocket && (res == UNRECOGNIZED_MESSAGE_ELEMENT) && capwap_is_request_type(rxmngpacket->ctrlmsg.type)) {
									capwap_logging_warning("Unrecognized Message Element, send Response Packet with error");
									ac_send_invalid_request(session, rxmngpacket, &connection, CAPWAP_RESULTCODE_FAILURE_UNRECOGNIZED_MESSAGE_ELEMENT);
									/* TODO: add the unrecognized message element */
								}

								ignorepacket = 1;
								capwap_logging_debug("Failed parsing packet");
							}
						}

						/* */
						if (!ignorepacket) {
							ac_dfa_execute(session, &packet);
						}

						/* Free memory */
						capwap_free_parsed_packet(&packet);
						ac_free_packet_rxmng(session, isctrlsocket);
					} else if (check != CAPWAP_REQUEST_MORE_FRAGMENT) {
						/* Discard fragments */
						ac_free_packet_rxmng(session, isctrlsocket);
					}
				}
			}
		}
	}

	/* Wait teardown timeout before kill session */
	capwap_wait_timeout(&session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
	ac_dfa_state_teardown(session);

	/* Release reference session */
	ac_session_destroy(session);
}

/* Change WTP state machine */
void ac_dfa_change_state(struct ac_session_t* session, int state) {
	ASSERT(session != NULL);

	if (state != session->state) {
#ifdef DEBUG
		char sessionname[33];
		capwap_sessionid_printf(&session->sessionid, sessionname);
		capwap_logging_debug("Session AC %s change state from %s to %s", sessionname, capwap_dfa_getname(session->state), capwap_dfa_getname(state));
#endif

		session->state = state;
	}
}

/* Teardown connection */
void ac_session_teardown(struct ac_session_t* session) {
	ASSERT(session != NULL);

	/* Remove session from list */
	capwap_rwlock_wrlock(&g_ac.sessionslock);
	capwap_itemlist_remove(g_ac.sessions, session->itemlist);
	capwap_rwlock_exit(&g_ac.sessionslock);

	/* Remove all pending packets */
	while ((session->controlpackets->count > 0) || (session->datapackets->count > 0)) {
		capwap_itemlist_free(capwap_itemlist_remove_head(((session->controlpackets->count > 0) ? session->controlpackets : session->datapackets)));
	}

	/* Close DTSL Control */
	if (session->ctrldtls.enable) {
		capwap_crypt_close(&session->ctrldtls);
	}

	/* Close DTLS Data */
	if (session->datadtls.enable) {
		capwap_crypt_close(&session->datadtls);
	}

	/* */
	capwap_killall_timeout(&session->timeout);
	capwap_set_timeout(session->dfa.rfcDTLSSessionDelete, &session->timeout, CAPWAP_TIMER_CONTROL_CONNECTION);
	ac_dfa_change_state(session, CAPWAP_DTLS_TEARDOWN_STATE);
}

/* */
void* ac_session_thread(void* param) {
	pthread_t threadid;
	struct ac_session_t* session = (struct ac_session_t*)param;

	ASSERT(param != NULL);

	threadid = session->threadid;

	/* */
	capwap_logging_debug("Session start");
	ac_session_run(session);
	capwap_logging_debug("Session end");

	/* Notify terminate thread */
	ac_session_msgqueue_notify_closethread(threadid);

	/* Thread exit */
	pthread_exit(NULL);
	return NULL;
}

/* */
void ac_get_control_information(struct capwap_list* controllist) {
	struct capwap_list* addrlist;
	struct capwap_list_item* item;

	ASSERT(controllist != NULL);

	/* Detect local address */
	addrlist = capwap_list_create();
	capwap_interface_list(&g_ac.net, addrlist);
	
	/* Prepare control list */
	for (item = addrlist->first; item != NULL; item = item->next) {
		struct capwap_list_item* itemcontrol;
		struct ac_session_control* sessioncontrol;
		struct sockaddr_storage* address = (struct sockaddr_storage*)item->item;

		/* */
		itemcontrol = capwap_itemlist_create(sizeof(struct ac_session_control));
		sessioncontrol = (struct ac_session_control*)itemcontrol->item;
		memcpy(&sessioncontrol->localaddress, address, sizeof(struct sockaddr_storage));
		sessioncontrol->count = 0;
		
		/* Add */
		capwap_itemlist_insert_after(controllist, NULL, itemcontrol);
	}

	/* Free local address list */
	capwap_list_free(addrlist);

	/* */
	capwap_rwlock_rdlock(&g_ac.sessionslock);

	/* Get wtp count from any local address */
	for (item = controllist->first; item != NULL; item = item->next) {
		struct capwap_list_item* search;
		struct ac_session_control* sessioncontrol = (struct ac_session_control*)item->item;

		for (search = g_ac.sessions->first; search != NULL; search = search->next) {
			struct ac_session_t* session = (struct ac_session_t*)search->item;

			if (!capwap_compare_ip(&session->acctrladdress, &sessioncontrol->localaddress)) {
				sessioncontrol->count++;
			}
		}
	}

	/* */
	capwap_rwlock_exit(&g_ac.sessionslock);
}

/* */
void ac_free_reference_last_request(struct ac_session_t* session) {
	ASSERT(session);

	capwap_list_flush(session->requestfragmentpacket);
}

/* */
void ac_free_reference_last_response(struct ac_session_t* session) {
	ASSERT(session);

	capwap_list_flush(session->responsefragmentpacket);
	memset(&session->lastrecvpackethash[0], 0, sizeof(session->lastrecvpackethash));
}

/* */
struct ac_soap_response* ac_session_send_soap_request(struct ac_session_t* session, char* method, int numparam, ...) {
	int i;
	va_list listparam;
	struct ac_soap_request* request;
	struct ac_http_soap_server* server;
	struct ac_soap_response* response = NULL;

	ASSERT(session != NULL);
	ASSERT(session->soaprequest == NULL);
	ASSERT(method != NULL);

	/* Get HTTP Soap Server */
	server = ac_backend_gethttpsoapserver();
	if (!server) {
		return NULL;
	}

	/* Critical section */
	capwap_lock_enter(&session->sessionlock);

	ASSERT(g_ac.backendsessionid != NULL);

	/* Build Soap Request */
	request = ac_soapclient_create_request(method, SOAP_NAMESPACE_URI);
	if (request) {
		ac_soapclient_add_param(request, "xs:string", "idsession", g_ac.backendsessionid);
		session->soaprequest = ac_soapclient_prepare_request(request, server);
	}

	capwap_lock_exit(&session->sessionlock);

	/* */
	if (!session->soaprequest) {
		if (request) {
			ac_soapclient_free_request(request);
		}

		return NULL;
	}

	/* Add params */
	va_start(listparam, numparam);
	for (i = 0; i < numparam; i++) {
		char* type = va_arg(listparam, char*);
		char* name = va_arg(listparam, char*);
		char* value = va_arg(listparam, char*);

		if (!ac_soapclient_add_param(request, type, name, value)) {
			ac_soapclient_close_request(session->soaprequest, 1);
			session->soaprequest = NULL;
			break;
		}
	}
	va_end(listparam);

	/* Send Request & Recv Response */
	if (session->soaprequest) {
		if (ac_soapclient_send_request(session->soaprequest, "")) {
			response = ac_soapclient_recv_response(session->soaprequest);
		}

		/* Critical section */
		capwap_lock_enter(&session->sessionlock);

		/* Free resource */
		ac_soapclient_close_request(session->soaprequest, 1);
		session->soaprequest = NULL;

		capwap_lock_exit(&session->sessionlock);
	}

	return response;
}
