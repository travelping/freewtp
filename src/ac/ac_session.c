#include <stdarg.h>
#include "ac.h"
#include "capwap_dfa.h"
#include "ac_session.h"
#include "ac_backend.h"
#include "ac_wlans.h"
#include <arpa/inet.h>

#define AC_ERROR_TIMEOUT				-1000
#define AC_ERROR_ACTION_SESSION			-1001

/* */
static int ac_session_action_resetwtp(struct ac_session_t* session, struct ac_notify_reset_t* reset) {
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_imageidentifier_element imageidentifier;

	ASSERT(session->requestfragmentpacket->count == 0);

	/* */
	imageidentifier.vendor = reset->vendor;
	imageidentifier.name = reset->name;

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, session->binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_RESET_REQUEST, session->localseqnumber++, session->mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_IMAGEIDENTIFIER, &imageidentifier);
	/* CAPWAP_ELEMENT_VENDORPAYLOAD */				/* TODO */

	/* Reset request complete, get fragment packets */
	capwap_packet_txmng_get_fragment_packets(txmngpacket, session->requestfragmentpacket, session->fragmentid);
	if (session->requestfragmentpacket->count > 1) {
		session->fragmentid++;
	}

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send Reset Request to WTP */
	if (capwap_crypt_sendto_fragmentpacket(&session->dtls, session->connection.socket.socket[session->connection.socket.type], session->requestfragmentpacket, &session->connection.localaddr, &session->connection.remoteaddr)) {
		session->retransmitcount = 0;
		ac_dfa_change_state(session, CAPWAP_RESET_STATE);
		capwap_timeout_set(session->timeout, session->idtimercontrol, AC_RETRANSMIT_INTERVAL, ac_dfa_retransmition_timeout, session, NULL);
	} else {
		capwap_logging_debug("Warning: error to send reset request packet");
		ac_free_reference_last_request(session);
		ac_session_teardown(session);
	}

	return AC_ERROR_ACTION_SESSION;
}

/* */
static int ac_session_action_addwlan(struct ac_session_t* session, struct ac_notify_addwlan_t* notify) {
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_80211_addwlan_element addwlan;

	ASSERT(session->requestfragmentpacket->count == 0);

	/* Check if WLAN id is valid and not used */
	if (!IS_VALID_RADIOID(notify->radioid) || !IS_VALID_WLANID(notify->wlanid)) {
		return AC_ERROR_ACTION_SESSION;
	} else if (ac_wlans_get_bssid_with_wlanid(session->wlans, notify->radioid, notify->wlanid)) {
		return AC_ERROR_ACTION_SESSION;
	}

	/* */
	memset(&addwlan, 0, sizeof(struct capwap_80211_addwlan_element));
	addwlan.radioid = notify->radioid;
	addwlan.wlanid = notify->wlanid;
	addwlan.capability = notify->capability;
	addwlan.qos = notify->qos;
	addwlan.authmode = notify->authmode;
	addwlan.macmode = notify->macmode;
	addwlan.tunnelmode = notify->tunnelmode;
	addwlan.suppressssid = notify->suppressssid;
	addwlan.ssid = (uint8_t*)notify->ssid;

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, session->binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_IEEE80211_WLAN_CONFIGURATION_REQUEST, session->localseqnumber++, session->mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_ADD_WLAN, &addwlan);

	/* CAPWAP_ELEMENT_80211_IE */

	/* CAPWAP_ELEMENT_VENDORPAYLOAD */				/* TODO */

	/* WLAN Configuration Request complete, get fragment packets */
	capwap_packet_txmng_get_fragment_packets(txmngpacket, session->requestfragmentpacket, session->fragmentid);
	if (session->requestfragmentpacket->count > 1) {
		session->fragmentid++;
	}

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send WLAN Configuration Request to WTP */
	if (capwap_crypt_sendto_fragmentpacket(&session->dtls, session->connection.socket.socket[session->connection.socket.type], session->requestfragmentpacket, &session->connection.localaddr, &session->connection.remoteaddr)) {
		session->retransmitcount = 0;
		capwap_timeout_set(session->timeout, session->idtimercontrol, AC_RETRANSMIT_INTERVAL, ac_dfa_retransmition_timeout, session, NULL);
	} else {
		capwap_logging_debug("Warning: error to send reset request packet");
		ac_free_reference_last_request(session);
		ac_session_teardown(session);
	}

	return AC_ERROR_ACTION_SESSION;
}

/* */
static int ac_session_action_execute(struct ac_session_t* session, struct ac_session_action* action) {
	int result = AC_ERROR_ACTION_SESSION;

	switch (action->action) {
		case AC_SESSION_ACTION_CLOSE: {
			result = CAPWAP_ERROR_CLOSE;
			break;
		}

		case AC_SESSION_ACTION_RESET_WTP: {
			result = ac_session_action_resetwtp(session, (struct ac_notify_reset_t*)action->data);
			break;
		}

		case AC_SESSION_ACTION_ADDWLAN: {
			result = ac_session_action_addwlan(session, (struct ac_notify_addwlan_t*)action->data);
			break;
		}

		case AC_SESSION_ACTION_ESTABLISHED_SESSION_DATA: {
			int valid = 0;
			struct ac_soap_response* response;

			/* Capwap handshake complete, notify event to backend */
			response = ac_soap_runningwtpsession(session, session->wtpid);
			if (response) {
				valid = ((response->responsecode == HTTP_RESULT_OK) ? 1 : 0);
				ac_soapclient_free_response(response);
			}

			if (valid) {
				ac_dfa_change_state(session, CAPWAP_RUN_STATE);
				capwap_timeout_set(session->timeout, session->idtimercontrol, AC_MAX_ECHO_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
			} else {
				result = CAPWAP_ERROR_CLOSE;
			}

			break;
		}

		case AC_SESSION_ACTION_NOTIFY_EVENT: {
			struct capwap_list_item* item;

			/* Copy event into queue */
			item = capwap_itemlist_create(sizeof(struct ac_session_notify_event_t));
			memcpy(item->item, action->data, sizeof(struct ac_session_notify_event_t));
			capwap_itemlist_insert_after(session->notifyevent, NULL, item);

			break;
		}
	}

	return result;
}

/* */
static int ac_network_read(struct ac_session_t* session, void* buffer, int length) {
	int result = 0;
	long waittimeout;
	
	ASSERT(session != NULL);
	ASSERT(buffer != NULL);
	ASSERT(length > 0);

	for (;;) {
		capwap_lock_enter(&session->sessionlock);

		if (!session->running) {
			capwap_lock_exit(&session->sessionlock);
			return CAPWAP_ERROR_CLOSE;
		} else if (!session->requestfragmentpacket->count && (session->action->count > 0)) {
			struct capwap_list_item* itemaction;

			itemaction = capwap_itemlist_remove_head(session->action);
			capwap_lock_exit(&session->sessionlock);

			/* */
			result = ac_session_action_execute(session, (struct ac_session_action*)itemaction->item);

			/* Free packet */
			capwap_itemlist_free(itemaction);
			return result;
		} else if (session->packets->count > 0) {
			struct capwap_list_item* itempacket;

			capwap_logging_debug("Receive control packet");

			/* Get packet */
			itempacket = capwap_itemlist_remove_head(session->packets);
			capwap_lock_exit(&session->sessionlock);

			if (itempacket) {
				struct ac_packet* packet = (struct ac_packet*)itempacket->item;
				long packetlength = itempacket->itemsize - sizeof(struct ac_packet);
				
				if (!packet->plainbuffer && session->dtls.enable) {
					int oldaction = session->dtls.action;

					/* Decrypt packet */
					result = capwap_decrypt_packet(&session->dtls, packet->buffer, packetlength, buffer, length);
					if (result == CAPWAP_ERROR_AGAIN) {
						/* Check is handshake complete */
						if ((oldaction == CAPWAP_DTLS_ACTION_HANDSHAKE) && (session->dtls.action == CAPWAP_DTLS_ACTION_DATA)) {
							if (session->state == CAPWAP_DTLS_CONNECT_STATE) {
								ac_dfa_change_state(session, CAPWAP_JOIN_STATE);
								capwap_timeout_set(session->timeout, session->idtimercontrol, AC_JOIN_INTERVAL, ac_dfa_state_join_timeout, session, NULL);
							}
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

		/* Get timeout */
		waittimeout = capwap_timeout_getcoming(session->timeout);
		if (!waittimeout) {
			capwap_timeout_hasexpired(session->timeout);
			return AC_ERROR_TIMEOUT;
		}

		/* Wait packet */
		capwap_event_wait_timeout(&session->waitpacket, waittimeout);
	}

	return 0;
}

/* */
static void ac_dfa_execute(struct ac_session_t* session, struct capwap_parsed_packet* packet) {
	ASSERT(session != NULL);
	ASSERT(packet != NULL);

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
static void ac_send_invalid_request(struct ac_session_t* session, uint32_t errorcode) {
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_list* responsefragmentpacket;
	struct capwap_fragment_packet_item* packet;
	struct capwap_header* header;
	struct capwap_resultcode_element resultcode = { .code = errorcode };

	ASSERT(session != NULL);
	ASSERT(session->rxmngpacket != NULL);
	ASSERT(session->rxmngpacket->fragmentlist->first != NULL);

	/* */
	packet = (struct capwap_fragment_packet_item*)session->rxmngpacket->fragmentlist->first->item;
	header = (struct capwap_header*)packet->buffer;

	/* Odd message type */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, GET_WBID_HEADER(header));
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, session->rxmngpacket->ctrlmsg.type + 1, session->rxmngpacket->ctrlmsg.seq, session->mtu);

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
	capwap_crypt_sendto_fragmentpacket(&session->dtls, session->connection.socket.socket[session->connection.socket.type], responsefragmentpacket, &session->connection.localaddr, &session->connection.remoteaddr);

	/* Don't buffering a packets sent */
	capwap_list_free(responsefragmentpacket);
}

/* Release reference of session */
static void ac_session_destroy(struct ac_session_t* session) {
#ifdef DEBUG
	char sessionname[33];
#endif

	ASSERT(session != NULL);

#ifdef DEBUG
	capwap_sessionid_printf(&session->sessionid, sessionname);
	capwap_logging_debug("Release Session AC %s", sessionname);
#endif

	/* Release session data reference */
	if (session->sessiondata) {
		ac_session_data_close(session->sessiondata);
		ac_session_data_release_reference(session->sessiondata);
	}

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
		/* */
		capwap_event_reset(&session->changereference);
		capwap_lock_exit(&session->sessionlock);

		/* Wait */
		capwap_event_wait(&session->changereference);

		capwap_lock_enter(&session->sessionlock);
	}

	capwap_lock_exit(&session->sessionlock);

	/* Free DTSL Control */
	capwap_crypt_freesession(&session->dtls);

	/* Free resource */
	while (session->packets->count > 0) {
		capwap_itemlist_free(capwap_itemlist_remove_head(session->packets));
	}

	/* Free WLANS */
	ac_wlans_destroy(session->wlans);

	/* */
	capwap_event_destroy(&session->changereference);
	capwap_event_destroy(&session->waitpacket);
	capwap_lock_destroy(&session->sessionlock);
	capwap_list_free(session->action);
	capwap_list_free(session->packets);

	/* Free fragments packet */
	if (session->rxmngpacket) {
		capwap_packet_rxmng_free(session->rxmngpacket);
	}

	capwap_list_free(session->requestfragmentpacket);
	capwap_list_free(session->responsefragmentpacket);
	capwap_list_free(session->notifyevent);
	capwap_timeout_free(session->timeout);

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
static void ac_session_report_connection(struct ac_session_t* session) {
	char localip[INET6_ADDRSTRLEN + 10] = "";
	char remoteip[INET6_ADDRSTRLEN + 10] = "";

	if (session->connection.localaddr.ss_family == AF_INET) {
		char buffer[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, (void*)&((struct sockaddr_in*)&session->connection.localaddr)->sin_addr, buffer, INET_ADDRSTRLEN);
		sprintf(localip, "%s:%hu", buffer, ntohs(((struct sockaddr_in*)&session->connection.localaddr)->sin_port));
	} else if (session->connection.localaddr.ss_family == AF_INET6) {
		char buffer[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, (void*)&((struct sockaddr_in6*)&session->connection.localaddr)->sin6_addr, buffer, INET6_ADDRSTRLEN);
		sprintf(localip, "%s:%hu", buffer, ntohs(((struct sockaddr_in6*)&session->connection.localaddr)->sin6_port));
	}

	if (session->connection.remoteaddr.ss_family == AF_INET) {
		char buffer[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, (void*)&((struct sockaddr_in*)&session->connection.remoteaddr)->sin_addr, buffer, INET_ADDRSTRLEN);
		sprintf(remoteip, "%s:%hu", buffer, ntohs(((struct sockaddr_in*)&session->connection.remoteaddr)->sin_port));
	} else if (session->connection.remoteaddr.ss_family == AF_INET6) {
		char buffer[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, (void*)&((struct sockaddr_in6*)&session->connection.remoteaddr)->sin6_addr, buffer, INET6_ADDRSTRLEN);
		sprintf(remoteip, "%s:%hu", buffer, ntohs(((struct sockaddr_in6*)&session->connection.remoteaddr)->sin6_port));
	}

	capwap_logging_info("Start control channel from %s to %s", remoteip, localip);
}

/* */
static void ac_session_run(struct ac_session_t* session) {
	int res;
	int check;
	int length;
	struct capwap_list_item* search;
	char buffer[CAPWAP_MAX_PACKET_SIZE];

	ASSERT(session != NULL);

	/* */
	ac_session_report_connection(session);

	/* Configure DFA */
	if (g_ac.enabledtls) {
		if (!ac_dtls_setup(session)) {
			ac_session_teardown(session);			/* Teardown connection */
		}
	} else {
		/* Wait Join request */
		ac_dfa_change_state(session, CAPWAP_JOIN_STATE);
		capwap_timeout_set(session->timeout, session->idtimercontrol, AC_JOIN_INTERVAL, ac_dfa_state_join_timeout, session, NULL);
	}

	while (session->state != CAPWAP_DTLS_TEARDOWN_STATE) {
		/* Get packet */
		length = ac_network_read(session, buffer, sizeof(buffer));
		if (length < 0) {
			if ((length == CAPWAP_ERROR_SHUTDOWN) || (length == CAPWAP_ERROR_CLOSE)) {
				ac_session_teardown(session);
			}
		} else if (length > 0) {
			/* Check generic capwap packet */
			check = capwap_sanity_check(1, CAPWAP_UNDEF_STATE, buffer, length, 0, 0);
			if (check == CAPWAP_PLAIN_PACKET) {
				struct capwap_parsed_packet packet;

				/* Defragment management */
				if (!session->rxmngpacket) {
					session->rxmngpacket = capwap_packet_rxmng_create_message(CAPWAP_CONTROL_PACKET);
				}

				/* If request, defragmentation packet */
				check = capwap_packet_rxmng_add_recv_packet(session->rxmngpacket, buffer, length);
				if (check == CAPWAP_RECEIVE_COMPLETE_PACKET) {
					/* Receive all fragment */
					if (!capwap_recv_retrasmitted_request(&session->dtls, session->rxmngpacket, &session->connection, session->lastrecvpackethash, session->responsefragmentpacket)) {
						/* Check message type */
						res = capwap_check_message_type(session->rxmngpacket);
						if (res == VALID_MESSAGE_TYPE) {
							res = capwap_parsing_packet(session->rxmngpacket, &session->connection, &packet);
							if (res == PARSING_COMPLETE) {
								int hasrequest = capwap_is_request_type(session->rxmngpacket->ctrlmsg.type);

								/* Validate packet */
								if (!capwap_validate_parsed_packet(&packet, NULL)) {
									/* Search into notify event */
									search = session->notifyevent->first;
									while (search != NULL) {
										struct ac_session_notify_event_t* notify = (struct ac_session_notify_event_t*)search->item;

										if (hasrequest && (notify->action == NOTIFY_ACTION_RECEIVE_REQUEST_CONTROLMESSAGE)) {
											char buffer[4];
											struct ac_soap_response* response;

											/* */
											response = ac_soap_updatebackendevent(session, notify->idevent, capwap_itoa(SOAP_EVENT_STATUS_COMPLETE, buffer));
											if (response) {
												ac_soapclient_free_response(response);
											}

											/* Remove notify event */
											capwap_itemlist_free(capwap_itemlist_remove(session->notifyevent, search));
											break;
										} else if (!hasrequest && (notify->action == NOTIFY_ACTION_RECEIVE_RESPONSE_CONTROLMESSAGE)) {
											char buffer[4];
											struct ac_soap_response* response;
											struct capwap_resultcode_element* resultcode;

											/* Check the success of the Request */
											resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(&packet, CAPWAP_ELEMENT_RESULTCODE);
											response = ac_soap_updatebackendevent(session, notify->idevent, capwap_itoa(((!resultcode || CAPWAP_RESULTCODE_OK(resultcode->code)) ? SOAP_EVENT_STATUS_COMPLETE : SOAP_EVENT_STATUS_GENERIC_ERROR), buffer));
											if (response) {
												ac_soapclient_free_response(response);
											}

											/* Remove notify event */
											capwap_itemlist_free(capwap_itemlist_remove(session->notifyevent, search));
											break;
										}

										search = search->next;
									}

									/* */
									ac_dfa_execute(session, &packet);
								} else {
									capwap_logging_debug("Failed validation parsed control packet");
									if (capwap_is_request_type(session->rxmngpacket->ctrlmsg.type)) {
										capwap_logging_warning("Missing Mandatory Message Element, send Response Packet with error");
										ac_send_invalid_request(session, CAPWAP_RESULTCODE_FAILURE_MISSING_MANDATORY_MSG_ELEMENT);
									}
								}
							} else {
								capwap_logging_debug("Failed parsing packet");
								if ((res == UNRECOGNIZED_MESSAGE_ELEMENT) && capwap_is_request_type(session->rxmngpacket->ctrlmsg.type)) {
									capwap_logging_warning("Unrecognized Message Element, send Response Packet with error");
									ac_send_invalid_request(session, CAPWAP_RESULTCODE_FAILURE_UNRECOGNIZED_MESSAGE_ELEMENT);
									/* TODO: add the unrecognized message element */
								}
							}
						} else {
							capwap_logging_debug("Invalid message type");
							if (res == INVALID_REQUEST_MESSAGE_TYPE) {
								capwap_logging_warning("Unexpected Unrecognized Request, send Response Packet with error");
								ac_send_invalid_request(session, CAPWAP_RESULTCODE_MSG_UNEXPECTED_UNRECOGNIZED_REQUEST);
							}
						}
					} else {
						capwap_logging_debug("Retrasmitted control packet");
					}

					/* Free memory */
					capwap_free_parsed_packet(&packet);
					if (session->rxmngpacket) {
						capwap_packet_rxmng_free(session->rxmngpacket);
						session->rxmngpacket = NULL;
					}
				} else if (check != CAPWAP_REQUEST_MORE_FRAGMENT) {
					/* Discard fragments */
					if (session->rxmngpacket) {
						capwap_packet_rxmng_free(session->rxmngpacket);
						session->rxmngpacket = NULL;
					}
				}
			}
		}
	}

	/* Wait teardown timeout before kill session */
	capwap_timeout_wait(AC_DTLS_SESSION_DELETE_INTERVAL);
	ac_dfa_state_teardown(session);

	/* Release reference session */
	ac_session_destroy(session);
}

/* Change WTP state machine */
void ac_dfa_change_state(struct ac_session_t* session, int state) {
	struct capwap_list_item* search;

	ASSERT(session != NULL);

	if (state != session->state) {
#ifdef DEBUG
		char sessionname[33];
		capwap_sessionid_printf(&session->sessionid, sessionname);
		capwap_logging_debug("Session AC %s change state from %s to %s", sessionname, capwap_dfa_getname(session->state), capwap_dfa_getname(state));
#endif

		session->state = state;

		/* Search into notify event */
		search = session->notifyevent->first;
		while (search != NULL) {
			struct ac_session_notify_event_t* notify = (struct ac_session_notify_event_t*)search->item;

			if ((notify->action == NOTIFY_ACTION_CHANGE_STATE) && (notify->session_state == state)) {
				char buffer[4];
				struct ac_soap_response* response;

				/* */
				response = ac_soap_updatebackendevent(session, notify->idevent, capwap_itoa(SOAP_EVENT_STATUS_COMPLETE, buffer));
				if (response) {
					ac_soapclient_free_response(response);
				}

				/* Remove notify event */
				capwap_itemlist_free(capwap_itemlist_remove(session->notifyevent, search));
				break;
			}

			search = search->next;
		}
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
	while (session->packets->count > 0) {
		capwap_itemlist_free(capwap_itemlist_remove_head(session->packets));
	}

	/* Close DTSL Control */
	if (session->dtls.enable) {
		capwap_crypt_close(&session->dtls);
	}

	/* Cancel all notify event */
	if (session->notifyevent->first) {
		char buffer[5];
		struct ac_soap_response* response;

		capwap_itoa(SOAP_EVENT_STATUS_CANCEL, buffer);
		while (session->notifyevent->first != NULL) {
			struct ac_session_notify_event_t* notify = (struct ac_session_notify_event_t*)session->notifyevent->first->item;

			/* Cancel event */
			response = ac_soap_updatebackendevent(session, notify->idevent, buffer);
			if (response) {
				ac_soapclient_free_response(response);
			}

			/* Remove notify event */
			capwap_itemlist_free(capwap_itemlist_remove(session->notifyevent, session->notifyevent->first));
		}
	}

	/* */
	ac_dfa_change_state(session, CAPWAP_DTLS_TEARDOWN_STATE);
	capwap_timeout_unset(session->timeout, session->idtimercontrol);
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
	ac_msgqueue_notify_closethread(threadid);

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

			if (!capwap_compare_ip(&session->connection.localaddr, &sessioncontrol->localaddress)) {
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
	struct ac_soap_response* response = NULL;

	ASSERT(session != NULL);
	ASSERT(session->soaprequest == NULL);
	ASSERT(method != NULL);

	/* Build Soap Request */
	capwap_lock_enter(&session->sessionlock);
	session->soaprequest = ac_backend_createrequest_with_session(method, SOAP_NAMESPACE_URI);
	capwap_lock_exit(&session->sessionlock);

	/* */
	if (!session->soaprequest) {
		return NULL;
	}

	/* Add params */
	va_start(listparam, numparam);
	for (i = 0; i < numparam; i++) {
		char* type = va_arg(listparam, char*);
		char* name = va_arg(listparam, char*);
		char* value = va_arg(listparam, char*);

		if (!ac_soapclient_add_param(session->soaprequest->request, type, name, value)) {
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

/* */
void ac_dfa_retransmition_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	struct ac_session_t* session = (struct ac_session_t*)context;

	if (!session->requestfragmentpacket->count) {
		ac_session_teardown(session);
	} else {
		session->retransmitcount++;
		if (session->retransmitcount >= AC_MAX_RETRANSMIT) {
			/* Timeout reset state */
			ac_free_reference_last_request(session);
			ac_session_teardown(session);
		} else {
			/* Retransmit Reset Request */
			capwap_logging_debug("Retransmition request packet");
			if (!capwap_crypt_sendto_fragmentpacket(&session->dtls, session->connection.socket.socket[session->connection.socket.type], session->requestfragmentpacket, &session->connection.localaddr, &session->connection.remoteaddr)) {
				capwap_logging_error("Error to send request packet");
			}

			/* Update timeout */
			capwap_timeout_set(session->timeout, session->idtimercontrol, AC_RETRANSMIT_INTERVAL, ac_dfa_retransmition_timeout, session, NULL);
		}
	}
}

void ac_dfa_teardown_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	ac_session_teardown((struct ac_session_t*)context);
}
