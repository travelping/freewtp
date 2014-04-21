#include "ac.h"
#include "capwap_dfa.h"
#include "ac_session.h"
#include "ac_wlans.h"
#include "ieee80211.h"
#include <arpa/inet.h>

#define AC_ERROR_TIMEOUT				-1000
#define AC_ERROR_ACTION_SESSION			-1001

#define AC_BODY_PACKET_MAX_SIZE			8192

/* */
static int ac_session_data_action_add_station_status(struct ac_session_data_t* sessiondata, struct ac_notify_add_station_status* notify) {
	struct ac_wlan* wlan;
	struct ac_station* station;
	char buffer[CAPWAP_MACADDRESS_EUI48_BUFFER];

	wlan = ac_wlans_get_bssid_with_wlanid(sessiondata, notify->radioid, notify->wlanid);
	if (wlan) {
		station = ac_stations_get_station(sessiondata, notify->radioid, wlan->bssid, notify->address);
		if (station) {
			if (CAPWAP_RESULTCODE_OK(notify->statuscode)) {
				capwap_logging_info("Authorized station: %s", capwap_printf_macaddress(buffer, station->address, MACADDRESS_EUI48_LENGTH));

				/* */
				station->flags |= AC_STATION_FLAGS_AUTHORIZED;
				capwap_timeout_deletetimer(sessiondata->timeout, station->idtimeout);
				station->idtimeout = CAPWAP_TIMEOUT_INDEX_NO_SET;
			} else {
				ac_stations_delete_station(sessiondata, station);
			}
		}
	}

	return AC_ERROR_ACTION_SESSION;
}

/* */
static int ac_session_data_action_delete_station_status(struct ac_session_data_t* sessiondata, struct ac_notify_delete_station_status* notify) {
	struct ac_station* station;
	char buffer[CAPWAP_MACADDRESS_EUI48_BUFFER];

	station = ac_stations_get_station(sessiondata, notify->radioid, NULL, notify->address);
	if (station) {
		capwap_logging_info("Deauthorized station: %s with %d result code", capwap_printf_macaddress(buffer, station->address, MACADDRESS_EUI48_LENGTH), (int)notify->statuscode);

		/* */
		ac_stations_delete_station(sessiondata, station);
	}

	return AC_ERROR_ACTION_SESSION;
}

/* */
static int ac_session_data_action_execute(struct ac_session_data_t* sessiondata, struct ac_session_action* action) {
	int result = AC_ERROR_ACTION_SESSION;

	switch (action->action) {
		case AC_SESSION_DATA_ACTION_ROAMING_STATION: {
			struct ac_station* station;

			/* Delete station */
			station = ac_stations_get_station(sessiondata, RADIOID_ANY, NULL, (uint8_t*)action->data);
			if (station) {
				ac_stations_delete_station(sessiondata, station);
			}

			break;
		}

		case AC_SESSION_DATA_ACTION_ASSIGN_BSSID: {
			ac_wlans_assign_bssid(sessiondata, *(struct ac_wlan**)action->data);
			break;
		}

		case AC_SESSION_DATA_ACTION_ADD_STATION_STATUS: {
			result = ac_session_data_action_add_station_status(sessiondata, (struct ac_notify_add_station_status*)action->data);
			break;
		}

		case AC_SESSION_DATA_ACTION_DELETE_STATION_STATUS: {
			result = ac_session_data_action_delete_station_status(sessiondata, (struct ac_notify_delete_station_status*)action->data);
			break;
		}
	}

	return result;
}

/* */
static int ac_network_read(struct ac_session_data_t* sessiondata, void* buffer, int length) {
	long waittimeout;
	int result = CAPWAP_ERROR_AGAIN;

	ASSERT(sessiondata != NULL);
	ASSERT(buffer != NULL);
	ASSERT(length > 0);

	for (;;) {
		capwap_lock_enter(&sessiondata->sessionlock);

		if (!sessiondata->running) {
			capwap_lock_exit(&sessiondata->sessionlock);
			return CAPWAP_ERROR_CLOSE;
		} else if (sessiondata->action->count > 0) {
			struct capwap_list_item* itemaction;

			itemaction = capwap_itemlist_remove_head(sessiondata->action);
			capwap_lock_exit(&sessiondata->sessionlock);

			/* */
			result = ac_session_data_action_execute(sessiondata, (struct ac_session_action*)itemaction->item);

			/* Free packet */
			capwap_itemlist_free(itemaction);
			return result;
		} else if (sessiondata->packets->count > 0) {
			struct capwap_list_item* itempacket;

			capwap_logging_debug("Receive data packet");

			/* Get packet */
			itempacket = capwap_itemlist_remove_head(sessiondata->packets);
			capwap_lock_exit(&sessiondata->sessionlock);

			if (itempacket) {
				struct ac_packet* packet = (struct ac_packet*)itempacket->item;
				long packetlength = itempacket->itemsize - sizeof(struct ac_packet);
				
				if (!packet->plainbuffer && sessiondata->dtls.enable) {
					int oldaction = sessiondata->dtls.action;

					result = capwap_decrypt_packet(&sessiondata->dtls, packet->buffer, packetlength, buffer, length);
					if (result == CAPWAP_ERROR_AGAIN) {
						/* Check is handshake complete */
						if ((oldaction == CAPWAP_DTLS_ACTION_HANDSHAKE) && (sessiondata->dtls.action == CAPWAP_DTLS_ACTION_DATA)) {
							capwap_timeout_unset(sessiondata->timeout, sessiondata->idtimercontrol);
							capwap_timeout_set(sessiondata->timeout, sessiondata->idtimerkeepalivedead, AC_MAX_DATA_KEEPALIVE_INTERVAL, NULL, NULL, NULL);
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

		capwap_lock_exit(&sessiondata->sessionlock);

		/* Get timeout */
		waittimeout = capwap_timeout_getcoming(sessiondata->timeout);
		if (!waittimeout) {
			capwap_timeout_hasexpired(sessiondata->timeout);
			return AC_ERROR_TIMEOUT;
		}

		/* Wait packet */
		capwap_event_wait_timeout(&sessiondata->waitpacket, waittimeout);
	}

	return result;
}

/* Management keep-alive */
static int ac_session_data_keepalive(struct ac_session_data_t* sessiondata, struct capwap_parsed_packet* packet) {
	int result = 0;
	struct capwap_list* txfragpacket;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_sessionid_element* sessionid;

	/* Get session id */
	sessionid = (struct capwap_sessionid_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_SESSIONID);
	if (!sessionid) {
		return 0;
	}

	/* */
	if (sessiondata->session) {
		if (memcmp(sessionid, &sessiondata->sessionid, sizeof(struct capwap_sessionid_element))) {
			return 0;		/* Invalid session id */
		}
	} else {
		struct capwap_list_item* search;

		/* Retrieve session and interconnect with session data */
		capwap_rwlock_rdlock(&g_ac.sessionslock);

		search = g_ac.sessions->first;
		while (search != NULL) {
			struct ac_session_t* session = (struct ac_session_t*)search->item;
			ASSERT(session != NULL);

			if (!memcmp(sessionid, &session->sessionid, sizeof(struct capwap_sessionid_element))) {
				/* Link session and session data */
				capwap_lock_enter(&session->sessionlock);
				session->count++;
				sessiondata->session = session;
				capwap_event_signal(&session->changereference);
				capwap_lock_exit(&session->sessionlock);

				capwap_lock_enter(&sessiondata->sessionlock);
				sessiondata->count++;
				session->sessiondata = sessiondata;
				capwap_event_signal(&sessiondata->changereference);
				capwap_lock_exit(&sessiondata->sessionlock);

				break;
			}

			search = search->next;
		}

		capwap_rwlock_exit(&g_ac.sessionslock);

		/* */
		if (sessiondata->session) {
#ifdef DEBUG
			char sessionname[33];

			capwap_sessionid_printf(sessionid, sessionname);
			capwap_logging_debug("Establiched Session Data AC %s", sessionname);
#endif

			/* Notify established session data */
			memcpy(&sessiondata->sessionid, sessionid, sizeof(struct capwap_sessionid_element));
			ac_session_send_action(sessiondata->session, AC_SESSION_ACTION_ESTABLISHED_SESSION_DATA, 0, NULL, 0);
		} else {
			return 0;		/* Session not found */
		}
	}

	/* Send keep-alive response */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, GET_WBID_HEADER(packet->rxmngpacket->header));
	capwap_header_set_keepalive_flag(&capwapheader, 1);
	txmngpacket = capwap_packet_txmng_create_data_message(&capwapheader, sessiondata->mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_SESSIONID, &sessiondata->sessionid);

	/* Data keepalive complete, get fragment packets into local list */
	txfragpacket = capwap_list_create();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, txfragpacket, sessiondata->fragmentid);
	if (txfragpacket->count == 1) {
		/* Send Data keepalive to WTP */
		if (capwap_crypt_sendto_fragmentpacket(&sessiondata->dtls, sessiondata->connection.socket.socket[sessiondata->connection.socket.type], txfragpacket, &sessiondata->connection.localaddr, &sessiondata->connection.remoteaddr)) {
			result = 1;
		} else {
			capwap_logging_debug("Warning: error to send data channel keepalive packet");
		}
	} else {
		capwap_logging_debug("Warning: error to send data channel keepalive packet, fragment packet");
	}

	/* Free packets manager */
	capwap_list_free(txfragpacket);
	capwap_packet_txmng_free(txmngpacket);
	return result;
}

/* Release reference of session data */
static void ac_session_data_destroy(struct ac_session_data_t* sessiondata) {
#ifdef DEBUG
	char sessionname[33];
#endif

	ASSERT(sessiondata != NULL);

#ifdef DEBUG
	capwap_sessionid_printf(&sessiondata->sessionid, sessionname);
	capwap_logging_debug("Release Session Data AC %s", sessionname);
#endif

	/* Remove session data from list */
	capwap_rwlock_wrlock(&g_ac.sessionslock);
	capwap_itemlist_remove(g_ac.sessionsdata, sessiondata->itemlist);
	capwap_rwlock_exit(&g_ac.sessionslock);

	/* Release session reference */
	if (sessiondata->session) {
		ac_session_close(sessiondata->session);
		ac_session_release_reference(sessiondata->session);
	}

	/* Release last reference */
	capwap_lock_enter(&sessiondata->sessionlock);
	sessiondata->count--;

	/* Check if all reference is release */
	while (sessiondata->count > 0) {
#ifdef DEBUG
		capwap_logging_debug("Wait for release Session Data AC %s (count=%d)", sessionname, sessiondata->count);
#endif
		/* */
		capwap_event_reset(&sessiondata->changereference);
		capwap_lock_exit(&sessiondata->sessionlock);

		/* Wait */
		capwap_event_wait(&sessiondata->changereference);

		capwap_lock_enter(&sessiondata->sessionlock);
	}

	capwap_lock_exit(&sessiondata->sessionlock);

	/* Free DTLS */
	capwap_crypt_freesession(&sessiondata->dtls);

	/* Free WLANS */
	ac_wlans_destroy(sessiondata);

	/* Free resource */
	while (sessiondata->packets->count > 0) {
		capwap_itemlist_free(capwap_itemlist_remove_head(sessiondata->packets));
	}

	/* */
	capwap_event_destroy(&sessiondata->changereference);
	capwap_event_destroy(&sessiondata->waitpacket);
	capwap_lock_destroy(&sessiondata->sessionlock);
	capwap_list_free(sessiondata->action);
	capwap_list_free(sessiondata->packets);
	capwap_timeout_free(sessiondata->timeout);

	/* Free fragments packet */
	if (sessiondata->rxmngpacket) {
		capwap_packet_rxmng_free(sessiondata->rxmngpacket);
	}

	/* Free item */
	capwap_itemlist_free(sessiondata->itemlist);
}

/* */
static void ac_session_data_report_connection(struct ac_session_data_t* sessiondata) {
	char localip[INET6_ADDRSTRLEN + 10] = "";
	char remoteip[INET6_ADDRSTRLEN + 10] = "";

	if (sessiondata->connection.localaddr.ss_family == AF_INET) {
		char buffer[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, (void*)&((struct sockaddr_in*)&sessiondata->connection.localaddr)->sin_addr, buffer, INET_ADDRSTRLEN);
		sprintf(localip, "%s:%hu", buffer, ntohs(((struct sockaddr_in*)&sessiondata->connection.localaddr)->sin_port));
	} else if (sessiondata->connection.localaddr.ss_family == AF_INET6) {
		char buffer[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, (void*)&((struct sockaddr_in6*)&sessiondata->connection.localaddr)->sin6_addr, buffer, INET6_ADDRSTRLEN);
		sprintf(localip, "%s:%hu", buffer, ntohs(((struct sockaddr_in6*)&sessiondata->connection.localaddr)->sin6_port));
	}

	if (sessiondata->connection.remoteaddr.ss_family == AF_INET) {
		char buffer[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, (void*)&((struct sockaddr_in*)&sessiondata->connection.remoteaddr)->sin_addr, buffer, INET_ADDRSTRLEN);
		sprintf(remoteip, "%s:%hu", buffer, ntohs(((struct sockaddr_in*)&sessiondata->connection.remoteaddr)->sin_port));
	} else if (sessiondata->connection.remoteaddr.ss_family == AF_INET6) {
		char buffer[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, (void*)&((struct sockaddr_in6*)&sessiondata->connection.remoteaddr)->sin6_addr, buffer, INET6_ADDRSTRLEN);
		sprintf(remoteip, "%s:%hu", buffer, ntohs(((struct sockaddr_in6*)&sessiondata->connection.remoteaddr)->sin6_port));
	}

	capwap_logging_info("Start data channel from %s to %s", remoteip, localip);
}

/* */
static void ac_session_data_run(struct ac_session_data_t* sessiondata) {
	int res;
	int check;
	int length;
	struct capwap_connection connection;
	char buffer[CAPWAP_MAX_PACKET_SIZE];
	uint8_t radioid;
	unsigned short binding;
	int bodypacketlength;
	uint8_t bodypacket[AC_BODY_PACKET_MAX_SIZE];

	ASSERT(sessiondata != NULL);

	/* */
	ac_session_data_report_connection(sessiondata);

	/* Create DTLS channel */
	if (sessiondata->enabledtls) {
		if (ac_dtls_data_setup(sessiondata)) {
			capwap_timeout_set(sessiondata->timeout, sessiondata->idtimercontrol, AC_DTLS_INTERVAL, NULL, NULL, NULL);
		} else {
			capwap_logging_debug("Unable to start DTLS data");
			sessiondata->running = 0;
		}
	} else {
		capwap_timeout_set(sessiondata->timeout, sessiondata->idtimerkeepalivedead, AC_MAX_DATA_KEEPALIVE_INTERVAL, NULL, NULL, NULL);
	}

	/* */
	while (sessiondata->running) {
		/* Get packet */
		length = ac_network_read(sessiondata, buffer, sizeof(buffer));
		if (length < 0) {
			if ((length == CAPWAP_ERROR_SHUTDOWN) || (length == CAPWAP_ERROR_CLOSE)) {
				break;		/* Close Session Data */
			}
		} else if (length > 0) {
			/* Check generic capwap packet */
			check = capwap_sanity_check(0, CAPWAP_UNDEF_STATE, buffer, length, 0, 0);
			if (check == CAPWAP_PLAIN_PACKET) {
				struct capwap_parsed_packet packet;

				/* Defragment management */
				if (!sessiondata->rxmngpacket) {
					sessiondata->rxmngpacket = capwap_packet_rxmng_create_message(CAPWAP_DATA_PACKET);
				}

				/* If request, defragmentation packet */
				check = capwap_packet_rxmng_add_recv_packet(sessiondata->rxmngpacket, buffer, length);
				if (check == CAPWAP_RECEIVE_COMPLETE_PACKET) {
					/* Validate message */
					if (capwap_check_message_type(sessiondata->rxmngpacket) == VALID_MESSAGE_TYPE) {
						/* Parsing packet */
						res = capwap_parsing_packet(sessiondata->rxmngpacket, &connection, &packet);
						if (res == PARSING_COMPLETE) {
							/* Validate packet */
							if (!capwap_validate_parsed_packet(&packet, NULL)) {
								if (IS_FLAG_K_HEADER(packet.rxmngpacket->header)) {
									ac_session_data_keepalive(sessiondata, &packet);

									/* Update timeout */
									capwap_timeout_set(sessiondata->timeout, sessiondata->idtimerkeepalivedead, AC_MAX_DATA_KEEPALIVE_INTERVAL, NULL, NULL, NULL);
								} else {
									bodypacketlength = capwap_packet_getdata(sessiondata->rxmngpacket, bodypacket, AC_BODY_PACKET_MAX_SIZE);

									/* Parsing body packet */
									if (bodypacketlength > 0) {
										radioid = GET_RID_HEADER(sessiondata->rxmngpacket->header);
										binding = GET_WBID_HEADER(sessiondata->rxmngpacket->header);
										if ((binding == CAPWAP_WIRELESS_BINDING_IEEE80211) && (bodypacketlength >= sizeof(struct ieee80211_header))) {
											ac_ieee80211_packet(sessiondata, radioid, (struct ieee80211_header*)bodypacket, bodypacketlength);
										}
									}
								}
							} else {
								capwap_logging_debug("Failed validation parsed data packet");
							}
						} else {
							capwap_logging_debug("Failed parsing data packet");
						}
					}

					/* Free memory */
					capwap_free_parsed_packet(&packet);
					capwap_packet_rxmng_free(sessiondata->rxmngpacket);
					sessiondata->rxmngpacket = NULL;
				} else if (check != CAPWAP_REQUEST_MORE_FRAGMENT) {
					/* Discard fragments */
					capwap_packet_rxmng_free(sessiondata->rxmngpacket);
					sessiondata->rxmngpacket = NULL;
				}
			}
		}
	}

	/* Release reference session data */
	ac_session_data_destroy(sessiondata);
}

/* */
void* ac_session_data_thread(void* param) {
	pthread_t threadid;
	struct ac_session_data_t* sessiondata = (struct ac_session_data_t*)param;

	ASSERT(param != NULL);

	threadid = sessiondata->threadid;

	/* */
	capwap_logging_debug("Session data start");
	ac_session_data_run(sessiondata);
	capwap_logging_debug("Session data end");

	/* Notify terminate thread */
	ac_msgqueue_notify_closethread(threadid);

	/* Thread exit */
	pthread_exit(NULL);
	return NULL;
}

/* */
void ac_session_data_send_data_packet(struct ac_session_data_t* sessiondata, uint8_t radioid, uint8_t wlanid, const uint8_t* data, int length, int leavenativeframe) {
	struct capwap_list* txfragpacket;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;

	/* Build packet */
	capwap_header_init(&capwapheader, radioid, sessiondata->session->binding);
	capwap_header_set_nativeframe_flag(&capwapheader, (leavenativeframe ? 1: 0));
	txmngpacket = capwap_packet_txmng_create_data_message(&capwapheader, sessiondata->mtu);

	/* */
	if (leavenativeframe) {
		capwap_packet_txmng_add_data(txmngpacket, data, length);
	} else {
		/* TODO */
	}

	/* Data message complete, get fragment packets into local list */
	txfragpacket = capwap_list_create();
	capwap_packet_txmng_get_fragment_packets(txmngpacket, txfragpacket, sessiondata->fragmentid);
	if (txfragpacket->count > 1) {
		sessiondata->fragmentid++;
	}

	/* */
	if (!capwap_crypt_sendto_fragmentpacket(&sessiondata->dtls, sessiondata->connection.socket.socket[sessiondata->connection.socket.type], txfragpacket, &sessiondata->connection.localaddr, &sessiondata->connection.remoteaddr)) {
		capwap_logging_debug("Warning: error to send data packet");
	}

	/* Free packets manager */
	capwap_list_free(txfragpacket);
	capwap_packet_txmng_free(txmngpacket);
}
