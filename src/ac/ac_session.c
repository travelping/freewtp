#include <stdarg.h>
#include "ac.h"
#include "capwap_dfa.h"
#include "ac_session.h"
#include "ac_wlans.h"
#include "ac_backend.h"
#include <arpa/inet.h>

#define AC_NO_ERROR						-1000
#define AC_ERROR_TIMEOUT				-1001

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
	if (capwap_crypt_sendto_fragmentpacket(&session->dtls, session->requestfragmentpacket)) {
		session->retransmitcount = 0;
		ac_dfa_change_state(session, CAPWAP_RESET_STATE);
		capwap_timeout_set(session->timeout, session->idtimercontrol, AC_RETRANSMIT_INTERVAL, ac_dfa_retransmition_timeout, session, NULL);
	} else {
		capwap_logging_debug("Warning: error to send Reset Request packet");
		ac_free_reference_last_request(session);
		ac_session_teardown(session);
	}

	return AC_NO_ERROR;
}

/* */
static int ac_session_action_addwlan(struct ac_session_t* session, struct ac_notify_addwlan_t* notify) {
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_80211_addwlan_element addwlan;

	ASSERT(session->requestfragmentpacket->count == 0);

	/* Check if WLAN id is valid and not used */
	if (!IS_VALID_RADIOID(notify->radioid) || !IS_VALID_WLANID(notify->wlanid)) {
		return AC_NO_ERROR;
#if 0
	} else if (ac_wlans_get_bssid_with_wlanid(session, notify->radioid, notify->wlanid)) {
		return AC_NO_ERROR;
#endif
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
	if (capwap_crypt_sendto_fragmentpacket(&session->dtls, session->requestfragmentpacket)) {
		session->retransmitcount = 0;
		capwap_timeout_set(session->timeout, session->idtimercontrol, AC_RETRANSMIT_INTERVAL, ac_dfa_retransmition_timeout, session, NULL);
	} else {
		capwap_logging_debug("Warning: error to send WLAN Configuration Request packet");
		ac_free_reference_last_request(session);
		ac_session_teardown(session);
	}

	return AC_NO_ERROR;
}

/* */
static int ac_session_action_station_configuration_ieee8011_add_station(struct ac_session_t* session, struct ac_notify_station_configuration_ieee8011_add_station* notify) {
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_addstation_element addstation;
	struct capwap_80211_station_element station;

	ASSERT(session->requestfragmentpacket->count == 0);

	/* Check if RADIO id and WLAN id is valid */
	if (!IS_VALID_RADIOID(notify->radioid) || !IS_VALID_WLANID(notify->wlanid)) {
		return AC_NO_ERROR;
	}

	/* */
	memset(&addstation, 0, sizeof(struct capwap_addstation_element));
	addstation.radioid = notify->radioid;
	addstation.length = MACADDRESS_EUI48_LENGTH;
	addstation.address = notify->address;
	if (notify->vlan[0]) {
		addstation.vlan = notify->vlan;
	}

	/* */
	memset(&station, 0, sizeof(struct capwap_80211_station_element));
	station.radioid = notify->radioid;
	station.associationid = notify->associationid;
	memcpy(station.address, notify->address, MACADDRESS_EUI48_LENGTH);
	station.capabilities = notify->capabilities;
	station.wlanid = notify->wlanid;
	station.supportedratescount = notify->supportedratescount;
	memcpy(station.supportedrates, notify->supportedrates, station.supportedratescount);

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, session->binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_STATION_CONFIGURATION_REQUEST, session->localseqnumber++, session->mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ADDSTATION, &addstation);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_STATION, &station);

	/* CAPWAP_ELEMENT_VENDORPAYLOAD */				/* TODO */

	/* Station Configuration Request complete, get fragment packets */
	capwap_packet_txmng_get_fragment_packets(txmngpacket, session->requestfragmentpacket, session->fragmentid);
	if (session->requestfragmentpacket->count > 1) {
		session->fragmentid++;
	}

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send Station Configuration Request to WTP */
	if (capwap_crypt_sendto_fragmentpacket(&session->dtls, session->requestfragmentpacket)) {
		session->retransmitcount = 0;
		capwap_timeout_set(session->timeout, session->idtimercontrol, AC_RETRANSMIT_INTERVAL, ac_dfa_retransmition_timeout, session, NULL);
	} else {
		capwap_logging_debug("Warning: error to send Station Configuration Request packet");
		ac_free_reference_last_request(session);
		ac_session_teardown(session);
	}

	return AC_NO_ERROR;
}

/* */
static int ac_session_action_station_configuration_ieee8011_delete_station(struct ac_session_t* session, struct ac_notify_station_configuration_ieee8011_delete_station* notify) {
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_deletestation_element deletestation;

	ASSERT(session->requestfragmentpacket->count == 0);

	/* Check if RADIO id is valid */
	if (!IS_VALID_RADIOID(notify->radioid)) {
		return AC_NO_ERROR;
	}

	/* */
	memset(&deletestation, 0, sizeof(struct capwap_deletestation_element));
	deletestation.radioid = notify->radioid;
	deletestation.length = MACADDRESS_EUI48_LENGTH;
	deletestation.address = notify->address;

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, session->binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_STATION_CONFIGURATION_REQUEST, session->localseqnumber++, session->mtu);

	/* Add message element */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_DELETESTATION, &deletestation);
	/* CAPWAP_ELEMENT_VENDORPAYLOAD */				/* TODO */

	/* Station Configuration Request complete, get fragment packets */
	capwap_packet_txmng_get_fragment_packets(txmngpacket, session->requestfragmentpacket, session->fragmentid);
	if (session->requestfragmentpacket->count > 1) {
		session->fragmentid++;
	}

	/* Free packets manager */
	capwap_packet_txmng_free(txmngpacket);

	/* Send Station Configuration Request to WTP */
	if (capwap_crypt_sendto_fragmentpacket(&session->dtls, session->requestfragmentpacket)) {
		session->retransmitcount = 0;
		capwap_timeout_set(session->timeout, session->idtimercontrol, AC_RETRANSMIT_INTERVAL, ac_dfa_retransmition_timeout, session, NULL);
	} else {
		capwap_logging_debug("Warning: error to send Station Configuration Request packet");
		ac_free_reference_last_request(session);
		ac_session_teardown(session);
	}

	return AC_NO_ERROR;
}

/* */
static int ac_session_action_recv_ieee80211_mgmt_packet(struct ac_session_t* session, struct capwap_header* header, long length) {
	long headersize;

	/* Retrieve info */
	headersize = GET_HLEN_HEADER(header) * 4;
	if ((GET_WBID_HEADER(header) == CAPWAP_WIRELESS_BINDING_IEEE80211) && ((length - headersize) >= sizeof(struct ieee80211_header))) {
		ac_ieee80211_packet(session, GET_RID_HEADER(header), (struct ieee80211_header*)(((char*)header) + headersize), (length - headersize));
	}

	return AC_NO_ERROR;
}

/* */
static int ac_session_action_execute(struct ac_session_t* session, struct ac_session_action* action) {
	int result = AC_NO_ERROR;

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

		case AC_SESSION_ACTION_RECV_KEEPALIVE: {
#ifdef DEBUG
			{
				char sessionname[33];
				capwap_sessionid_printf(&session->sessionid, sessionname);
				capwap_logging_debug("Receive Keep-Alive from %s", sessionname);
			}
#endif
			/* Send keep-alive response */
			ac_kmod_send_keepalive(&session->sockaddrdata.ss);
			capwap_timeout_set(session->timeout, session->idtimerkeepalivedead, AC_MAX_DATA_KEEPALIVE_INTERVAL, ac_dfa_teardown_timeout, session, NULL);

			/* */
			if (session->state == CAPWAP_DATA_CHECK_TO_RUN_STATE) {
				struct ac_soap_response* response;

				/* Capwap handshake complete, notify event to backend */
				response = ac_soap_runningwtpsession(session, session->wtpid);
				if (response) {
					if (response->responsecode == HTTP_RESULT_OK) {
						ac_dfa_change_state(session, CAPWAP_RUN_STATE);
						capwap_timeout_set(session->timeout, session->idtimercontrol, AC_MAX_ECHO_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
					} else {
						result = CAPWAP_ERROR_CLOSE;
					}

					ac_soapclient_free_response(response);
				} else {
					result = CAPWAP_ERROR_CLOSE;
				}
			}

			break;
		}

		case AC_SESSION_ACTION_RECV_IEEE80211_MGMT_PACKET: {
			result = ac_session_action_recv_ieee80211_mgmt_packet(session, (struct capwap_header*)action->data, action->length);
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

		case AC_SESSION_ACTION_STATION_CONFIGURATION_IEEE80211_ADD_STATION: {
			result = ac_session_action_station_configuration_ieee8011_add_station(session, (struct ac_notify_station_configuration_ieee8011_add_station*)action->data);
			break;
		}

		case AC_SESSION_ACTION_STATION_CONFIGURATION_IEEE80211_DELETE_STATION: {
			result = ac_session_action_station_configuration_ieee8011_delete_station(session, (struct ac_notify_station_configuration_ieee8011_delete_station*)action->data);
			break;
		}

		case AC_SESSION_ACTION_STATION_ROAMING: {
			struct ac_station* station;

			/* Delete station */
			station = ac_stations_get_station(session, RADIOID_ANY, NULL, (uint8_t*)action->data);
			if (station) {
				ac_stations_delete_station(session, station);
			}

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
								capwap_timeout_set(session->timeout, session->idtimercontrol, AC_JOIN_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
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
	capwap_crypt_sendto_fragmentpacket(&session->dtls, responsefragmentpacket);

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

	/* Close data channel */
	ac_kmod_delete_datasession(&session->sockaddrdata.ss, &session->sessionid);

	/* Free DTSL Control */
	capwap_crypt_freesession(&session->dtls);

	/* Free resource */
	while (session->packets->count > 0) {
		capwap_itemlist_free(capwap_itemlist_remove_head(session->packets));
	}

	/* Free WLANS */
	ac_wlans_destroy(session);

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
static void ac_session_run(struct ac_session_t* session) {
	int res;
	int check;
	int length;
	struct capwap_list_item* search;
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
		capwap_timeout_set(session->timeout, session->idtimercontrol, AC_JOIN_INTERVAL, ac_dfa_teardown_timeout, session, NULL);
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
			check = capwap_sanity_check(CAPWAP_UNDEF_STATE, buffer, length, 0);
			if (check == CAPWAP_PLAIN_PACKET) {
				struct capwap_parsed_packet packet;

				/* Defragment management */
				if (!session->rxmngpacket) {
					session->rxmngpacket = capwap_packet_rxmng_create_message();
				}

				/* If request, defragmentation packet */
				check = capwap_packet_rxmng_add_recv_packet(session->rxmngpacket, buffer, length);
				if (check == CAPWAP_RECEIVE_COMPLETE_PACKET) {
					/* Receive all fragment */
					if (capwap_is_request_type(session->rxmngpacket->ctrlmsg.type) && (session->remotetype == session->rxmngpacket->ctrlmsg.type) && (session->remoteseqnumber == session->rxmngpacket->ctrlmsg.seq)) {
						/* Retransmit response */
						if (!capwap_crypt_sendto_fragmentpacket(&session->dtls, session->responsefragmentpacket)) {
							capwap_logging_error("Error to resend response packet");
						} else {
							capwap_logging_debug("Retrasmitted control packet");
						}
					} else {
						/* Check message type */
						res = capwap_check_message_type(session->rxmngpacket);
						if (res == VALID_MESSAGE_TYPE) {
							res = capwap_parsing_packet(session->rxmngpacket, &packet);
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

	/* Remove timer */
	if (session->idtimercontrol != CAPWAP_TIMEOUT_INDEX_NO_SET) {
		capwap_timeout_unset(session->timeout, session->idtimercontrol);
		session->idtimercontrol = CAPWAP_TIMEOUT_INDEX_NO_SET;
	}

	if (session->idtimerkeepalivedead != CAPWAP_TIMEOUT_INDEX_NO_SET) {
		capwap_timeout_unset(session->timeout, session->idtimerkeepalivedead);
		session->idtimerkeepalivedead = CAPWAP_TIMEOUT_INDEX_NO_SET;
	}

	/* */
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
	ac_msgqueue_notify_closethread(threadid);

	/* Thread exit */
	pthread_exit(NULL);
	return NULL;
}

/* */
void ac_get_control_information(struct capwap_list* controllist) {
	int count;
	struct capwap_list_item* item;

	ASSERT(controllist != NULL);

	/* */
	capwap_rwlock_rdlock(&g_ac.sessionslock);
	count = g_ac.sessions->count;
	capwap_rwlock_exit(&g_ac.sessionslock);

	/* Prepare control list */
	for (item = g_ac.addrlist->first; item != NULL; item = item->next) {
		struct capwap_list_item* itemcontrol;
		struct ac_session_control* sessioncontrol;
		union sockaddr_capwap* address = (union sockaddr_capwap*)item->item;

		/* */
		itemcontrol = capwap_itemlist_create(sizeof(struct ac_session_control));
		sessioncontrol = (struct ac_session_control*)itemcontrol->item;
		memcpy(&sessioncontrol->localaddress, address, sizeof(union sockaddr_capwap));
		sessioncontrol->count = count;

		/* Add */
		capwap_itemlist_insert_after(controllist, NULL, itemcontrol);
	}
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
	session->remotetype = 0;
	session->remoteseqnumber = 0;
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
		capwap_logging_warning("Invalid retransmition request packet");
		ac_session_teardown(session);
	} else {
		session->retransmitcount++;
		if (session->retransmitcount >= AC_MAX_RETRANSMIT) {
			capwap_logging_info("Retransmition request packet timeout");

			/* Timeout reset state */
			ac_free_reference_last_request(session);
			ac_session_teardown(session);
		} else {
			/* Retransmit Request */
			capwap_logging_debug("Retransmition request packet");
			if (!capwap_crypt_sendto_fragmentpacket(&session->dtls, session->requestfragmentpacket)) {
				capwap_logging_error("Error to send request packet");
			}

			/* Update timeout */
			capwap_timeout_set(session->timeout, session->idtimercontrol, AC_RETRANSMIT_INTERVAL, ac_dfa_retransmition_timeout, session, NULL);
		}
	}
}

void ac_dfa_teardown_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param) {
	capwap_logging_info("Session timeout, teardown");
	ac_session_teardown((struct ac_session_t*)context);
}
