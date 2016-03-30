#include "ac.h"
#include "ac_session.h"
#include "ac_wlans.h"

/* */
static void ac_ieee80211_mgmt_probe_request_packet(struct ac_session_t* session, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;

	/* Accept probe request only if not sent by WTP */
	if (!memcmp(mgmt->bssid, mgmt->sa, MACADDRESS_EUI48_LENGTH)) {
		return;
	}

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->proberequest));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->proberequest.ie[0], ielength)) {
		return;
	}

	/* TODO */
}

/* */
static void ac_ieee80211_mgmt_authentication_packet(struct ac_session_t* session, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;
	struct ac_station* station;
	struct ac_wlan* wlan;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->authetication));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->authetication.ie[0], ielength)) {
		return;
	}

	/* */
	if (memcmp(mgmt->bssid, mgmt->sa, MACADDRESS_EUI48_LENGTH) && !memcmp(mgmt->bssid, mgmt->da, MACADDRESS_EUI48_LENGTH)) {
		station = ac_stations_create_station(session, radioid, mgmt->bssid, mgmt->sa);
		if (!station || !station->wlan) {
			return;
		}

		/* */
		log_printf(LOG_INFO, "Receive IEEE802.11 Authentication Request from %s station", station->addrtext);

		/* A station is removed if the association does not complete within a given period of time */
		station->timeoutaction = AC_STATION_TIMEOUT_ACTION_DEAUTHENTICATE;
		station->idtimeout = capwap_timeout_set(session->timeout, station->idtimeout, AC_STATION_TIMEOUT_ASSOCIATION_COMPLETE, ac_stations_timeout, station, session);

		/* */
		wlan = station->wlan;
		if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL) {
			/* TODO */
		} else if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
			uint16_t algorithm;
			uint16_t transactionseqnumber;
			uint16_t responsestatuscode;
			uint8_t buffer[IEEE80211_MTU];
			struct ieee80211_authentication_params ieee80211_params;
			int responselength;

			/* Parsing Information Elements */
			if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->authetication.ie[0], ielength)) {
				log_printf(LOG_INFO, "Invalid IEEE802.11 Authentication Request from %s station", station->addrtext);
				return;
			}

			/* */
			algorithm = __le16_to_cpu(mgmt->authetication.algorithm);
			transactionseqnumber = __le16_to_cpu(mgmt->authetication.transactionseqnumber);

			/* */
			responsestatuscode = IEEE80211_STATUS_NOT_SUPPORTED_AUTHENTICATION_ALGORITHM;
			if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_OPEN) && (wlan->authmode == CAPWAP_ADD_WLAN_AUTHTYPE_OPEN)) {
				if (transactionseqnumber == 1) {
					responsestatuscode = IEEE80211_STATUS_SUCCESS;
					station->authalgorithm = IEEE80211_AUTHENTICATION_ALGORITHM_OPEN;
				} else {
					responsestatuscode = IEEE80211_STATUS_UNKNOWN_AUTHENTICATION_TRANSACTION;
				}
			} else if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_SHARED_KEY) && (wlan->authmode == CAPWAP_ADD_WLAN_AUTHTYPE_WEP)) {
				/* TODO */
			}

			/* Create authentication packet */
			memset(&ieee80211_params, 0, sizeof(struct ieee80211_authentication_params));
			memcpy(ieee80211_params.bssid, wlan->address, MACADDRESS_EUI48_LENGTH);
			memcpy(ieee80211_params.station, mgmt->sa, MACADDRESS_EUI48_LENGTH);
			ieee80211_params.algorithm = algorithm;
			ieee80211_params.transactionseqnumber = transactionseqnumber + 1;
			ieee80211_params.statuscode = responsestatuscode;

			responselength = ieee80211_create_authentication_response(buffer, sizeof(buffer), &ieee80211_params);
			if (responselength > 0) {
				/* Send authentication response */
				if (!ac_kmod_send_data(&session->sessionid, wlan->device->radioid, session->binding, buffer, responselength)) {
					log_printf(LOG_INFO, "Sent IEEE802.11 Authentication Response to %s station with %d status code", station->addrtext, (int)responsestatuscode);
					station->flags |= AC_STATION_FLAGS_AUTHENTICATED;
				} else {
					log_printf(LOG_WARNING, "Unable to send IEEE802.11 Authentication Response to %s station", station->addrtext);
					ac_stations_delete_station(session, station);
				}
			} else {
				log_printf(LOG_WARNING, "Unable to create IEEE802.11 Authentication Response to %s station", station->addrtext);
				ac_stations_delete_station(session, station);
			}
		}
	} else if (!memcmp(mgmt->bssid, mgmt->sa, MACADDRESS_EUI48_LENGTH) && memcmp(mgmt->bssid, mgmt->da, MACADDRESS_EUI48_LENGTH)) {
		station = ac_stations_get_station(session, radioid, mgmt->bssid, mgmt->da);
		if (station && station->wlan && (station->wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL)) {
			uint16_t algorithm;
			uint16_t transactionseqnumber;
			uint16_t statuscode;

			/* */
			statuscode = __le16_to_cpu(mgmt->authetication.statuscode);

			/* */
			log_printf(LOG_INFO, "Receive IEEE802.11 Authentication Response to %s station with %d status code", station->addrtext, (int)statuscode);

			if (statuscode == IEEE80211_STATUS_SUCCESS) {
				algorithm = __le16_to_cpu(mgmt->authetication.algorithm);
				transactionseqnumber = __le16_to_cpu(mgmt->authetication.transactionseqnumber);

				/* Check if authenticate */
				if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_OPEN) && (transactionseqnumber == 2)) {
					station->flags |= AC_STATION_FLAGS_AUTHENTICATED;
				} else if ((algorithm == IEEE80211_AUTHENTICATION_ALGORITHM_SHARED_KEY) && (transactionseqnumber == 4)) {
					/* TODO */
				}
			}
		}
	}
}

/* */
static void ac_ieee80211_mgmt_association_request_packet(struct ac_session_t* session, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;
	struct ac_station* station;
	struct ac_wlan* wlan;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->associationrequest));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->associationrequest.ie[0], ielength)) {
		return;
	}

	/* Get station */
	if (memcmp(mgmt->bssid, mgmt->sa, MACADDRESS_EUI48_LENGTH) && !memcmp(mgmt->bssid, mgmt->da, MACADDRESS_EUI48_LENGTH)) {
		station = ac_stations_get_station(session, radioid, mgmt->bssid, mgmt->sa);
		if (!station || !station->wlan) {
			return;
		}

		/* */
		log_printf(LOG_INFO, "Receive IEEE802.11 Association Request from %s station", station->addrtext);

		/* */
		wlan = station->wlan;
		if (!(station->flags & AC_STATION_FLAGS_AUTHENTICATED)) {
			/* Invalid station, delete station */
			log_printf(LOG_INFO, "Receive IEEE802.11 Association Request from %s unauthorized station", station->addrtext);
			ac_stations_delete_station(session, station);
			return;
		}

		/* Get Station Info */
		station->capability = __le16_to_cpu(mgmt->associationrequest.capability);
		station->listeninterval = __le16_to_cpu(mgmt->associationrequest.listeninterval);

		/* Get supported rates */
		if (ieitems.supported_rates && ((ieitems.supported_rates->len + (ieitems.extended_supported_rates ? ieitems.extended_supported_rates->len : 0)) <= sizeof(station->supportedrates))) {
			station->supportedratescount = ieitems.supported_rates->len;
			memcpy(station->supportedrates, ieitems.supported_rates->rates, ieitems.supported_rates->len);
			if (ieitems.extended_supported_rates) {
				station->supportedratescount += ieitems.extended_supported_rates->len;
				memcpy(&station->supportedrates[ieitems.supported_rates->len], ieitems.extended_supported_rates->rates, ieitems.extended_supported_rates->len);
			}

			/* */
			if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL) {
				/* TODO */
			} else if (wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
				int responselength;
				struct ieee80211_ie_items ieitems;
				struct ieee80211_associationresponse_params ieee80211_params;
				uint16_t resultstatuscode;
				uint8_t buffer[IEEE80211_MTU];

				/* Parsing Information Elements */
				if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->associationrequest.ie[0], ielength)) {
					log_printf(LOG_INFO, "Invalid IEEE802.11 Association Request from %s station", station->addrtext);
					ac_stations_delete_station(session, station);
					return;
				}

				/* Verify SSID */
				if (ieee80211_is_valid_ssid(wlan->ssid, ieitems.ssid, NULL) != IEEE80211_VALID_SSID) {
					resultstatuscode = IEEE80211_STATUS_UNSPECIFIED_FAILURE;
				} else {
					/* Check supported rates */
					if (!ieitems.supported_rates || ((ieitems.supported_rates->len + (ieitems.extended_supported_rates ? ieitems.extended_supported_rates->len : 0)) > sizeof(station->supportedrates))) {
						resultstatuscode = IEEE80211_STATUS_UNSPECIFIED_FAILURE;
					} else {
						station->capability = __le16_to_cpu(mgmt->associationrequest.capability);
						station->listeninterval = __le16_to_cpu(mgmt->associationrequest.listeninterval);
						if (ieee80211_aid_create(wlan->aidbitfield, &station->aid)) {
							resultstatuscode = IEEE80211_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
						} else {
							/* Get supported rates */
							station->supportedratescount = ieitems.supported_rates->len;
							memcpy(station->supportedrates, ieitems.supported_rates->rates, ieitems.supported_rates->len);
							if (ieitems.extended_supported_rates) {
								station->supportedratescount += ieitems.extended_supported_rates->len;
								memcpy(&station->supportedrates[ieitems.supported_rates->len], ieitems.extended_supported_rates->rates, ieitems.extended_supported_rates->len);
							}

							/* */
							resultstatuscode = IEEE80211_STATUS_SUCCESS;
						}
					}
				}

				/* Create association response packet */
				memset(&ieee80211_params, 0, sizeof(struct ieee80211_authentication_params));
				memcpy(ieee80211_params.bssid, wlan->address, ETH_ALEN);
				memcpy(ieee80211_params.station, mgmt->sa, ETH_ALEN);
				ieee80211_params.capability = wlan->capability;
				ieee80211_params.statuscode = resultstatuscode;
				ieee80211_params.aid = IEEE80211_AID_FIELD | station->aid;
				memcpy(ieee80211_params.supportedrates, wlan->device->supportedrates, wlan->device->supportedratescount);
				ieee80211_params.supportedratescount = wlan->device->supportedratescount;

				responselength = ieee80211_create_associationresponse_response(buffer, sizeof(buffer), &ieee80211_params);
				if (responselength > 0) {
					/* Send association response */
					if (!ac_kmod_send_data(&session->sessionid, wlan->device->radioid, session->binding, buffer, responselength)) {
						log_printf(LOG_INFO, "Sent IEEE802.11 Association Response to %s station with %d status code", station->addrtext, (int)resultstatuscode);

						/* Active Station */
						station->flags |= AC_STATION_FLAGS_ASSOCIATE;
						ac_stations_authorize_station(session, station);
					} else {
						log_printf(LOG_WARNING, "Unable to send IEEE802.11 Association Response to %s station", station->addrtext);
						ac_stations_delete_station(session, station);
					}
				} else {
					log_printf(LOG_WARNING, "Unable to create IEEE802.11 Association Response to %s station", station->addrtext);
					ac_stations_delete_station(session, station);
				}
			}
		}
	}
}

/* */
static void ac_ieee80211_mgmt_association_response_packet(struct ac_session_t* session, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;
	struct ac_station* station;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->associationresponse));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->associationresponse.ie[0], ielength)) {
		return;
	}

	/* Get station */
	if (!memcmp(mgmt->bssid, mgmt->sa, MACADDRESS_EUI48_LENGTH) && memcmp(mgmt->bssid, mgmt->da, MACADDRESS_EUI48_LENGTH)) {
		station = ac_stations_get_station(session, radioid, mgmt->bssid, mgmt->da);
		if (station && station->wlan && (station->wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL)) {
			log_printf(LOG_INFO, "Receive IEEE802.11 Association Response to %s station with %d status code", station->addrtext, (int)mgmt->associationresponse.statuscode);

			if (mgmt->associationresponse.statuscode == IEEE80211_STATUS_SUCCESS) {
				/* Get Station Info */
				station->capability = __le16_to_cpu(mgmt->associationresponse.capability);
				station->aid = __le16_to_cpu(mgmt->associationresponse.aid);
				station->flags |= AC_STATION_FLAGS_ASSOCIATE;

				/* Get supported rates */
				if (ieitems.supported_rates && ((ieitems.supported_rates->len + (ieitems.extended_supported_rates ? ieitems.extended_supported_rates->len : 0)) <= sizeof(station->supportedrates))) {
					station->supportedratescount = ieitems.supported_rates->len;
					memcpy(station->supportedrates, ieitems.supported_rates->rates, ieitems.supported_rates->len);
					if (ieitems.extended_supported_rates) {
						station->supportedratescount += ieitems.extended_supported_rates->len;
						memcpy(&station->supportedrates[ieitems.supported_rates->len], ieitems.extended_supported_rates->rates, ieitems.extended_supported_rates->len);
					}

					/* Active Station */
					ac_stations_authorize_station(session, station);
				}
			}
		}
	}
}

/* */
static void ac_ieee80211_mgmt_reassociation_request_packet(struct ac_session_t* session, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->reassociationrequest));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->reassociationrequest.ie[0], ielength)) {
		return;
	}

	/* TODO */
}

/* */
static void ac_ieee80211_mgmt_reassociation_response_packet(struct ac_session_t* session, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->reassociationresponse));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->reassociationresponse.ie[0], ielength)) {
		return;
	}

	/* TODO */
}

/* */
static void ac_ieee80211_mgmt_disassociation_packet(struct ac_session_t* session, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->disassociation));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->disassociation.ie[0], ielength)) {
		return;
	}

	/* TODO */
}

/* */
static void ac_ieee80211_mgmt_deauthentication_packet(struct ac_session_t* session, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	const uint8_t* stationaddress;
	struct ac_station* station;
	struct ieee80211_ie_items ieitems;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->deauthetication));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->deauthetication.ie[0], ielength)) {
		return;
	}

	/* Get station address */
	stationaddress = (memcmp(mgmt->bssid, mgmt->sa, MACADDRESS_EUI48_LENGTH) ? mgmt->sa : mgmt->da);

	/* Delete station */
	station = ac_stations_get_station(session, radioid, NULL, stationaddress);
	if (station) {
		/* Delete station without forward another IEEE802.11 deauthentication message */
		station->flags &= ~(AC_STATION_FLAGS_AUTHENTICATED | AC_STATION_FLAGS_ASSOCIATE);
		ac_stations_delete_station(session, station);
	}
}

/* */
static void ac_ieee80211_mgmt_packet(struct ac_session_t* session, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength, uint16_t framecontrol_subtype) {
	switch (framecontrol_subtype) {
		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_PROBE_REQUEST: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->proberequest))) {
				ac_ieee80211_mgmt_probe_request_packet(session, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTHENTICATION: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->authetication))) {
				ac_ieee80211_mgmt_authentication_packet(session, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_REQUEST: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->associationrequest))) {
				ac_ieee80211_mgmt_association_request_packet(session, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_RESPONSE: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->associationresponse))) {
				ac_ieee80211_mgmt_association_response_packet(session, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_REASSOCIATION_REQUEST: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->reassociationrequest))) {
				ac_ieee80211_mgmt_reassociation_request_packet(session, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_REASSOCIATION_RESPONSE: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->reassociationresponse))) {
				ac_ieee80211_mgmt_reassociation_response_packet(session, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DISASSOCIATION: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->disassociation))) {
				ac_ieee80211_mgmt_disassociation_packet(session, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTHENTICATION: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->deauthetication))) {
				ac_ieee80211_mgmt_deauthentication_packet(session, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ACTION: {
			break;
		}
	}
}

/* */
void ac_ieee80211_packet(struct ac_session_t* session, uint8_t radioid, const struct ieee80211_header* header, int length) {
	uint16_t framecontrol;
	uint16_t framecontrol_type;
	uint16_t framecontrol_subtype;

	ASSERT(session != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(header != NULL);
	ASSERT(length >= sizeof(struct ieee80211_header));

	/* Get type frame */
	framecontrol = __le16_to_cpu(header->framecontrol);
	framecontrol_type = IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol);
	framecontrol_subtype = IEEE80211_FRAME_CONTROL_GET_SUBTYPE(framecontrol);

	/* Parsing frame */
	if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_MGMT) {
		ac_ieee80211_mgmt_packet(session, radioid, (const struct ieee80211_header_mgmt*)header, length, framecontrol_subtype);
	}
}
