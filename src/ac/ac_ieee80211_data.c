#include "ac.h"
#include "ac_session.h"
#include "ac_wlans.h"

/* */
static void ac_ieee80211_mgmt_probe_request_packet(struct ac_session_data_t* sessiondata, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
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
static void ac_ieee80211_mgmt_authentication_packet(struct ac_session_data_t* sessiondata, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;
	struct ac_station* station;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->authetication));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->authetication.ie[0], ielength)) {
		return;
	}

	/* Create station if sent by station */
	if (memcmp(mgmt->bssid, mgmt->sa, MACADDRESS_EUI48_LENGTH)) {
		station = ac_stations_create_station(sessiondata->session, radioid, mgmt->bssid, mgmt->sa);

		/* */
		if (station->wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL) {
			/* TODO */
		} else if (station->wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
			/* TODO */
		}
	} else {
		station = ac_stations_get_station(sessiondata->session, radioid, mgmt->bssid, mgmt->da);
		if (station) {
			if (station->wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL) {
				/* TODO */
			} else if (station->wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
				/* TODO */
			}
		}
	}
}

/* */
static void ac_ieee80211_mgmt_association_request_packet(struct ac_session_data_t* sessiondata, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;
	struct ac_station* station;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->associationrequest));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->associationrequest.ie[0], ielength)) {
		return;
	}

	/* Get station */
	if (memcmp(mgmt->bssid, mgmt->sa, MACADDRESS_EUI48_LENGTH)) {
		station = ac_stations_get_station(sessiondata->session, radioid, mgmt->bssid, mgmt->sa);

		/* */
		if (station->wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL) {
			/* TODO */
		} else if (station->wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
			/* TODO */
		}
	} else {
		station = ac_stations_get_station(sessiondata->session, radioid, mgmt->bssid, mgmt->da);
		if (station) {
			if (station->wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL) {
				/* TODO */
			} else if (station->wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
				/* TODO */
			}
		}
	}
}

/* */
static void ac_ieee80211_mgmt_association_response_packet(struct ac_session_data_t* sessiondata, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;
	struct ac_station* station;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->associationresponse));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->associationresponse.ie[0], ielength)) {
		return;
	}

	/* Get station */
	station = ac_stations_get_station(sessiondata->session, radioid, mgmt->bssid, mgmt->sa);

	/* */
	if (station->wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_LOCAL) {
		/* TODO */
	} else if (station->wlan->macmode == CAPWAP_ADD_WLAN_MACMODE_SPLIT) {
		/* TODO */
	}
}

/* */
static void ac_ieee80211_mgmt_reassociation_request_packet(struct ac_session_data_t* sessiondata, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
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
static void ac_ieee80211_mgmt_reassociation_response_packet(struct ac_session_data_t* sessiondata, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
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
static void ac_ieee80211_mgmt_disassociation_packet(struct ac_session_data_t* sessiondata, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
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
static void ac_ieee80211_mgmt_deauthentication_packet(struct ac_session_data_t* sessiondata, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	const uint8_t* stationaddress;
	struct ieee80211_ie_items ieitems;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->deauthetication));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->deauthetication.ie[0], ielength)) {
		return;
	}

	/* Get station address */
	stationaddress = (memcmp(mgmt->bssid, mgmt->sa, MACADDRESS_EUI48_LENGTH) ? mgmt->sa : mgmt->da);

	/* Delete station */
	ac_stations_delete_station(sessiondata->session, stationaddress);
}

/* */
static void ac_ieee80211_mgmt_packet(struct ac_session_data_t* sessiondata, uint8_t radioid, const struct ieee80211_header_mgmt* mgmt, int mgmtlength, uint16_t framecontrol_subtype) {
	switch (framecontrol_subtype) {
		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_PROBE_REQUEST: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->proberequest))) {
				ac_ieee80211_mgmt_probe_request_packet(sessiondata, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTHENTICATION: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->authetication))) {
				ac_ieee80211_mgmt_authentication_packet(sessiondata, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_REQUEST: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->associationrequest))) {
				ac_ieee80211_mgmt_association_request_packet(sessiondata, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_RESPONSE: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->associationresponse))) {
				ac_ieee80211_mgmt_association_response_packet(sessiondata, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_REASSOCIATION_REQUEST: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->reassociationrequest))) {
				ac_ieee80211_mgmt_reassociation_request_packet(sessiondata, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_REASSOCIATION_RESPONSE: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->reassociationresponse))) {
				ac_ieee80211_mgmt_reassociation_response_packet(sessiondata, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DISASSOCIATION: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->disassociation))) {
				ac_ieee80211_mgmt_disassociation_packet(sessiondata, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTHENTICATION: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->deauthetication))) {
				ac_ieee80211_mgmt_deauthentication_packet(sessiondata, radioid, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ACTION: {
			break;
		}
	}
}

/* */
void ac_ieee80211_packet(struct ac_session_data_t* sessiondata, uint8_t radioid, const uint8_t* buffer, int length) {
	const struct ieee80211_header* header;
	uint16_t framecontrol;
	uint16_t framecontrol_type;
	uint16_t framecontrol_subtype;

	ASSERT(sessiondata != NULL);
	ASSERT(IS_VALID_RADIOID(radioid));
	ASSERT(buffer != NULL);
	ASSERT(length >= sizeof(struct ieee80211_header));

	/* Get type frame */
	header = (const struct ieee80211_header*)buffer;
	framecontrol = __le16_to_cpu(header->framecontrol);
	framecontrol_type = IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol);
	framecontrol_subtype = IEEE80211_FRAME_CONTROL_GET_SUBTYPE(framecontrol);

	/* Parsing frame */
	if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_MGMT) {
		ac_ieee80211_mgmt_packet(sessiondata, radioid, (const struct ieee80211_header_mgmt*)buffer, length, framecontrol_subtype);
	}
}
