#include "ac.h"
#include "ac_session.h"
#include "ieee80211.h"

/* */
static void ac_ieee80211_mgmt_probe_request_packet(struct ac_session_data_t* sessiondata, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->proberequest));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->proberequest.ie[0], ielength)) {
		return;
	}

	/* TODO */
}

/* */
static void ac_ieee80211_mgmt_authentication_packet(struct ac_session_data_t* sessiondata, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->proberequest));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->proberequest.ie[0], ielength)) {
		return;
	}

	/* TODO */
}

/* */
static void ac_ieee80211_mgmt_association_request_packet(struct ac_session_data_t* sessiondata, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->proberequest));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->proberequest.ie[0], ielength)) {
		return;
	}

	/* TODO */
}

/* */
static void ac_ieee80211_mgmt_reassociation_request_packet(struct ac_session_data_t* sessiondata, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->proberequest));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->proberequest.ie[0], ielength)) {
		return;
	}

	/* TODO */
}

/* */
static void ac_ieee80211_mgmt_disassociation_packet(struct ac_session_data_t* sessiondata, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->proberequest));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->proberequest.ie[0], ielength)) {
		return;
	}

	/* TODO */
}

/* */
static void ac_ieee80211_mgmt_deauthentication_packet(struct ac_session_data_t* sessiondata, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	int ielength;
	struct ieee80211_ie_items ieitems;

	/* Parsing Information Elements */
	ielength = mgmtlength - (sizeof(struct ieee80211_header) + sizeof(mgmt->proberequest));
	if (ieee80211_retrieve_information_elements_position(&ieitems, &mgmt->proberequest.ie[0], ielength)) {
		return;
	}

	/* TODO */
}

/* */
static void ac_ieee80211_mgmt_packet(struct ac_session_data_t* sessiondata, const struct ieee80211_header_mgmt* mgmt, int mgmtlength, uint16_t framecontrol_subtype) {
	switch (framecontrol_subtype) {
		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_PROBE_REQUEST: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->proberequest))) {
				ac_ieee80211_mgmt_probe_request_packet(sessiondata, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTHENTICATION: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->authetication))) {
				ac_ieee80211_mgmt_authentication_packet(sessiondata, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_REQUEST: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->associationrequest))) {
				ac_ieee80211_mgmt_association_request_packet(sessiondata, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_REASSOCIATION_REQUEST: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->reassociationrequest))) {
				ac_ieee80211_mgmt_reassociation_request_packet(sessiondata, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DISASSOCIATION: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->disassociation))) {
				ac_ieee80211_mgmt_disassociation_packet(sessiondata, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTHENTICATION: {
			if (mgmtlength >= (sizeof(struct ieee80211_header) + sizeof(mgmt->deauthetication))) {
				ac_ieee80211_mgmt_deauthentication_packet(sessiondata, mgmt, mgmtlength);
			}

			break;
		}

		case IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ACTION: {
			break;
		}
	}
}

/* */
void ac_ieee80211_packet(struct ac_session_data_t* sessiondata, const uint8_t* buffer, int length) {
	const struct ieee80211_header* header;
	uint16_t framecontrol;
	uint16_t framecontrol_type;
	uint16_t framecontrol_subtype;

	ASSERT(sessiondata != NULL);
	ASSERT(buffer != NULL);
	ASSERT(length >= sizeof(struct ieee80211_header));

	/* Get type frame */
	header = (const struct ieee80211_header*)buffer;
	framecontrol = __le16_to_cpu(header->framecontrol);
	framecontrol_type = IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol);
	framecontrol_subtype = IEEE80211_FRAME_CONTROL_GET_SUBTYPE(framecontrol);

	/* Parsing frame */
	if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_MGMT) {
		ac_ieee80211_mgmt_packet(sessiondata, (const struct ieee80211_header_mgmt*)buffer, length, framecontrol_subtype);
	}
}
