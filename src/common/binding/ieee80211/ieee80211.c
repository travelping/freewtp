#include "capwap.h"
#include "ieee80211.h"

/* */
static int ieee80211_ie_set_ssid(uint8_t* buffer, const char* ssid, int hidessid) {
	struct ieee80211_ie_ssid* iessid = (struct ieee80211_ie_ssid*)buffer;

	ASSERT(buffer != NULL);
	ASSERT(ssid != NULL);

	iessid->id = IEEE80211_IE_SSID;
	if (hidessid) {
		iessid->len = 0;
	} else {
		iessid->len = strlen(ssid);
		if (iessid->len > IEEE80211_IE_SSID_MAX_LENGTH) {
			return -1;
		}

		strncpy((char*)iessid->ssid, ssid, iessid->len);
	}

	return sizeof(struct ieee80211_ie_ssid) + iessid->len;
}

/* */
static int ieee80211_ie_set_supportedrates(uint8_t* buffer, uint8_t* supportedrates, int supportedratescount) {
	int i;
	int count;
	struct ieee80211_ie_supported_rates* iesupportedrates = (struct ieee80211_ie_supported_rates*)buffer;

	ASSERT(buffer != NULL);
	ASSERT(supportedrates != NULL);
	ASSERT(supportedratescount > 0);

	/* IE accept max only 8 rate */
	count = supportedratescount;
	if (count > 8) {
		count = 8;
	}

	/* */
	iesupportedrates->id = IEEE80211_IE_SUPPORTED_RATES;
	iesupportedrates->len = count;

	for (i = 0; i < count; i++) {
		iesupportedrates->rates[i] = supportedrates[i];
	}

	return sizeof(struct ieee80211_ie_supported_rates) + iesupportedrates->len;
}

/* */
static int ieee80211_ie_set_extendedsupportedrates(uint8_t* buffer, uint8_t* supportedrates, int supportedratescount) {
	int i, j;
	struct ieee80211_ie_extended_supported_rates* ieextendedsupportedrates = (struct ieee80211_ie_extended_supported_rates*)buffer;

	ASSERT(buffer != NULL);
	ASSERT(supportedrates != NULL);

	/* IE accept only > 8 rate */
	if (supportedratescount <= IEEE80211_IE_SUPPORTED_RATES_MAX_LENGTH) {
		return 0;
	}

	/* */
	ieextendedsupportedrates->id = IEEE80211_IE_EXTENDED_SUPPORTED_RATES;
	ieextendedsupportedrates->len = supportedratescount - IEEE80211_IE_SUPPORTED_RATES_MAX_LENGTH;

	for (i = IEEE80211_IE_SUPPORTED_RATES_MAX_LENGTH, j = 0; i < supportedratescount; i++, j++) {
		ieextendedsupportedrates->rates[j] = supportedrates[i];
	}

	return sizeof(struct ieee80211_ie_extended_supported_rates) + ieextendedsupportedrates->len;
}

/* */
static int ieee80211_ie_set_dsss(uint8_t* buffer, uint8_t channel) {
	struct ieee80211_ie_dsss* iedsss = (struct ieee80211_ie_dsss*)buffer;

	ASSERT(buffer != NULL);

	iedsss->id = IEEE80211_IE_DSSS;
	iedsss->len = IEEE80211_IE_DSSS_LENGTH;
	iedsss->channel = channel;

	return sizeof(struct ieee80211_ie_dsss);
}

/* */
static int ieee80211_ie_set_erp(uint8_t* buffer, uint32_t mode, uint8_t erpinfo) {
	struct ieee80211_ie_erp* ieerp = (struct ieee80211_ie_erp*)buffer;

	ASSERT(buffer != NULL);

	if (!(mode & IEEE80211_RADIO_TYPE_80211G)) {
		return 0;
	}

	ieerp->id = IEEE80211_IE_ERP;
	ieerp->len = IEEE80211_IE_ERP_LENGTH;
	ieerp->params = erpinfo;

	return sizeof(struct ieee80211_ie_erp);
}

/* */
int ieee80211_retrieve_information_elements_position(struct ieee80211_ie_items* items, const uint8_t* data, int length) {
	ASSERT(items != NULL);
	ASSERT(data != NULL);

	/* */
	memset(items, 0, sizeof(struct ieee80211_ie_items));

	/* Parsing */
	while (length >= 2) {
		uint8_t ie_id = data[0];
		uint8_t ie_len = data[1];

		/* Parsing Information Element */
		switch (ie_id) {
			case IEEE80211_IE_SSID: {
				if (ie_len > IEEE80211_IE_SSID_MAX_LENGTH) {
					return -1;
				}

				items->ssid = (struct ieee80211_ie_ssid*)data;
				break;
			}

			case IEEE80211_IE_SUPPORTED_RATES: {
				if ((ie_len < IEEE80211_IE_SUPPORTED_RATES_MIN_LENGTH) || (ie_len > IEEE80211_IE_SUPPORTED_RATES_MAX_LENGTH)) {
					return -1;
				}

				items->supported_rates = (struct ieee80211_ie_supported_rates*)data;
				break;
			}

			case IEEE80211_IE_DSSS: {
				if (ie_len != IEEE80211_IE_DSSS_LENGTH) {
					return -1;
				}

				items->dsss = (struct ieee80211_ie_dsss*)data;
				break;
			}

			case IEEE80211_IE_COUNTRY: {
				if (ie_len < IEEE80211_IE_COUNTRY_MIN_LENGTH) {
					return -1;
				}

				items->country = (struct ieee80211_ie_country*)data;
				break;
			}

			case IEEE80211_IE_CHALLENGE_TEXT: {
				if (ie_len < IEEE80211_IE_CHALLENGE_TEXT_MIN_LENGTH) {
					return -1;
				}

				items->challenge_text = (struct ieee80211_ie_challenge_text*)data;
				break;
			}

			case IEEE80211_IE_ERP: {
				if (ie_len != IEEE80211_IE_ERP_LENGTH) {
					return -1;
				}

				items->erp = (struct ieee80211_ie_erp*)data;
				break;
			}

			case IEEE80211_IE_EXTENDED_SUPPORTED_RATES: {
				if (ie_len < IEEE80211_IE_EXTENDED_SUPPORTED_MIN_LENGTH) {
					return -1;
				}

				items->extended_supported_rates = (struct ieee80211_ie_extended_supported_rates*)data;
				break;
			}

			case IEEE80211_IE_EDCA_PARAMETER_SET: {
				if (ie_len != IEEE80211_IE_EDCA_PARAMETER_SET_LENGTH) {
					return -1;
				}

				items->edca_parameter_set = (struct ieee80211_ie_edca_parameter_set*)data;
				break;
			}

			case IEEE80211_IE_QOS_CAPABILITY: {
				if (ie_len != IEEE80211_IE_QOS_CAPABILITY_LENGTH) {
					return -1;
				}

				items->qos_capability = (struct ieee80211_ie_qos_capability*)data;
				break;
			}

			case IEEE80211_IE_POWER_CONSTRAINT: {
				if (ie_len != IEEE80211_IE_POWER_CONSTRAINT_LENGTH) {
					return -1;
				}

				items->power_constraint = (struct ieee80211_ie_power_constraint*)data;
				break;
			}

			case IEEE80211_IE_SSID_LIST: {
				items->ssid_list = (struct ieee80211_ie_ssid_list*)data;
				break;
			}
		}

		/* Next Information Element */
		data += sizeof(struct ieee80211_ie) + ie_len;
		length -= sizeof(struct ieee80211_ie) + ie_len;
	}

	return (!length ? 0 : -1);
}

/* */
int ieee80211_aid_create(uint32_t* aidbitfield, uint16_t* aid) {
	int i, j;

	ASSERT(aidbitfield != NULL);
	ASSERT(aid != NULL);

	/* Search free aid bitfield */
	for (i = 0; i < IEEE80211_AID_BITFIELD_SIZE; i++) {
		if (aidbitfield[i] != 0xffffffff) {
			uint32_t bitfield = aidbitfield[i];

			/* Search free bit */
			for (j = 0; j < 32; j++) {
				if (!(bitfield & (1 << j))) {
					*aid = i * 32 + j + 1;
					if (*aid <= IEEE80211_AID_MAX_VALUE) {
						aidbitfield[i] |= (1 << j);
						return 0;
					}

					break;
				}
			}

			break;
		}
	}

	*aid = 0;
	return -1;
}

/* */
void ieee80211_aid_free(uint32_t* aidbitfield, uint16_t aid) {
	ASSERT(aidbitfield != NULL);
	ASSERT((aid > 0) && (aid <= IEEE80211_AID_MAX_VALUE));

	aidbitfield[(aid - 1) / 32] &= ~(1 << ((aid - 1) % 32));
}

/* */
unsigned long ieee80211_frequency_to_channel(uint32_t freq) {
	if ((freq >= 2412) && (freq <= 2472)) {
		return (freq - 2407) / 5;
	} else if (freq == 2484) {
		return 14;
	} else if ((freq >= 4915) && (freq <= 4980)) {
		return (freq - 4000) / 5;
	} else if ((freq >= 5035) && (freq <= 5825)) {
		return (freq - 5000) / 5;
	}

	return 0;
}

/* */
int ieee80211_is_broadcast_addr(const uint8_t* addr) {
	return (((addr[0] == 0xff) && (addr[1] == 0xff) && (addr[2] == 0xff) && (addr[3] == 0xff) && (addr[4] == 0xff) && (addr[5] == 0xff)) ? 1 : 0);
}

/* */
const uint8_t* ieee80211_get_sa_addr(const struct ieee80211_header* header) {
	uint16_t framecontrol;
	uint16_t framecontrol_type;

	ASSERT(header);

	/* Get type frame */
	framecontrol = __le16_to_cpu(header->framecontrol);
	framecontrol_type = IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol);

	if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_MGMT) {
		return header->address2;
	} else if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_DATA) {
		switch (framecontrol & (IEEE80211_FRAME_CONTROL_MASK_TODS | IEEE80211_FRAME_CONTROL_MASK_FROMDS)) {
			case 0: {
				return header->address2;
			}

			case IEEE80211_FRAME_CONTROL_MASK_TODS: {
				return header->address2;
			}

			case IEEE80211_FRAME_CONTROL_MASK_FROMDS: {
				return header->address3;
			}
		}
	}

	return NULL;
}

const uint8_t* ieee80211_get_da_addr(const struct ieee80211_header* header) {
	uint16_t framecontrol;
	uint16_t framecontrol_type;

	ASSERT(header);

	/* Get type frame */
	framecontrol = __le16_to_cpu(header->framecontrol);
	framecontrol_type = IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol);

	if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_MGMT) {
		return header->address1;
	} else if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_DATA) {
		switch (framecontrol & (IEEE80211_FRAME_CONTROL_MASK_TODS | IEEE80211_FRAME_CONTROL_MASK_FROMDS)) {
			case 0: {
				return header->address1;
			}

			case IEEE80211_FRAME_CONTROL_MASK_TODS: {
				return header->address3;
			}

			case IEEE80211_FRAME_CONTROL_MASK_FROMDS: {
				return header->address1;
			}
		}
	}

	return NULL;
}

/* */
const uint8_t* ieee80211_get_bssid_addr(const struct ieee80211_header* header) {
	uint16_t framecontrol;
	uint16_t framecontrol_type;

	ASSERT(header);

	/* Get type frame */
	framecontrol = __le16_to_cpu(header->framecontrol);
	framecontrol_type = IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol);

	if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_MGMT) {
		return header->address3;
	} else if (framecontrol_type == IEEE80211_FRAMECONTROL_TYPE_DATA) {
		switch (framecontrol & (IEEE80211_FRAME_CONTROL_MASK_TODS | IEEE80211_FRAME_CONTROL_MASK_FROMDS)) {
			case 0: {
				return header->address3;
			}

			case IEEE80211_FRAME_CONTROL_MASK_TODS: {
				return header->address1;
			}

			case IEEE80211_FRAME_CONTROL_MASK_FROMDS: {
				return header->address2;
			}
		}
	}

	return NULL;
}

/* */
int ieee80211_is_valid_ssid(const char* ssid, struct ieee80211_ie_ssid* iessid, struct ieee80211_ie_ssid_list* isssidlist) {
	int ssidlength;

	ASSERT(ssid != NULL);

	if (!iessid) {
		return IEEE80211_WRONG_SSID;
	}

	/* Check SSID */
	ssidlength = strlen((char*)ssid);
	if ((ssidlength == iessid->len) && !memcmp(ssid, iessid->ssid, ssidlength)) {
		return IEEE80211_VALID_SSID;
	}

	/* Check SSID list */
	if (isssidlist) {
		int length = isssidlist->len;
		uint8_t* pos = isssidlist->lists;

		while (length >= sizeof(struct ieee80211_ie)) {
			struct ieee80211_ie_ssid* ssiditem = (struct ieee80211_ie_ssid*)pos;

			/* Check buffer */
			length -= sizeof(struct ieee80211_ie);
			if ((ssiditem->id != IEEE80211_IE_SSID) || !ssiditem->len || (length < ssiditem->len)) {
				break;
			} else if ((ssidlength == ssiditem->len) && !memcmp(ssid, ssiditem->ssid, ssidlength)) {
				return IEEE80211_VALID_SSID;
			}

			/* Next */
			length -= ssiditem->len;
			pos += sizeof(struct ieee80211_ie) + ssiditem->len;
		}
	}

	return (!iessid->len ? IEEE80211_WILDCARD_SSID : IEEE80211_WRONG_SSID);
}

/* */
uint8_t ieee80211_get_erpinfo(uint32_t mode, int olbc, unsigned long stationnonerpcount, unsigned long stationnoshortpreamblecount, int shortpreamble) {
	uint8_t result = 0;

	/* Erp mode is valid only in IEEE 802.11 g*/
	if (mode & IEEE80211_RADIO_TYPE_80211G) {
		if (olbc) {
			result |= IEEE80211_ERP_INFO_USE_PROTECTION;
		}

		if (stationnonerpcount > 0) {
			result |= (IEEE80211_ERP_INFO_NON_ERP_PRESENT | IEEE80211_ERP_INFO_USE_PROTECTION);
		}

		if (!shortpreamble || (stationnoshortpreamblecount > 0)) {
			result |= IEEE80211_ERP_INFO_BARKER_PREAMBLE_MODE;
		}
	}

	return result;
}


/* */
int ieee80211_create_beacon(uint8_t* buffer, int length, struct ieee80211_beacon_params* params) {
	int result;
	uint8_t* pos;
	struct ieee80211_header_mgmt* header;

	ASSERT(buffer != NULL);

	/* */
	header = (struct ieee80211_header_mgmt*)buffer;
	params->headbeacon = buffer;

	/* Management header frame */
	header->framecontrol = IEEE80211_FRAME_CONTROL(IEEE80211_FRAMECONTROL_TYPE_MGMT, IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_BEACON);
	header->durationid = __cpu_to_le16(0);
	memset(header->da, 0xff, ETH_ALEN);
	memcpy(header->sa, params->bssid, ETH_ALEN);
	memcpy(header->bssid, params->bssid, ETH_ALEN);
	header->sequencecontrol = __cpu_to_le16(0);
	memset(header->beacon.timestamp, 0, sizeof(header->beacon.timestamp));
	header->beacon.beaconinterval = __cpu_to_le16(params->beaconperiod);
	header->beacon.capability = __cpu_to_le16(params->capability);

	/* Header frame size */
	params->headbeaconlength = (int)((uint8_t*)&header->beacon.ie[0] - (uint8_t*)header);
	pos = buffer + params->headbeaconlength;

	/* Information Element: SSID */
	result = ieee80211_ie_set_ssid(pos, params->ssid, (params->ssid_hidden ? 1 : 0));
	if (result < 0) {
		return -1;
	}

	pos += result;
	params->headbeaconlength += result;

	/* Information Element: Supported Rates */
	result = ieee80211_ie_set_supportedrates(pos, params->supportedrates, params->supportedratescount);
	if (result < 0) {
		return -1;
	}

	pos += result;
	params->headbeaconlength += result;

	/* Information Element: DSSS */
	result = ieee80211_ie_set_dsss(pos, params->channel);
	if (result < 0) {
		return -1;
	}

	pos += result;
	params->headbeaconlength += result;

	/* Separate Information Elements into two block between IE TIM */
	params->tailbeacon = pos;
	params->tailbeaconlength = 0;

	/* Information Element: Country */
	/* TODO */

	/* Information Element: ERP */
	result = ieee80211_ie_set_erp(pos, params->mode, params->erpinfo);
	if (result < 0) {
		return -1;
	}

	pos += result;
	params->tailbeaconlength += result;

	/* Information Element: Extended Supported Rates */
	result = ieee80211_ie_set_extendedsupportedrates(pos, params->supportedrates, params->supportedratescount);
	if (result < 0) {
		return -1;
	}

	pos += result;
	params->tailbeaconlength += result;

	/* Probe Response offload */
	if (params->flags & IEEE80221_CREATE_BEACON_FLAGS_PROBE_RESPONSE_OFFLOAD) {
		struct ieee80211_probe_response_params proberesponseparams;

		/* */
		memset(&proberesponseparams, 0, sizeof(struct ieee80211_probe_response_params));
		memcpy(proberesponseparams.bssid, params->bssid, ETH_ALEN);
		proberesponseparams.beaconperiod = params->beaconperiod;
		proberesponseparams.capability = params->capability;
		proberesponseparams.ssid = params->ssid;
		memcpy(proberesponseparams.supportedrates, params->supportedrates, params->supportedratescount);
		proberesponseparams.supportedratescount = params->supportedratescount;
		proberesponseparams.mode = params->mode;
		proberesponseparams.erpinfo = params->erpinfo;
		proberesponseparams.channel = params->channel;

		/* */
		params->proberesponseoffload = pos;
		params->proberesponseoffloadlength = ieee80211_create_probe_response(pos, (int)(pos - buffer), &proberesponseparams);
		if (params->proberesponseoffloadlength < 0) {
			return -1;
		}

		/* */
		pos += params->proberesponseoffloadlength;
	}

	return (int)(pos - buffer);
}

/* */
int ieee80211_create_probe_response(uint8_t* buffer, int length, struct ieee80211_probe_response_params* params) {
	int result;
	uint8_t* pos;
	int responselength;
	struct ieee80211_header_mgmt* header;

	ASSERT(buffer != NULL);

	/* */
	header = (struct ieee80211_header_mgmt*)buffer;

	/* Management header frame */
	header->framecontrol = IEEE80211_FRAME_CONTROL(IEEE80211_FRAMECONTROL_TYPE_MGMT, IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_PROBE_RESPONSE);
	header->durationid = __cpu_to_le16(0);
	memcpy(header->da, params->station, ETH_ALEN);
	memcpy(header->sa, params->bssid, ETH_ALEN);
	memcpy(header->bssid, params->bssid, ETH_ALEN);
	header->sequencecontrol = __cpu_to_le16(0);
	memset(header->proberesponse.timestamp, 0, sizeof(header->proberesponse.timestamp));
	header->proberesponse.beaconinterval = __cpu_to_le16(params->beaconperiod);
	header->proberesponse.capability = __cpu_to_le16(params->capability);

	/* Header frame size */
	responselength = (int)((uint8_t*)&header->proberesponse.ie[0] - (uint8_t*)header);
	pos = buffer + responselength;

	/* Information Element: SSID */
	result = ieee80211_ie_set_ssid(pos, params->ssid, 0);
	if (result < 0) {
		return -1;
	}

	pos += result;
	responselength += result;

	/* Information Element: Supported Rates */
	result = ieee80211_ie_set_supportedrates(pos, params->supportedrates, params->supportedratescount);
	if (result < 0) {
		return -1;
	}

	pos += result;
	responselength += result;

	/* Information Element: DSSS */
	result = ieee80211_ie_set_dsss(pos, params->channel);
	if (result < 0) {
		return -1;
	}

	pos += result;
	responselength += result;

	/* Information Element: Country */
	/* TODO */

	/* Information Element: ERP */
	result = ieee80211_ie_set_erp(pos, params->mode, params->erpinfo);
	if (result < 0) {
		return -1;
	}

	pos += result;
	responselength += result;

	/* Information Element: Extended Supported Rates */
	result = ieee80211_ie_set_extendedsupportedrates(pos, params->supportedrates, params->supportedratescount);
	if (result < 0) {
		return -1;
	}

	/*pos += result;*/ /* Comment for disable Dead inscrement Clang Analyzer warning */
	responselength += result;

	return responselength;
}

/* */
int ieee80211_create_authentication_response(uint8_t* buffer, int length, struct ieee80211_authentication_params* params) {
	int responselength;
	struct ieee80211_header_mgmt* header;

	ASSERT(buffer != NULL);

	/* */
	header = (struct ieee80211_header_mgmt*)buffer;

	/* Management header frame */
	header->framecontrol = IEEE80211_FRAME_CONTROL(IEEE80211_FRAMECONTROL_TYPE_MGMT, IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTHENTICATION);
	header->durationid = __cpu_to_le16(0);
	memcpy(header->da, params->station, ETH_ALEN);
	memcpy(header->sa, params->bssid, ETH_ALEN);
	memcpy(header->bssid, params->bssid, ETH_ALEN);
	header->sequencecontrol = __cpu_to_le16(0);
	header->authetication.algorithm = __cpu_to_le16(params->algorithm);
	header->authetication.transactionseqnumber = __cpu_to_le16(params->transactionseqnumber);
	header->authetication.statuscode = __cpu_to_le16(params->statuscode);

	/* Header frame size */
	responselength = (int)((uint8_t*)&header->authetication.ie[0] - (uint8_t*)header);

	/* TODO: add custon IE */

	return responselength;
}

/* */
int ieee80211_create_associationresponse_response(uint8_t* buffer, int length, struct ieee80211_associationresponse_params* params) {
	uint8_t* pos;
	int result;
	int responselength;
	struct ieee80211_header_mgmt* header;

	ASSERT(buffer != NULL);

	/* */
	header = (struct ieee80211_header_mgmt*)buffer;

	/* Management header frame */
	header->framecontrol = IEEE80211_FRAME_CONTROL(IEEE80211_FRAMECONTROL_TYPE_MGMT, IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_RESPONSE);
	header->durationid = __cpu_to_le16(0);
	memcpy(header->da, params->station, ETH_ALEN);
	memcpy(header->sa, params->bssid, ETH_ALEN);
	memcpy(header->bssid, params->bssid, ETH_ALEN);
	header->sequencecontrol = __cpu_to_le16(0);
	header->associationresponse.capability = __cpu_to_le16(params->capability);
	header->associationresponse.statuscode = __cpu_to_le16(params->statuscode);
	header->associationresponse.aid = __cpu_to_le16(params->aid);

	/* Header frame size */
	responselength = (int)((uint8_t*)&header->associationresponse.ie[0] - (uint8_t*)header);
	pos = buffer + responselength;

	/* Information Element: Supported Rates */
	result = ieee80211_ie_set_supportedrates(pos, params->supportedrates, params->supportedratescount);
	if (result < 0) {
		return -1;
	}

	pos += result;
	responselength += result;

	/* Information Element: Extended Supported Rates */
	result = ieee80211_ie_set_extendedsupportedrates(pos, params->supportedrates, params->supportedratescount);
	if (result < 0) {
		return -1;
	}

	/*pos += result;*/ /* Comment for disable Dead inscrement Clang Analyzer warning */
	responselength += result;

	return responselength;
}

/* */
int ieee80211_create_deauthentication(uint8_t* buffer, int length, struct ieee80211_deauthentication_params* params) {
	struct ieee80211_header_mgmt* header;

	ASSERT(buffer != NULL);

	/* */
	header = (struct ieee80211_header_mgmt*)buffer;

	/* Management header frame */
	header->framecontrol = IEEE80211_FRAME_CONTROL(IEEE80211_FRAMECONTROL_TYPE_MGMT, IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTHENTICATION);
	header->durationid = __cpu_to_le16(0);
	memcpy(header->da, params->station, ETH_ALEN);
	memcpy(header->sa, params->bssid, ETH_ALEN);
	memcpy(header->bssid, params->bssid, ETH_ALEN);
	header->sequencecontrol = __cpu_to_le16(0);
	header->deauthetication.reasoncode = __cpu_to_le16(params->reasoncode);

	return (int)((uint8_t*)&header->deauthetication.ie[0] - (uint8_t*)header);
}
