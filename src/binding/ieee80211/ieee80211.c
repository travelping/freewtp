#include "capwap.h"
#include "ieee80211.h"

/* */
static int ieee80211_ie_set_ssid(char* buffer, const char* ssid, int hidessid) {
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
static int ieee80211_ie_set_supportedrates(char* buffer, uint8_t* supportedrates, int supportedratescount) {
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
static int ieee80211_ie_set_extendedsupportedrates(char* buffer, uint8_t* supportedrates, int supportedratescount) {
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
static int ieee80211_ie_set_dsss(char* buffer, uint8_t channel) {
	struct ieee80211_ie_dsss* iedsss = (struct ieee80211_ie_dsss*)buffer;

	ASSERT(buffer != NULL);

	iedsss->id = IEEE80211_IE_DSSS;
	iedsss->len = 1;
	iedsss->channel = channel;

	return sizeof(struct ieee80211_ie_dsss);
}

/* */
static int ieee80211_ie_set_erp(char* buffer, uint32_t mode) {
	struct ieee80211_ie_erp* ieerp = (struct ieee80211_ie_erp*)buffer;

	ASSERT(buffer != NULL);

	if (!(mode & IEEE80211_RADIO_TYPE_80211G)) {
		return 0;
	}

	ieerp->id = IEEE80211_IE_ERP;
	ieerp->len = 1;
	ieerp->params = 0;		/* TODO */

	return sizeof(struct ieee80211_ie_erp);
}

/* */
int ieee80211_create_beacon(char* buffer, int length, struct ieee80211_beacon_params* params) {
	int result;
	char* pos;
	struct ieee80211_header_mgmt* header;

	ASSERT(buffer != NULL);
	ASSERT(length == IEEE80211_MTU);

	/* */
	memset(buffer, 0x00, length);
	header = (struct ieee80211_header_mgmt*)buffer;
	params->headbeacon = buffer;

	/* Management header frame */
	header->framecontrol = IEEE80211_FRAME_CONTROL(IEEE80211_FRAMECONTROL_TYPE_MGMT, IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_BEACON);
	memset(header->da, 0xff, ETH_ALEN);
	memcpy(header->sa, params->bssid, ETH_ALEN);
	memcpy(header->bssid, params->bssid, ETH_ALEN);
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
	result = ieee80211_ie_set_erp(pos, params->erpmode);
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

	return (params->headbeaconlength + params->tailbeaconlength);
}

/* */
int ieee80211_create_probe_response(char* buffer, int length, const struct ieee80211_header_mgmt* proberequestheader, struct ieee80211_probe_response_params* params) {
	int result;
	char* pos;
	int responselength;
	struct ieee80211_header_mgmt* header;

	ASSERT(buffer != NULL);
	ASSERT(length == IEEE80211_MTU);

	/* */
	memset(buffer, 0x00, length);
	header = (struct ieee80211_header_mgmt*)buffer;

	/* Management header frame */
	header->framecontrol = IEEE80211_FRAME_CONTROL(IEEE80211_FRAMECONTROL_TYPE_MGMT, IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_PROBE_RESP);
	if (proberequestheader) {
		memcpy(header->da, proberequestheader->sa, ETH_ALEN);
	} else {
		memset(header->da, 0x00, ETH_ALEN);
	}
	memcpy(header->sa, params->bssid, ETH_ALEN);
	memcpy(header->bssid, params->bssid, ETH_ALEN);
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
	result = ieee80211_ie_set_erp(pos, params->erpmode);
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

	pos += result;
	responselength += result;

	return responselength;
}