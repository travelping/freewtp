#ifndef __CAPWAP_IEEE802_11_HEADER__
#define __CAPWAP_IEEE802_11_HEADER__

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/if_ether.h>

#ifndef STRUCT_PACKED
#define STRUCT_PACKED					__attribute__((__packed__))
#endif

/* Global values */
#define IEEE80211_MTU					2304

/* Radio type with value same of IEEE802.11 Radio Information Message Element */
#define IEEE80211_RADIO_TYPE_80211B			0x00000001
#define IEEE80211_RADIO_TYPE_80211A			0x00000002
#define IEEE80211_RADIO_TYPE_80211G			0x00000004
#define IEEE80211_RADIO_TYPE_80211N			0x00000008

/* */
#define IS_IEEE80211_FREQ_BG(x)			(((x >= 2412) && (x <= 2484)) ? 1 : 0)
#define IS_IEEE80211_FREQ_A(x)			((((x >= 4915) && (x <= 4980)) || ((x >= 5035) && (x <= 5825))) ? 1 : 0)

/* Rate into multiple of 500Kbps */
#define IEEE80211_RATE_1M				2
#define IEEE80211_RATE_2M				4
#define IEEE80211_RATE_5_5M				11
#define IEEE80211_RATE_11M				22
#define IEEE80211_RATE_6M				12
#define IEEE80211_RATE_9M				18
#define IEEE80211_RATE_12M				24
#define IEEE80211_RATE_18M				36
#define IEEE80211_RATE_24M				48
#define IEEE80211_RATE_36M				72
#define IEEE80211_RATE_48M				96
#define IEEE80211_RATE_54M				108
#define IEEE80211_RATE_80211N			127

#define IS_IEEE80211_RATE_B(x)			(((x == IEEE80211_RATE_1M) || (x == IEEE80211_RATE_2M) || (x == IEEE80211_RATE_5_5M) || (x == IEEE80211_RATE_11M)) ? 1 : 0)
#define IS_IEEE80211_RATE_G(x)			(((x == IEEE80211_RATE_6M) || (x == IEEE80211_RATE_9M) || (x == IEEE80211_RATE_12M) || (x == IEEE80211_RATE_18M) || (x == IEEE80211_RATE_24M) || (x == IEEE80211_RATE_36M) || (x == IEEE80211_RATE_48M) || (x == IEEE80211_RATE_54M)) ? 1 : 0)
#define IS_IEEE80211_RATE_A(x)			(((x == IEEE80211_RATE_6M) || (x == IEEE80211_RATE_9M) || (x == IEEE80211_RATE_12M) || (x == IEEE80211_RATE_18M) || (x == IEEE80211_RATE_24M) || (x == IEEE80211_RATE_36M) || (x == IEEE80211_RATE_48M) || (x == IEEE80211_RATE_54M)) ? 1 : 0)
#define IS_IEEE80211_RATE_N(x)			((x == IEEE80211_RATE_80211N) ? 1 : 0)

#define IEEE80211_BASICRATE				128
#define IS_IEEE80211_BASICRATE_B(x)		((x == IEEE80211_RATE_1M) || (x == IEEE80211_RATE_2M))
#define IS_IEEE80211_BASICRATE_G(x)		((x == IEEE80211_RATE_1M) || (x == IEEE80211_RATE_2M) || (x == IEEE80211_RATE_5_5M) || (x == IEEE80211_RATE_11M))
#define IS_IEEE80211_BASICRATE_A(x)		((x == IEEE80211_RATE_6M) || (x == IEEE80211_RATE_12M) || (x == IEEE80211_RATE_24M))

/* Frame control type */
#define IEEE80211_FRAMECONTROL_TYPE_MGMT					0
#define IEEE80211_FRAMECONTROL_TYPE_CTRL					1
#define IEEE80211_FRAMECONTROL_TYPE_DATA					2

/* Frame control Management subtype */
#define IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_REQUEST			0
#define IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ASSOCIATION_RESPONSE		1
#define IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_REASSOCIATION_REQUEST		2
#define IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_REASSOCIATION_RESPONSE		3
#define IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_PROBE_REQUEST				4
#define IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_PROBE_RESPONSE				5
#define IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_TIMING_ADV					6
#define IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_BEACON						8
#define IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ATIM						9
#define IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DISASSOCIATION				10
#define IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_AUTHENTICATION				11
#define IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_DEAUTHENTICATION			12
#define IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ACTION						13
#define IEEE80211_FRAMECONTROL_MGMT_SUBTYPE_ACTION_NOACK				14

/* Frame control Control subtype */
#define IEEE80211_FRAMECONTROL_CTRL_SUBTYPE_CTRLWRAPPER				7
#define IEEE80211_FRAMECONTROL_CTRL_SUBTYPE_BLOCKACK_REQ			8
#define IEEE80211_FRAMECONTROL_CTRL_SUBTYPE_BLOCKACK				9
#define IEEE80211_FRAMECONTROL_CTRL_SUBTYPE_PSPOLL					10
#define IEEE80211_FRAMECONTROL_CTRL_SUBTYPE_RTS						11
#define IEEE80211_FRAMECONTROL_CTRL_SUBTYPE_CTS						12
#define IEEE80211_FRAMECONTROL_CTRL_SUBTYPE_ACK						13
#define IEEE80211_FRAMECONTROL_CTRL_SUBTYPE_CFEND					14
#define IEEE80211_FRAMECONTROL_CTRL_SUBTYPE_CFEND_CFACK				15

/* Frame control Data subtype */
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_DATA					0
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_DATA_CFACK				1
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_DATA_CFPOLL				2
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_DATA_CFACK_CFPOLL		3
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_NULL					4
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_CFACK					5
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_CFPOLL					6
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_CFACK_CFPOLL			7
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_QOSDATA					8
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_QOSDATA_CFACK			9
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_QOSDATA_CFPOLL			10
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_QOSDATA_CFACK_CFPOLL	11
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_QOSNULL					12
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_QOSCFPOLL				14
#define IEEE80211_FRAMECONTROL_DATA_SUBTYPE_QOSCFACK_CFPOLL			15

/* */
#define IEEE80211_FRAME_CONTROL(type, stype) 						__cpu_to_le16((type << 2) | (stype << 4))
#define IEEE80211_FRAME_CONTROL_GET_TYPE(framecontrol)				(((framecontrol) & 0x000c) >> 2)
#define IEEE80211_FRAME_CONTROL_GET_SUBTYPE(framecontrol)			(((framecontrol) & 0x00f0) >> 4)

/* IEEE802.11 Status Code */
#define IEEE80211_STATUS_SUCCESS									0
#define IEEE80211_STATUS_UNSPECIFIED_FAILURE						1
#define IEEE80211_STATUS_TDLS_WAKEUP_ALTERNATE						2
#define IEEE80211_STATUS_TDLS_WAKEUP_REJECT							3
#define IEEE80211_STATUS_SECURITY_DISABLED							5
#define IEEE80211_STATUS_UNACCEPTABLE_LIFETIME						6
#define IEEE80211_STATUS_NOT_IN_SAME_BSS							7
#define IEEE80211_STATUS_CAPS_UNSUPPORTED							10
#define IEEE80211_STATUS_REASSOCIATION_NO_ASSOCIATE					11
#define IEEE80211_STATUS_ASSOCIATION_DENIED_UNSPEC					12
#define IEEE80211_STATUS_NOT_SUPPORTED_AUTHENTICATION_ALGORITHM		13
#define IEEE80211_STATUS_UNKNOWN_AUTHENTICATION_TRANSACTION			14
#define IEEE80211_STATUS_CHALLENGE_FAIL								15
#define IEEE80211_STATUS_AUTHENTICATION_TIMEOUT						16
#define IEEE80211_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA				17
#define IEEE80211_STATUS_ASSOCIATION_DENIED_RATES					18
#define IEEE80211_STATUS_ASSOCIATION_DENIED_NOSHORT					19
#define IEEE80211_STATUS_ASSOCIATION_DENIED_NOPBCC					20
#define IEEE80211_STATUS_ASSOCIATION_DENIED_NOAGILITY				21
#define IEEE80211_STATUS_SPEC_MGMT_REQUIRED							22
#define IEEE80211_STATUS_PWR_CAPABILITY_NOT_VALID					23
#define IEEE80211_STATUS_SUPPORTED_CHANNEL_NOT_VALID				24
#define IEEE80211_STATUS_ASSOCIATION_DENIED_NO_SHORT_SLOT_TIME		25
#define IEEE80211_STATUS_ASSOCIATION_DENIED_NO_DSSS_OFDM			26
#define IEEE80211_STATUS_ASSOCIATION_DENIED_NO_HT					27
#define IEEE80211_STATUS_R0KH_UNREACHABLE							28
#define IEEE80211_STATUS_ASSOCIATION_DENIED_NO_PCO					29
#define IEEE80211_STATUS_ASSOCIATION_REJECTED_TEMPORARILY			30
#define IEEE80211_STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION			31
#define IEEE80211_STATUS_UNSPECIFIED_QOS_FAILURE					32
#define IEEE80211_STATUS_QOS_INSUFFICIENT_BANDWIDTH					33
#define IEEE80211_STATUS_EXCESSIVE_FRAME_LOST						34
#define IEEE80211_STATUS_STA_NOT_SUPPORT_QOS_FACILITY				35
#define IEEE80211_STATUS_REQUEST_DECLINED							37
#define IEEE80211_STATUS_INVALID_PARAMETERS							38
#define IEEE80211_STATUS_REJECTED_WITH_SUGGESTED_CHANGES			39
#define IEEE80211_STATUS_INVALID_IE									40
#define IEEE80211_STATUS_GROUP_CIPHER_NOT_VALID						41
#define IEEE80211_STATUS_PAIRWISE_CIPHER_NOT_VALID					42
#define IEEE80211_STATUS_AKMP_NOT_VALID								43
#define IEEE80211_STATUS_UNSUPPORTED_RSN_IE_VERSION					44
#define IEEE80211_STATUS_INVALID_RSN_IE_CAPAB						45
#define IEEE80211_STATUS_CIPHER_REJECTED_PER_POLICY					46
#define IEEE80211_STATUS_TS_NOT_CREATED								47
#define IEEE80211_STATUS_DIRECT_LINK_NOT_ALLOWED					48
#define IEEE80211_STATUS_DEST_STA_NOT_PRESENT						49
#define IEEE80211_STATUS_DEST_STA_NOT_QOS_STA						50
#define IEEE80211_STATUS_ASSOCIATION_DENIED_LISTEN_INT_TOO_LARGE	51
#define IEEE80211_STATUS_INVALID_FT_ACTION_FRAME_COUNT				52
#define IEEE80211_STATUS_INVALID_PMKID								53
#define IEEE80211_STATUS_INVALID_MDIE								54
#define IEEE80211_STATUS_INVALID_FTIE								55
#define IEEE80211_STATUS_REQUEST_TCLAS_NOT_SUPPORTED				56
#define IEEE80211_STATUS_INSUFFICIENT_TCLAS							57
#define IEEE80211_STATUS_TS_NOT_BEEN_CREATED						58
#define IEEE80211_STATUS_GAS_ADV_PROTO_NOT_SUPPORTED				59
#define IEEE80211_STATUS_NO_OUTSTANDING_GAS_REQ						60
#define IEEE80211_STATUS_GAS_RESP_NOT_RECEIVED						61
#define IEEE80211_STATUS_STA_TIMED_OUT_WAITING_FOR_GAS_RESP			62
#define IEEE80211_STATUS_GAS_RESP_LARGER_THAN_LIMIT					63
#define IEEE80211_STATUS_REQ_REFUSED_HOME							64
#define IEEE80211_STATUS_ADV_SRV_UNREACHABLE						65
#define IEEE80211_STATUS_REQ_REFUSED_SSPN							67
#define IEEE80211_STATUS_REQ_REFUSED_UNAUTH_ACCESS					68
#define IEEE80211_STATUS_INVALID_RSNIE								72
#define IEEE80211_STATUS_UAPSD_COEXISTENCE_NOT_SUPPORTED			73
#define IEEE80211_STATUS_REQUEST_UAPSD_COEXISTENCE_NOT_SUPPORTED	74
#define IEEE80211_STATUS_REQUEST_INTERVAL_NOT SUPPORTED				75
#define IEEE80211_STATUS_ANTI_CLOGGING_TOKEN_REQ					76
#define IEEE80211_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED			77
#define IEEE80211_STATUS_CANNOT_FIND_ALTERNATIVE_TBTT				78
#define IEEE80211_STATUS_TRANSMISSION_FAILURE						79
#define IEEE80211_STATUS_REQUYESTED_TCLAS_NOT_SUPPORTED				80
#define IEEE80211_STATUS_TCLAS_RESOURCES_EXHAUSTED					81
#define IEEE80211_STATUS_REJECTED_WITH_SUGGESTED_BSS_TRANSITION		82
#define IEEE80211_STATUS_REFUSED_EXTERNAL_REASON					92
#define IEEE80211_STATUS_REFUSED_AP_OUT_OF_MEMORY					93
#define IEEE80211_STATUS_REJECTED_EMERGENCY_SERVICES_NOT_SUPPORTED	94
#define IEEE80211_STATUS_QUERY_RESPONSE_OUTSTANDING					95
#define IEEE80211_STATUS_MCCAOP_RESERVATION_CONFLICT				100
#define IEEE80211_STATUS_MAF_LIMIT_EXCEEDED							101
#define IEEE80211_STATUS_MCCA_TRACK_LIMIT_EXCEEDED					102

/* IEEE802.11 Authentication Algorithm */
#define IEEE80211_AUTHENTICATION_ALGORITHM_OPEN						0
#define IEEE80211_AUTHENTICATION_ALGORITHM_SHARED_KEY				1
#define IEEE80211_AUTHENTICATION_ALGORITHM_FAST_BSS					2
#define IEEE80211_AUTHENTICATION_ALGORITHM_SAE						3

/* 802.11 Packet - IEEE802.11 is a little-endian protocol */
struct ieee80211_header {
	__le16 framecontrol;
	__le16 durationid;
	uint8_t address1[ETH_ALEN];
	uint8_t address2[ETH_ALEN];
	uint8_t address3[ETH_ALEN];
	__le16 sequencecontrol;
} STRUCT_PACKED;

/* */
struct ieee80211_header_mgmt {
	__le16 framecontrol;
	__le16 durationid;
	uint8_t da[ETH_ALEN];
	uint8_t sa[ETH_ALEN];
	uint8_t bssid[ETH_ALEN];
	__le16 sequencecontrol;

	union {
		struct {
			uint8_t timestamp[8];
			__le16 beaconinterval;
			__le16 capability;
			uint8_t ie[0];
		} STRUCT_PACKED beacon;

		struct {
			uint8_t ie[0];
		} STRUCT_PACKED proberequest;

		struct {
			uint8_t timestamp[8];
			__le16 beaconinterval;
			__le16 capability;
			uint8_t ie[0];
		} STRUCT_PACKED proberesponse;

		struct {
			__le16 algorithm;
			__le16 transactionseqnumber;
			__le16 statuscode;
			uint8_t ie[0];
		} STRUCT_PACKED authetication;
	};
} STRUCT_PACKED;

/* 802.11 Generic information element */
struct ieee80211_ie {
	uint8_t id;
	uint8_t len;
} STRUCT_PACKED;

/* 802.11 SSID information element */
#define IEEE80211_IE_SSID								0
#define IEEE80211_IE_SSID_MAX_LENGTH					32

struct ieee80211_ie_ssid {
	uint8_t id;
	uint8_t len;
	uint8_t ssid[0];
} STRUCT_PACKED;

/* 802.11 Supported Rates information element */
#define IEEE80211_IE_SUPPORTED_RATES					1
#define IEEE80211_IE_SUPPORTED_RATES_MIN_LENGTH			1
#define IEEE80211_IE_SUPPORTED_RATES_MAX_LENGTH			8

struct ieee80211_ie_supported_rates {
	uint8_t id;
	uint8_t len;
	uint8_t rates[0];
} STRUCT_PACKED;

/* 802.11 DSSS information element */
#define IEEE80211_IE_DSSS								3
#define IEEE80211_IE_DSSS_LENGTH						1

struct ieee80211_ie_dsss {
	uint8_t id;
	uint8_t len;
	uint8_t channel;
} STRUCT_PACKED;

/* 802.11 Country information element */
#define IEEE80211_IE_COUNTRY							7
#define IEEE80211_IE_COUNTRY_MIN_LENGTH					6

struct ieee80211_ie_country_channelgroup {
	uint8_t firstchannel;
	uint8_t numberchannels;
	uint8_t maxtxpower;
} STRUCT_PACKED;

struct ieee80211_ie_country {
	uint8_t id;
	uint8_t len;
	uint8_t country[3];
	uint8_t channelgroup[0];
} STRUCT_PACKED;

/* 802.11 Challenge text information element */
#define IEEE80211_IE_CHALLENGE_TEXT						16
#define IEEE80211_IE_CHALLENGE_TEXT_MIN_LENGTH			3

struct ieee80211_ie_challenge_text {
	uint8_t id;
	uint8_t len;
	uint8_t challengetext[0];
} STRUCT_PACKED;

/* 802.11 ERP information element */
#define IEEE80211_IE_ERP								42
#define IEEE80211_IE_ERP_LENGTH							1

struct ieee80211_ie_erp {
	uint8_t id;
	uint8_t len;
	uint8_t params;
} STRUCT_PACKED;

/* 802.11 Extended Supported Rates information element */
#define IEEE80211_IE_EXTENDED_SUPPORTED_RATES			50
#define IEEE80211_IE_EXTENDED_SUPPORTED_MIN_LENGTH		1

struct ieee80211_ie_extended_supported_rates {
	uint8_t id;
	uint8_t len;
	uint8_t rates[0];
} STRUCT_PACKED;

/* 802.11 EDCA Parameter Set information element */
#define IEEE80211_IE_EDCA_PARAMETER_SET					12
#define IEEE80211_IE_EDCA_PARAMETER_SET_LENGTH			18

#define EDCA_PARAMETER_RECORD_AC_BE_FIELD				0
#define EDCA_PARAMETER_RECORD_AC_BK_FIELD				1
#define EDCA_PARAMETER_RECORD_AC_VI_FIELD				2
#define EDCA_PARAMETER_RECORD_AC_VO_FIELD				3

struct ieee80211_ie_edca_parameter_set {
	uint8_t id;
	uint8_t len;
	/* TODO */
} STRUCT_PACKED;

/* 802.11 QoS Capability information element */
#define IEEE80211_IE_QOS_CAPABILITY						46
#define IEEE80211_IE_QOS_CAPABILITY_LENGTH				1

struct ieee80211_ie_qos_capability {
	uint8_t id;
	uint8_t len;
	/* TODO */
} STRUCT_PACKED;

/* 802.11 Power Constraint information element */
#define IEEE80211_IE_POWER_CONSTRAINT					32
#define IEEE80211_IE_POWER_CONSTRAINT_LENGTH			1

struct ieee80211_ie_power_constraint {
	uint8_t id;
	uint8_t len;
	/* TODO */
} STRUCT_PACKED;

/* 802.11 SSID List */
#define IEEE80211_IE_SSID_LIST							84

struct ieee80211_ie_ssid_list {
	uint8_t id;
	uint8_t len;
	uint8_t lists[0];
} STRUCT_PACKED;

/* 802.11 All information elements */
struct ieee80211_ie_items {
	struct ieee80211_ie_ssid* ssid;
	struct ieee80211_ie_supported_rates* supported_rates;
	struct ieee80211_ie_dsss* dsss;
	struct ieee80211_ie_country* country;
	struct ieee80211_ie_challenge_text* challenge_text;
	struct ieee80211_ie_erp* erp;
	struct ieee80211_ie_extended_supported_rates* extended_supported_rates;
	struct ieee80211_ie_edca_parameter_set* edca_parameter_set;
	struct ieee80211_ie_qos_capability* qos_capability;
	struct ieee80211_ie_power_constraint* power_constraint;
	struct ieee80211_ie_ssid_list* ssid_list;
};

/* IEEE 802.11 functions */
#define IEEE80211_SUPPORTEDRATE_MAX_COUNT				16

/* Management Beacon */
struct ieee80211_beacon_params {
	/* Beacon packet */
	char* headbeacon;
	int headbeaconlength;
	char* tailbeacon;
	int tailbeaconlength;

	/* Header information */
	uint8_t bssid[ETH_ALEN];
	uint16_t beaconperiod;
	uint16_t capability;

	/* SSID */
	const char* ssid;
	int ssid_hidden;

	/* Supported Rates */
	int supportedratescount;
	uint8_t supportedrates[IEEE80211_SUPPORTEDRATE_MAX_COUNT];

	/* DSSS */
	uint8_t channel;

	/* ERP */
	uint32_t erpmode;
};

int ieee80211_create_beacon(char* buffer, int length, struct ieee80211_beacon_params* params);

/* Management Probe Response */
struct ieee80211_probe_response_params {
	/* Header information */
	uint8_t bssid[ETH_ALEN];
	uint16_t beaconperiod;
	uint16_t capability;

	/* SSID */
	const char* ssid;

	/* Supported Rates */
	int supportedratescount;
	uint8_t supportedrates[IEEE80211_SUPPORTEDRATE_MAX_COUNT];

	/* DSSS */
	uint8_t channel;

	/* ERP */
	uint32_t erpmode;
};

int ieee80211_create_probe_response(char* buffer, int length, const struct ieee80211_header_mgmt* proberequestheader, struct ieee80211_probe_response_params* params);

/* Management Authentication */
struct ieee80211_authentication_params {
	/* Header information */
	uint8_t bssid[ETH_ALEN];
	uint16_t algorithm;
	uint16_t transactionseqnumber;
	uint16_t statuscode;
};

int ieee80211_create_authentication_response(char* buffer, int length, const struct ieee80211_header_mgmt* authenticationheader, struct ieee80211_authentication_params* params);

#endif /* __CAPWAP_IEEE802_11_HEADER__ */
