#ifndef __CAPWAP_RFC_HEADER__
#define __CAPWAP_RFC_HEADER__

#include <inttypes.h>

#ifndef STRUCT_PACKED
#define STRUCT_PACKED					__attribute__((__packed__))
#endif

#define CAPWAP_PROTOCOL_VERSION			0

#define CAPWAP_MTU_DEFAULT				1400
#define CAPWAP_DONT_FRAGMENT			0

/* Capwap preamble */
#define CAPWAP_PREAMBLE_HEADER			0
#define CAPWAP_PREAMBLE_DTLS_HEADER		1

struct capwap_preamble {
#ifdef CAPWAP_BIG_ENDIAN
	uint8_t version : 4;
	uint8_t type : 4;
#else
	uint8_t type : 4;
	uint8_t version : 4;
#endif
} STRUCT_PACKED;

/* Capwap DTLS header */
struct capwap_dtls_header {
	struct capwap_preamble preamble;
	uint8_t reserved1;
	uint8_t reserved2;
	uint8_t reserved3;
} STRUCT_PACKED;

/* Capwap header: 8 (header) + 12 (radio mac) + 256 (wireless info) */
#define CAPWAP_HEADER_MAX_SIZE			276
struct capwap_header {
	struct capwap_preamble preamble;
#ifdef CAPWAP_BIG_ENDIAN
	uint16_t hlen : 5;
	uint16_t rid : 5;
	uint16_t wbid : 5;
	uint16_t flag_t : 1;
	uint8_t flag_f : 1;
	uint8_t flag_l : 1;
	uint8_t flag_w : 1;
	uint8_t flag_m : 1;
	uint8_t flag_k : 1;
	uint8_t flag_res : 3;
#else
	uint16_t _rid_hi : 3;
	uint16_t hlen : 5;
	uint16_t flag_t : 1;
	uint16_t wbid : 5;
	uint16_t _rid_lo : 2;
	uint8_t flag_res : 3;
	uint8_t flag_k : 1;
	uint8_t flag_m : 1;
	uint8_t flag_w : 1;
	uint8_t flag_l : 1;
	uint8_t flag_f : 1;
#endif
	uint16_t frag_id;
	uint16_t frag_off;	/* Only first 13 bit */
} STRUCT_PACKED;

#define FRAGMENT_OFFSET_MASK		0xfff8

/* Mac Address */
struct capwap_mac_address {
	uint8_t length;
	int8_t address[0];
} STRUCT_PACKED;

/* Wireless Information */
struct capwap_wireless_information {
	uint8_t length;
	int8_t data[0];
} STRUCT_PACKED;

/* Message element */
struct capwap_message_element {
	uint16_t type;
	uint16_t length;
	int8_t data[0];
} STRUCT_PACKED;

/* Control Message Type */
#define CAPWAP_FIRST_MESSAGE_TYPE					1
#define CAPWAP_DISCOVERY_REQUEST					1
#define CAPWAP_DISCOVERY_RESPONSE					2
#define CAPWAP_JOIN_REQUEST							3
#define CAPWAP_JOIN_RESPONSE						4
#define CAPWAP_CONFIGURATION_STATUS_REQUEST			5
#define CAPWAP_CONFIGURATION_STATUS_RESPONSE		6
#define CAPWAP_CONFIGURATION_UPDATE_REQUEST			7
#define CAPWAP_CONFIGURATION_UPDATE_RESPONSE		8
#define CAPWAP_WTP_EVENT_REQUEST					9
#define CAPWAP_WTP_EVENT_RESPONSE					10
#define CAPWAP_CHANGE_STATE_EVENT_REQUEST			11
#define CAPWAP_CHANGE_STATE_EVENT_RESPONSE			12
#define CAPWAP_ECHO_REQUEST							13
#define CAPWAP_ECHO_RESPONSE						14
#define CAPWAP_IMAGE_DATA_REQUEST					15
#define CAPWAP_IMAGE_DATA_RESPONSE					16
#define CAPWAP_RESET_REQUEST						17
#define CAPWAP_RESET_RESPONSE						18
#define CAPWAP_PRIMARY_DISCOVERY_REQUEST			19
#define CAPWAP_PRIMARY_DISCOVERY_RESPONSE			20
#define CAPWAP_DATA_TRANSFER_REQUEST				21
#define CAPWAP_DATA_TRANSFER_RESPONSE				22
#define CAPWAP_CLEAR_CONFIGURATION_REQUEST			23
#define CAPWAP_CLEAR_CONFIGURATION_RESPONSE			24
#define CAPWAP_STATION_CONFIGURATION_REQUEST		25
#define CAPWAP_STATION_CONFIGURATION_RESPONSE		26
#define CAPWAP_LAST_MESSAGE_TYPE					26

/* Control Message */
#define CAPWAP_CONTROL_MESSAGE_MIN_LENGTH			3

struct capwap_control_message {
	uint32_t type;
	uint8_t seq;
	uint16_t length;
	uint8_t flags;
	int8_t elements[0];
} STRUCT_PACKED;

/* Data Message Keep-Alive*/
#define CAPWAP_DATA_MESSAGE_KEEPALIVE_MIN_LENGTH	2

struct capwap_data_message {
	uint16_t length;
	int8_t elements[0];
} STRUCT_PACKED;

/* Capwap dtls header helper */
#define GET_DTLS_BODY(x)					(void*)(((int8_t*)(x)) + sizeof(struct capwap_dtls_header))

/* Capwap header helper */
#define GET_VERSION_HEADER(x)				((x)->preamble.version)
#define SET_VERSION_HEADER(x, y)			((x)->preamble.version = (uint8_t)(y))
#define GET_TYPE_HEADER(x)					((x)->preamble.type)
#define SET_TYPE_HEADER(x, y)				((x)->preamble.type = (uint8_t)(y))

#define GET_HLEN_HEADER(x)					((x)->hlen)
#define SET_HLEN_HEADER(x, y)				((x)->hlen = (uint16_t)(y))
#ifdef CAPWAP_BIG_ENDIAN
	#define GET_RID_HEADER(x)				((x)->rid)
	#define SET_RID_HEADER(x, y)			((x)->rid = (uint16_t)(y))
#else
	#define GET_RID_HEADER(x)				((uint16_t)((x)->_rid_hi << 2 | (x)->_rid_lo))
	#define SET_RID_HEADER(x, y)			({ (x)->_rid_hi = (uint16_t)((y) >> 2); (x)->_rid_lo = (uint16_t)((y) & 0x0003); })
#endif
#define GET_WBID_HEADER(x)					((x)->wbid)
#define SET_WBID_HEADER(x, y)				((x)->wbid = (uint16_t)(y))

#define IS_FLAG_T_HEADER(x)					((x)->flag_t)
#define SET_FLAG_T_HEADER(x, y)				((x)->flag_t = ((y) ? 1 : 0))
#define IS_FLAG_F_HEADER(x)					((x)->flag_f)
#define SET_FLAG_F_HEADER(x, y)				((x)->flag_f = ((y) ? 1 : 0))
#define IS_FLAG_L_HEADER(x)					((x)->flag_l)
#define SET_FLAG_L_HEADER(x, y)				((x)->flag_l = ((y) ? 1 : 0))
#define IS_FLAG_W_HEADER(x)					((x)->flag_w)
#define SET_FLAG_W_HEADER(x, y)				((x)->flag_w = ((y) ? 1 : 0))
#define IS_FLAG_M_HEADER(x)					((x)->flag_m)
#define SET_FLAG_M_HEADER(x, y)				((x)->flag_m = ((y) ? 1 : 0))
#define IS_FLAG_K_HEADER(x)					((x)->flag_k)
#define SET_FLAG_K_HEADER(x, y)				((x)->flag_k = ((y) ? 1 : 0))

#define GET_FRAGMENT_ID_HEADER(x)			(ntohs((x)->frag_id))
#define SET_FRAGMENT_ID_HEADER(x, y)		((x)->frag_id = htons((uint16_t)(y)))
#define GET_FRAGMENT_OFFSET_HEADER(x)		(ntohs((x)->frag_off) & FRAGMENT_OFFSET_MASK)
#define SET_FRAGMENT_OFFSET_HEADER(x, y)	((x)->frag_off &= ~FRAGMENT_OFFSET_MASK, (x)->frag_off |= htons((uint16_t)(y) & FRAGMENT_OFFSET_MASK))

#define GET_RADIO_MAC_ADDRESS_STRUCT(x)		((struct capwap_mac_address*)(((int8_t*)(x)) + sizeof(struct capwap_header)))
#define GET_WIRELESS_INFORMATION_STRUCT(x)	((struct capwap_wireless_information*)(((int8_t*)(x)) + sizeof(struct capwap_header) + (IS_FLAG_M_HEADER(x) ? (((GET_RADIO_MAC_ADDRESS_STRUCT(x)->length + sizeof(struct capwap_mac_address)) + 3) / 4) * 4 : 0)))
#define GET_PAYLOAD_HEADER(x)				((void*)(((int8_t*)(x)) + GET_HLEN_HEADER(x) * 4))

#define IS_SEQUENCE_SMALLER(s1, s2)			(((((s1) < (s2)) && (((s2) - (s1)) < 128)) || (((s1) > (s2)) && (((s1) - (s2)) > 128))) ? 1 : 0)

/* */
#define MACADDRESS_EUI48_LENGTH				6
struct capwap_macaddress_eui48 {
	uint8_t macaddress[MACADDRESS_EUI48_LENGTH];
} STRUCT_PACKED;

/* */
#define MACADDRESS_EUI64_LENGTH				8
struct capwap_macaddress_eui64 {
	uint8_t macaddress[MACADDRESS_EUI64_LENGTH];
} STRUCT_PACKED;

#define IS_VALID_MACADDRESS_LENGTH(x)		((x == MACADDRESS_EUI48_LENGTH) || (x == MACADDRESS_EUI64_LENGTH))

#define IS_VALID_RADIOID(x)					((x >= 1) && (x <= 31))
#define IS_VALID_WLANID(x)					((x >= 1) && (x <= 16))

/* Standard message elements 1 -> 52 (1 - 1023) */
#define CAPWAP_MESSAGE_ELEMENTS_START				1
#define CAPWAP_MESSAGE_ELEMENTS_STOP				53
#define CAPWAP_MESSAGE_ELEMENTS_COUNT				((CAPWAP_MESSAGE_ELEMENTS_STOP - CAPWAP_MESSAGE_ELEMENTS_START) + 1)
#define IS_MESSAGE_ELEMENTS(x)						(((x >= CAPWAP_MESSAGE_ELEMENTS_START) && (x <= CAPWAP_MESSAGE_ELEMENTS_STOP)) ? 1 : 0)

/* 802.11 message elements 1024 -> 1024 (1024 - 2047) */
#define CAPWAP_80211_MESSAGE_ELEMENTS_START			1024
#define CAPWAP_80211_MESSAGE_ELEMENTS_STOP			1048
#define CAPWAP_80211_MESSAGE_ELEMENTS_COUNT			((CAPWAP_80211_MESSAGE_ELEMENTS_STOP - CAPWAP_80211_MESSAGE_ELEMENTS_START) + 1)
#define IS_80211_MESSAGE_ELEMENTS(x)				(((x >= CAPWAP_80211_MESSAGE_ELEMENTS_START) && (x <= CAPWAP_80211_MESSAGE_ELEMENTS_STOP)) ? 1 : 0)

#endif /* __CAPWAP_RFC_HEADER__ */
