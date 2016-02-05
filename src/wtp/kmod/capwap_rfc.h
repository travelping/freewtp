#ifndef __KMOD_CAPWAP_RFC_HEADER__
#define __KMOD_CAPWAP_RFC_HEADER__

#include <linux/types.h>
#include <asm/byteorder.h>

/* */
#define CAPWAP_RADIOID_MAX_COUNT					31
#define IS_VALID_RADIOID(x)							((x >= 1) && (x <= CAPWAP_RADIOID_MAX_COUNT))

#define CAPWAP_WLANID_MAX_COUNT						16
#define IS_VALID_WLANID(x)							((x >= 1) && (x <= CAPWAP_WLANID_MAX_COUNT))

/* */
#define CAPWAP_WIRELESS_BINDING_NONE				0
#define CAPWAP_WIRELESS_BINDING_IEEE80211			1

/* */
#define CAPWAP_ELEMENT_SESSIONID		35

/* */
#define CAPWAP_KEEPALIVE_SIZE			(sizeof(struct sc_capwap_dtls_header) + \
										 sizeof(struct sc_capwap_header) + \
										 sizeof(struct sc_capwap_data_message) + \
										 sizeof(struct sc_capwap_message_element) + \
										 sizeof(struct sc_capwap_sessionid_element))

/* Preamble */
struct sc_capwap_preamble {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint8_t version: 4,
			type: 4;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t type: 4,
			version: 4;
#endif
} __packed;

/* DTLS header */
struct sc_capwap_dtls_header {
	struct sc_capwap_preamble preamble;
	uint8_t reserved[3];
} __packed;

/* Plain header */
struct sc_capwap_header {
	struct sc_capwap_preamble preamble;
#if defined(__BIG_ENDIAN_BITFIELD)
	uint16_t hlen: 5,
			 rid: 5,
			 wbid: 5,
			 flag_t: 1;
	uint8_t flag_f: 1,
			flag_l: 1,
			flag_w: 1,
			flag_m: 1,
			flag_k: 1,
			flag_res: 3;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint16_t _rid_hi: 3,
			 hlen: 5,
			 flag_t: 1,
			 wbid: 5,
			 _rid_lo: 2;
	uint8_t flag_res: 3,
			flag_k: 1,
			flag_m: 1,
			flag_w: 1,
			flag_l: 1,
			flag_f: 1;
#endif
	__be16 frag_id;
	__be16 frag_off;
} __packed;

/* Mac Address */
#define CAPWAP_RADIO_EUI48_LENGTH_PADDED			8
#define CAPWAP_RADIO_EUI64_LENGTH_PADDED			12
#define CAPWAP_RADIO_MAX_LENGTH_PADDED				12
struct sc_capwap_radio_addr {
	uint8_t length;
	uint8_t addr[0];
} __packed;

/* Wireless Information */
#define CAPWAP_WINFO_FRAMEINFO_LENGTH_PADDED		8
#define CAPWAP_WINFO_DESTWLAN_LENGTH_PADDED			8
#define CAPWAP_WINFO_MAX_LENGTH_PADDED				8
struct sc_capwap_wireless_information {
	uint8_t length;
} __packed;

/* IEEE802.11 Wireless Information */
struct sc_capwap_ieee80211_frame_info {
	uint8_t rssi;
	uint8_t snr;
	__be16 rate;
} __packed;

/* Destination WLANs */
struct sc_capwap_destination_wlans {
	__be16 wlanidbitmap;
	__be16 reserved;
} __packed;

/* */
#define CAPWAP_HEADER_MAX_LENGTH					(sizeof(struct sc_capwap_header) + CAPWAP_RADIO_MAX_LENGTH_PADDED + CAPWAP_WINFO_MAX_LENGTH_PADDED)

/* Data channel message */
struct sc_capwap_data_message {
	__be16 length;
} __packed;

/* Message element */
struct sc_capwap_message_element {
	__be16 type;
	__be16 length;
} __packed;

/* Session id message element */
struct sc_capwap_sessionid_element {
	union {
		uint8_t id[16];
		uint32_t id32[4];
	};
} __packed;

/* */
#define MACADDRESS_EUI48_LENGTH				6
struct sc_capwap_macaddress_eui48 {
	uint8_t addr[MACADDRESS_EUI48_LENGTH];
} __packed;

/* */
#define MACADDRESS_EUI64_LENGTH				8
struct sc_capwap_macaddress_eui64 {
	uint8_t addr[MACADDRESS_EUI64_LENGTH];
} __packed;

/* Capwap preamble */
#define CAPWAP_PROTOCOL_VERSION			0
#define CAPWAP_PREAMBLE_HEADER			0
#define CAPWAP_PREAMBLE_DTLS_HEADER		1

#define CAPWAP_WIRELESS_BINDING_NONE			0
#define CAPWAP_WIRELESS_BINDING_IEEE80211		1

/* */
#define CAPWAP_KEEP_ALIVE_MAX_SIZE			(sizeof(struct sc_capwap_header) + sizeof(struct sc_capwap_data_message) + sizeof(struct sc_capwap_message_element) + sizeof(struct sc_capwap_sessionid_element))

/* */
#define GET_VERSION_HEADER(x)				((x)->preamble.version)
#define SET_VERSION_HEADER(x, y)			((x)->preamble.version = (uint8_t)(y))
#define GET_TYPE_HEADER(x)					((x)->preamble.type)
#define SET_TYPE_HEADER(x, y)				((x)->preamble.type = (uint8_t)(y))

#define GET_HLEN_HEADER(x)					((x)->hlen)
#define SET_HLEN_HEADER(x, y)				((x)->hlen = (uint16_t)(y))
#if defined(__BIG_ENDIAN_BITFIELD)
	#define GET_RID_HEADER(x)				((uint8_t)((x)->rid))
	#define SET_RID_HEADER(x, y)			((x)->rid = (uint16_t)(y))
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	#define GET_RID_HEADER(x)				((uint8_t)((uint16_t)((x)->_rid_hi << 2 | (x)->_rid_lo)))
	#define SET_RID_HEADER(x, y)			({ (x)->_rid_hi = (uint16_t)((y) >> 2); (x)->_rid_lo = (uint16_t)((y) & 0x0003); })
#endif
#define GET_WBID_HEADER(x)					((uint8_t)((x)->wbid))
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

/* IEEE 802.11 Add WLAN */
#define CAPWAP_ADD_WLAN_TUNNELMODE_LOCAL			0
#define CAPWAP_ADD_WLAN_TUNNELMODE_8023				1
#define CAPWAP_ADD_WLAN_TUNNELMODE_80211			2

#endif /* __KMOD_CAPWAP_RFC_HEADER__ */
