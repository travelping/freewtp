#ifndef __CAPWAP_PROTOCOL_HEADER__
#define __CAPWAP_PROTOCOL_HEADER__

#include "capwap_element.h"
#include "capwap_network.h"
#include "capwap_dtls.h"

#define CAPWAP_PROTOCOL_VERSION			0

#define CAPWAP_MTU_DEFAULT				1400
#define CAPWAP_DONT_FRAGMENT			0

/* Capwap preamble */
#define CAPWAP_PREAMBLE_HEADER			0
#define CAPWAP_PREAMBLE_DTLS_HEADER		1

struct capwap_preamble {
#ifdef CAPWAP_BIG_ENDIAN
	unsigned char version : 4;
	unsigned char type : 4;
#else
	unsigned char type : 4;
	unsigned char version : 4;
#endif
} __attribute__((__packed__));

/* Capwap DTLS header */
struct capwap_dtls_header {
	struct capwap_preamble preamble;
	unsigned char reserved1;
	unsigned char reserved2;
	unsigned char reserved3;
} __attribute__((__packed__));

/* Capwap header: 8 (header) + 12 (radio mac) + 256 (wireless info) */
#define CAPWAP_HEADER_MAX_SIZE			276	
struct capwap_header {
	struct capwap_preamble preamble;
#ifdef CAPWAP_BIG_ENDIAN
	unsigned short hlen : 5;
	unsigned short rid : 5;
	unsigned short wbid : 5;
	unsigned short flag_t : 1;
	unsigned char flag_f : 1;
	unsigned char flag_l : 1;
	unsigned char flag_w : 1;
	unsigned char flag_m : 1;
	unsigned char flag_k : 1;
	unsigned char flag_res : 3;
#else
	unsigned short _rid_hi : 3;
	unsigned short hlen : 5;
	unsigned short flag_t : 1;
	unsigned short wbid : 5;
	unsigned short _rid_lo : 2;
	unsigned char flag_res : 3;
	unsigned char flag_k : 1;
	unsigned char flag_m : 1;
	unsigned char flag_w : 1;
	unsigned char flag_l : 1;
	unsigned char flag_f : 1;
#endif
	unsigned short frag_id;
	unsigned short frag_off;	/* Only first 13 bit */
} __attribute__((__packed__));

#define FRAGMENT_OFFSET_MASK		0xfff8

/* Mac Address */
struct capwap_mac_address {
	unsigned char length;
	char address[0];
} __attribute__((__packed__));

/* Wireless Information */
struct capwap_wireless_information {
	unsigned char length;
	char data[0];
} __attribute__((__packed__));

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
struct capwap_control_message {
	unsigned long type;
	unsigned char seq;
	unsigned short length;
	unsigned char flags;
	char elements[0];
} __attribute__((__packed__));

/* Data Message */
struct capwap_data_message {
	unsigned short length;
	char elements[0];
} __attribute__((__packed__));

/* Capwap dtls header helper */
#define GET_DTLS_BODY(x)					(void*)(((char*)(x)) + sizeof(struct capwap_dtls_header))

/* Capwap header helper */
#define GET_VERSION_HEADER(x)				((x)->preamble.version)
#define SET_VERSION_HEADER(x, y)			((x)->preamble.version = (unsigned char)(y))
#define GET_TYPE_HEADER(x)					((x)->preamble.type)
#define SET_TYPE_HEADER(x, y)				((x)->preamble.type = (unsigned char)(y))

#define GET_HLEN_HEADER(x)					((x)->hlen)
#define SET_HLEN_HEADER(x, y)				((x)->hlen = (unsigned short)(y))
#ifdef CAPWAP_BIG_ENDIAN
	#define GET_RID_HEADER(x)				((x)->rid)
	#define SET_RID_HEADER(x, y)			((x)->rid = (unsigned short)(y))
#else
	#define GET_RID_HEADER(x)				((unsigned short)((x)->_rid_hi << 2 | (x)->_rid_lo))
	#define SET_RID_HEADER(x, y)			({ (x)->_rid_hi = (unsigned short)((y) >> 2); (x)->_rid_lo = (unsigned short)((y) & 0x0003); })
#endif
#define GET_WBID_HEADER(x)					((x)->wbid)
#define SET_WBID_HEADER(x, y)				((x)->wbid = (unsigned short)(y))

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
#define SET_FRAGMENT_ID_HEADER(x, y)		((x)->frag_id = htons((unsigned short)(y)))
#define GET_FRAGMENT_OFFSET_HEADER(x)		(ntohs((x)->frag_off) & FRAGMENT_OFFSET_MASK)
#define SET_FRAGMENT_OFFSET_HEADER(x, y)	((x)->frag_off &= ~FRAGMENT_OFFSET_MASK, (x)->frag_off |= htons((unsigned short)(y) & FRAGMENT_OFFSET_MASK))

#define GET_RADIO_MAC_ADDRESS_STRUCT(x)		((struct capwap_mac_address*)(((char*)(x)) + sizeof(struct capwap_header)))
#define GET_WIRELESS_INFORMATION_STRUCT(x)	((struct capwap_wireless_information*)(((char*)(x)) + sizeof(struct capwap_header) + (IS_FLAG_M_HEADER(x) ? (((GET_RADIO_MAC_ADDRESS_STRUCT(x)->length + sizeof(struct capwap_mac_address)) + 3) / 4) * 4 : 0)))
#define GET_PAYLOAD_HEADER(x)				((void*)(((char*)(x)) + GET_HLEN_HEADER(x) * 4))

#define IS_SEQUENCE_SMALLER(s1, s2)			(((((s1) < (s2)) && (((s2) - (s1)) < 128)) || (((s1) > (s2)) && (((s1) - (s2)) > 128))) ? 1 : 0)
	
/*********************************************************************************************************************/
/* Sanity check packet */
#define CAPWAP_WRONG_PACKET				-1
#define CAPWAP_NONE_PACKET				0
#define CAPWAP_PLAIN_PACKET				1
#define CAPWAP_DTLS_PACKET				2
int capwap_sanity_check(int isctrlsocket, int state, void* buffer, int buffersize, int dtlsctrlenable, int dtlsdataenable);

/* Fragment packet */
struct capwap_fragment_packet {
	void* buffer;
	int size;
	unsigned short offset;
};

/* Fragment control list */
struct capwap_fragment_sender {
	struct sockaddr_storage sendaddr;
	unsigned short fragment_id;
	int islastrecv;
	
	/* Packet */
	struct capwap_header* header;
	struct capwap_list* packetlist;
};

typedef struct capwap_list capwap_fragment_list;

/* Packet */
struct capwap_packet {
	unsigned short packetsize;
	struct capwap_header* header;
	void* payload;
	struct sockaddr_storage localaddr;
	struct sockaddr_storage remoteaddr;
	struct capwap_socket socket;
};

#define CAPWAP_WRONG_FRAGMENT			-1
#define CAPWAP_REQUEST_MORE_FRAGMENT		0
#define CAPWAP_RECEIVE_COMPLETE_PACKET		1
int capwap_defragment_packets(struct sockaddr_storage* sendaddr, void* buffer, int buffersize, capwap_fragment_list* defraglist, struct capwap_packet* packet);

capwap_fragment_list* capwap_defragment_init_list(void);
void capwap_defragment_flush_list(capwap_fragment_list* defraglist);
void capwap_defragment_free_list(capwap_fragment_list* defraglist);

int capwap_defragment_remove_sender(capwap_fragment_list* defraglist, struct sockaddr_storage* sendaddr);
struct capwap_fragment_sender* capwap_defragment_find_sender(capwap_fragment_list* defraglist, struct sockaddr_storage* sendaddr);

void capwap_free_packet(struct capwap_packet* packet);

/* Build tx packet */
struct capwap_build_packet {
	union {
		struct capwap_header header;
		char headerbuffer[CAPWAP_HEADER_MAX_SIZE];
	};
	
	/* Control Packet */
	int isctrlmsg;
	union {
		struct capwap_control_message ctrlmsg;
		struct capwap_data_message datamsg;
	};
	
	/* Message element */
	struct capwap_list* elementslist;
};

#define CAPWAP_RADIOID_NONE						0
#define CAPWAP_WIRELESS_BINDING_NONE			0
#define CAPWAP_WIRELESS_BINDING_IEEE80211		1
#define CAPWAP_WIRELESS_BINDING_EPCGLOBAL		3

struct capwap_build_packet* capwap_tx_packet_create(unsigned short radioid, unsigned short binding);
struct capwap_build_packet* capwap_rx_packet_create(void* buffer, int buffersize, int isctrlpacket);
void capwap_build_packet_free(struct capwap_build_packet* buildpacket);
void capwap_build_packet_set_radio_macaddress(struct capwap_build_packet* buildpacket, int radiotype, char* macaddress);
void capwap_build_packet_set_wireless_information(struct capwap_build_packet* buildpacket, void* buffer, unsigned char length);
void capwap_build_packet_set_control_message_type(struct capwap_build_packet* buildpacket, unsigned long type, unsigned char seq);
void capwap_build_packet_add_message_element(struct capwap_build_packet* buildpacket, struct capwap_message_element* element);

#define CAPWAP_VALID_PACKET							0x00000000
#define CAPWAP_MISSING_MANDATORY_MSG_ELEMENT		0x00000001
#define CAPWAP_UNRECOGNIZED_MSG_ELEMENT				0x00000002

struct unrecognized_info {
	unsigned short element;
	unsigned char reason;
};

typedef struct capwap_array capwap_unrecognized_element_array;
unsigned long capwap_build_packet_validate(struct capwap_build_packet* buildpacket, capwap_unrecognized_element_array* reasonarray);

typedef struct capwap_array capwap_fragment_packet_array;
int capwap_fragment_build_packet(struct capwap_build_packet* buildpacket, capwap_fragment_packet_array* packets, unsigned short mtu, unsigned short fragmentid);
void capwap_fragment_free(capwap_fragment_packet_array* packets);

int capwap_is_request_type(unsigned long type);
void capwap_get_packet_digest(void* buffer, unsigned long length, unsigned char packetdigest[16]);
int capwap_recv_retrasmitted_request(struct capwap_dtls* dtls, struct capwap_packet* packet, unsigned char lastseqnumber, unsigned char packetdigest[16], struct capwap_socket* sock, capwap_fragment_packet_array* txfragmentpacket, struct sockaddr_storage* sendfromaddr, struct sockaddr_storage* sendtoaddr);

int capwap_check_message_type(struct capwap_dtls* dtls, struct capwap_packet* packet, unsigned short mtu);

int capwap_get_sessionid_from_keepalive(struct capwap_build_packet* buildpacket, struct capwap_sessionid_element* session);

#endif /* __CAPWAP_PROTOCOL_HEADER__ */
