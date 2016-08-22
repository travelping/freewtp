#ifndef __CAPWAP_PROTOCOL_HEADER__
#define __CAPWAP_PROTOCOL_HEADER__

#include "element.h"
#include "network.h"
#include "dtls.h"

#define CAPWAP_RADIOID_NONE						0

#define CAPWAP_WIRELESS_BINDING_NONE			0
#define CAPWAP_WIRELESS_BINDING_IEEE80211		1
#define CAPWAP_WIRELESS_BINDING_EPCGLOBAL		3

/* Sanity check packet */
#define CAPWAP_WRONG_PACKET				-1
#define CAPWAP_NONE_PACKET				0
#define CAPWAP_PLAIN_PACKET				1
#define CAPWAP_DTLS_PACKET				2
int capwap_sanity_check(int state, void* buffer, int buffersize, int dtlsenable);

/* Fragment management */
struct capwap_fragment_packet_item {
	unsigned short size;
	unsigned short offset;
	char buffer[0];
};

/* Capwap header function */
struct capwap_header_data {
	char headerbuffer[CAPWAP_HEADER_MAX_SIZE];
};

void capwap_header_init(struct capwap_header_data* data, unsigned short radioid, unsigned short binding);
void capwap_header_set_radio_macaddress(struct capwap_header_data* data, int radiotype, const uint8_t* macaddress);
void capwap_header_set_wireless_information(struct capwap_header_data* data, void* buffer, unsigned char length);
void capwap_header_set_keepalive_flag(struct capwap_header_data* data, int enable);
void capwap_header_set_nativeframe_flag(struct capwap_header_data* data, int enable);

/* Management tx capwap packet */
struct write_block_from_pos {
	struct capwap_list_item* item;
	unsigned short pos;
};

struct capwap_packet_txmng {
	unsigned short mtu;
	struct capwap_list* fragmentlist;

	/* Capwap header */
	struct capwap_header* header;

	/* Capwap message */
	struct capwap_control_message* ctrlmsg;

	/* Write functions */
	struct capwap_write_message_elements_ops write_ops;
	unsigned short writerpacketsize;
};

/* */
struct capwap_packet_txmng* capwap_packet_txmng_create_ctrl_message(struct capwap_header_data* data, unsigned long type, unsigned char seq, unsigned short mtu);
void capwap_packet_txmng_add_message_element(struct capwap_packet_txmng *txmngpacket,
					     const struct capwap_message_element_id id,
					     void *data);
void capwap_packet_txmng_get_fragment_packets(struct capwap_packet_txmng* txmngpacket, struct capwap_list* fragmentlist, unsigned short fragmentid);
void capwap_packet_txmng_free(struct capwap_packet_txmng* txmngpacket);

/* Management rx capwap packet */
struct read_block_from_pos {
	struct capwap_list_item* item;
	unsigned short pos;
};

struct capwap_packet_rxmng {
	struct capwap_list* fragmentlist;
	unsigned long packetlength;

	/* Capwap header */
	struct capwap_header* header;

	/* Capwap message */
	struct capwap_control_message ctrlmsg;

	/* Position of message elements or binding data */
	struct read_block_from_pos readbodypos;

	/* Read functions */
	struct capwap_read_message_elements_ops read_ops;
	struct read_block_from_pos readpos;
	unsigned short readerpacketallowed;

	struct capwap_list_item* readerfragmentitem;
	unsigned short readerfragmentoffset;
};

/* */
#define CAPWAP_WRONG_FRAGMENT				-1
#define CAPWAP_REQUEST_MORE_FRAGMENT		0
#define CAPWAP_RECEIVE_COMPLETE_PACKET		1

struct capwap_packet_rxmng* capwap_packet_rxmng_create_message(void);
int capwap_packet_rxmng_add_recv_packet(struct capwap_packet_rxmng* rxmngpacket, void* data, int length);
void capwap_packet_rxmng_free(struct capwap_packet_rxmng* rxmngpacket);

/* Parsing a packet sent */
struct capwap_packet_rxmng* capwap_packet_rxmng_create_from_requestfragmentpacket(struct capwap_list* requestfragmentpacket);

/* */
int capwap_is_request_type(unsigned long type);

/* Check capwap message type */
#define VALID_MESSAGE_TYPE					0
#define INVALID_MESSAGE_TYPE				1
#define INVALID_REQUEST_MESSAGE_TYPE		2
int capwap_check_message_type(struct capwap_packet_rxmng* rxmngpacket);

#endif /* __CAPWAP_PROTOCOL_HEADER__ */
