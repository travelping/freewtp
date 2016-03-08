#include "capwap.h"
#include "capwap_protocol.h"
#include "capwap_network.h"
#include "capwap_dfa.h"
#include "capwap_list.h"
#include "capwap_array.h"

/* Check valid packet */
int capwap_sanity_check(int state, void* buffer, int buffersize, int dtlsenable) {
	struct capwap_preamble* preamble;

	ASSERT(buffer != NULL);
	ASSERT(buffersize > sizeof(struct capwap_preamble));

	preamble = (struct capwap_preamble*)buffer;
	if (preamble->version != CAPWAP_PROTOCOL_VERSION) {
		return CAPWAP_WRONG_PACKET;
	}

	if (dtlsenable) {
		if ((preamble->type == CAPWAP_PREAMBLE_DTLS_HEADER) && (buffersize >= sizeof(struct capwap_dtls_header))) {
			if (state == CAPWAP_DISCOVERY_STATE) {
				return CAPWAP_WRONG_PACKET;
			}

			return CAPWAP_DTLS_PACKET;
		} else if ((preamble->type == CAPWAP_PREAMBLE_HEADER) && (buffersize >= sizeof(struct capwap_header))) {
			struct capwap_header* header = (struct capwap_header*)preamble;
			if (buffersize >= GET_HLEN_HEADER(header) * 4) {
				if ((state != CAPWAP_DISCOVERY_STATE) && (state != CAPWAP_UNDEF_STATE)) {
					return CAPWAP_WRONG_PACKET;
				}

				return CAPWAP_PLAIN_PACKET;
			}
		}
	} else {
		if ((preamble->type == CAPWAP_PREAMBLE_HEADER) && (buffersize >= sizeof(struct capwap_header))) {
			struct capwap_header* header = (struct capwap_header*)preamble;
			if (buffersize >= GET_HLEN_HEADER(header) * 4) {
				return CAPWAP_PLAIN_PACKET;
			}
		}
	}

	return CAPWAP_WRONG_PACKET;
}

/* Detect if type is a request */
int capwap_is_request_type(unsigned long type) {
	if ((type == CAPWAP_DISCOVERY_REQUEST) ||
		(type == CAPWAP_JOIN_REQUEST) ||
		(type == CAPWAP_CONFIGURATION_STATUS_REQUEST) ||
		(type == CAPWAP_CONFIGURATION_UPDATE_REQUEST) ||
		(type == CAPWAP_WTP_EVENT_REQUEST) ||
		(type == CAPWAP_CHANGE_STATE_EVENT_REQUEST) ||
		(type == CAPWAP_ECHO_REQUEST) ||
		(type == CAPWAP_IMAGE_DATA_REQUEST) ||
		(type == CAPWAP_RESET_REQUEST) ||
		(type == CAPWAP_PRIMARY_DISCOVERY_REQUEST) ||
		(type == CAPWAP_DATA_TRANSFER_REQUEST) ||
		(type == CAPWAP_CLEAR_CONFIGURATION_REQUEST) ||
		(type == CAPWAP_STATION_CONFIGURATION_REQUEST) ||
		(type == CAPWAP_IEEE80211_WLAN_CONFIGURATION_REQUEST)) {

		/* Request type */
		return 1;
	}

	return 0;
}

/* Check valid message type */
int capwap_check_message_type(struct capwap_packet_rxmng* rxmngpacket) {
	unsigned short lengthpayload;

	ASSERT(rxmngpacket != NULL);

	if (rxmngpacket->fragmentlist->first) {
		struct capwap_fragment_packet_item* packet = (struct capwap_fragment_packet_item*)rxmngpacket->fragmentlist->first->item;
		struct capwap_header* header = (struct capwap_header*)packet->buffer;
		unsigned short binding = GET_WBID_HEADER(rxmngpacket->header);

		lengthpayload = packet->offset - GET_HLEN_HEADER(header) * 4;
		if (lengthpayload >= sizeof(struct capwap_control_message)) {
			if (CAPWAP_VALID_MESSAGE_TYPE(rxmngpacket->ctrlmsg.type)) {
				return VALID_MESSAGE_TYPE;
			} else if ((binding == CAPWAP_WIRELESS_BINDING_IEEE80211) && CAPWAP_VALID_IEEE80211_MESSAGE_TYPE(rxmngpacket->ctrlmsg.type)) {
				return VALID_MESSAGE_TYPE;
			}

			/* Unknown message type */
			if ((rxmngpacket->ctrlmsg.type % 2) != 0) {
				return INVALID_REQUEST_MESSAGE_TYPE;
			}
		}
	}

	return INVALID_MESSAGE_TYPE;
}

/* */
void capwap_header_init(struct capwap_header_data* data, unsigned short radioid, unsigned short binding) {
	struct capwap_header* header;

	ASSERT(data != NULL);

	/* */
	header = (struct capwap_header*)&data->headerbuffer[0];
	memset(header, 0, sizeof(struct capwap_header));

	/* Standard configuration */
	SET_VERSION_HEADER(header, CAPWAP_PROTOCOL_VERSION);
	SET_TYPE_HEADER(header, CAPWAP_PREAMBLE_HEADER);
	SET_HLEN_HEADER(header, sizeof(struct capwap_header) / 4);
	SET_RID_HEADER(header, radioid);
	SET_WBID_HEADER(header, binding);
}

/* */
void capwap_header_set_radio_macaddress(struct capwap_header_data* data, int radiotype, const uint8_t* macaddress) {
	struct capwap_header* header;

	ASSERT(data != NULL);

	header = (struct capwap_header*)&data->headerbuffer[0];
	if (radiotype == MACADDRESS_NONE_LENGTH) {
		if (IS_FLAG_M_HEADER(header)) {
			if (!IS_FLAG_W_HEADER(header)) {
				SET_HLEN_HEADER(header, sizeof(struct capwap_header) / 4);
			} else {
				struct capwap_wireless_information* wireless = GET_WIRELESS_INFORMATION_STRUCT(header);
				int lengthpadded = (((sizeof(struct capwap_wireless_information) + wireless->length) + 3) / 4);
				
				/* Move wireless information */
				memmove(((char*)header + sizeof(struct capwap_header)), wireless, lengthpadded * 4);
				SET_HLEN_HEADER(header, (sizeof(struct capwap_header) / 4) + lengthpadded);
			}

			SET_FLAG_M_HEADER(header, 0);
		}
	} else {
		int i;
		int radiosizepadded;
		struct capwap_mac_address* radio;
		int size = sizeof(struct capwap_header) / 4;

		ASSERT(macaddress != NULL);
		ASSERT((radiotype == MACADDRESS_EUI48_LENGTH) || (radiotype == MACADDRESS_EUI64_LENGTH));

		if (IS_FLAG_M_HEADER(header)) {
			radio = GET_RADIO_MAC_ADDRESS_STRUCT(header);

			if (radio->length == radiotype) {
				/* Rewrite mac address */
				memcpy(radio->address, macaddress, radiotype);
				return;
			}

			/* Remove old radio mac address */
			capwap_header_set_radio_macaddress(data, MACADDRESS_NONE_LENGTH, NULL);
		}

		/* Radio mac address size*/
		radio = (struct capwap_mac_address*)((char*)header + sizeof(struct capwap_header));
		radiosizepadded = (((sizeof(struct capwap_mac_address) + radiotype) + 3) / 4);
		size += radiosizepadded;

		/* Wireless information */
		if (IS_FLAG_W_HEADER(header)) {
			struct capwap_wireless_information* wireless = GET_WIRELESS_INFORMATION_STRUCT(header);
			int lengthpadded = (((sizeof(struct capwap_wireless_information) + wireless->length) + 3) / 4);
			
			memmove((char*)radio + radiosizepadded, wireless, lengthpadded * 4);
			size += lengthpadded;
		}

		radio->length = radiotype;
		memcpy(radio->address, macaddress, radiotype);
		for (i = (radiosizepadded * 4) - 2; i >= radiotype; i--) {
			radio->address[i] = 0;
		}

		SET_FLAG_M_HEADER(header, 1);
		SET_HLEN_HEADER(header, size);
	}
}

/* */
void capwap_header_set_wireless_information(struct capwap_header_data* data, void* buffer, unsigned char length) {
	int size;
	struct capwap_header* header;
	
	ASSERT(data != NULL);
	
	header = (struct capwap_header*)&data->headerbuffer[0];

	/* Calculate size of header */
	size = sizeof(struct capwap_header) / 4;
	if (IS_FLAG_M_HEADER(header)) {
		struct capwap_mac_address* radio = GET_RADIO_MAC_ADDRESS_STRUCT(header);
		size += ((sizeof(struct capwap_mac_address) + radio->length) + 3) / 4;
	}

	/* Remove old wireless information */
	if (IS_FLAG_W_HEADER(header)) {
		SET_FLAG_W_HEADER(header, 0);
		SET_HLEN_HEADER(header, size);
	}

	/* Add new wireless information */
	if (length > 0) {
		int i;
		struct capwap_wireless_information* wireless;
		int lengthpadded = (((sizeof(struct capwap_wireless_information) + length) + 3) / 4);

		ASSERT(buffer != NULL);

		wireless = GET_WIRELESS_INFORMATION_STRUCT(header);
		wireless->length = length;
		memcpy(wireless->data, buffer, length);
		for (i = (lengthpadded * 4) - 2; i >= length; i--) {
			wireless->data[i] = 0;
		}

		/* Update size */
		size += lengthpadded;
		SET_FLAG_W_HEADER(header, 1);
		SET_HLEN_HEADER(header, size);
	}
}

/* */
void capwap_header_set_keepalive_flag(struct capwap_header_data* data, int enable) {
	struct capwap_header* header;

	ASSERT(data != NULL);

	header = (struct capwap_header*)&data->headerbuffer[0];
	SET_FLAG_K_HEADER(header, (enable ? 1 : 0));
}

/* */
void capwap_header_set_nativeframe_flag(struct capwap_header_data* data, int enable) {
	struct capwap_header* header;

	ASSERT(data != NULL);

	header = (struct capwap_header*)&data->headerbuffer[0];
	SET_FLAG_T_HEADER(header, (enable ? 1 : 0));
}

/* */
static struct capwap_list_item* capwap_packet_txmng_create_fragment_item(struct capwap_packet_txmng* txmngpacket) {
	struct capwap_list_item* item;
	struct capwap_fragment_packet_item* packet;

	/* Create maxium size of packet */
	item = capwap_itemlist_create(sizeof(struct capwap_fragment_packet_item) + txmngpacket->mtu);
	packet = (struct capwap_fragment_packet_item*)item->item;

	/* */
	memset(packet, 0, sizeof(sizeof(struct capwap_fragment_packet_item) + txmngpacket->mtu));
	packet->size = txmngpacket->mtu;

	/* Append to last position */
	capwap_itemlist_insert_after(txmngpacket->fragmentlist, NULL, item);

	return item;
}

/* */
static int capwap_fragment_write_block_from_pos(struct capwap_packet_txmng* txmngpacket, const uint8_t* data, unsigned short length, struct write_block_from_pos* writepos) {
	unsigned short packetpos;
	struct capwap_list_item* item;
	struct capwap_fragment_packet_item* fragmentpacket;

	ASSERT(txmngpacket != NULL);
	ASSERT(data != NULL);
	ASSERT(length > 0);
	ASSERT(writepos != NULL);

	/* Get fragment packet */
	item = writepos->item;
	packetpos = writepos->pos;
	fragmentpacket = (struct capwap_fragment_packet_item*)item->item;
	ASSERT(packetpos <= fragmentpacket->size);

	/* Write data into one o more fragment packet */
	while (length > 0) {
		unsigned short available = min(length, (fragmentpacket->size - packetpos));

		/* Check if require new fragment */
		if (!available) {
			struct capwap_header* header;

			if (item->next) {
				/* Next packet */
				item = item->next;
				fragmentpacket = (struct capwap_fragment_packet_item*)item->item;

				/* Get capwap header size */
				header = (struct capwap_header*)fragmentpacket->buffer;
				packetpos = GET_HLEN_HEADER(header);
			} else {
				/* Create new fragment packet */
				item = capwap_packet_txmng_create_fragment_item(txmngpacket);
				fragmentpacket = (struct capwap_fragment_packet_item*)item->item;
	
				/* Copy capwap header without macaddress and wireless info */
				memcpy(fragmentpacket->buffer, txmngpacket->header, sizeof(struct capwap_header));
				fragmentpacket->offset += sizeof(struct capwap_header);
				packetpos = fragmentpacket->offset;
	
				/* Normalize packet to multiple of 8 bytes */
				fragmentpacket->size -= (fragmentpacket->size - fragmentpacket->offset) % 8;
	
				/* Radio mac address and wireless information is sent only into first packet */
				header = (struct capwap_header*)fragmentpacket->buffer;
				SET_FLAG_M_HEADER(header, 0);
				SET_FLAG_W_HEADER(header, 0);
				SET_HLEN_HEADER(header, sizeof(struct capwap_header) / 4);
			}

			/* Recalculate space available */
			available = min(length, (fragmentpacket->size - packetpos));
			ASSERT(available > 0);
		}

		/* Write data */
		memcpy(&fragmentpacket->buffer[packetpos], data, available);
		length -= available;
		txmngpacket->writerpacketsize += available;

		if ((available + packetpos) > fragmentpacket->offset) {
			unsigned short oldoffset = fragmentpacket->offset;

			fragmentpacket->offset = available + packetpos;
			txmngpacket->ctrlmsg->length = htons(ntohs(txmngpacket->ctrlmsg->length) + (fragmentpacket->offset - oldoffset));
		}
	}

	return length;
}

/* */
static int capwap_fragment_write_block(capwap_message_elements_handle handle, const uint8_t* data, unsigned short length) {
	struct capwap_packet_txmng* txmngpacket;
	struct write_block_from_pos writepos;

	ASSERT(handle != NULL);
	ASSERT(data != NULL);
	ASSERT(length > 0);

	/* Get last fragment packet */
	txmngpacket = (struct capwap_packet_txmng*)handle;

	/* */
	writepos.item = txmngpacket->fragmentlist->last;
	writepos.pos = ((struct capwap_fragment_packet_item*)writepos.item->item)->offset;

	return capwap_fragment_write_block_from_pos(txmngpacket, data, length, &writepos);
}

/* */
static int capwap_fragment_write_u8(capwap_message_elements_handle handle, uint8_t data) {
	if (capwap_fragment_write_block(handle, &data, sizeof(uint8_t)) != sizeof(uint8_t)) {
		return -1;
	}

	return sizeof(uint8_t);
}

/* */
static int capwap_fragment_write_u16_from_pos(capwap_message_elements_handle handle, uint16_t data, struct write_block_from_pos* writepos) {
	uint16_t temp = htons(data);
	if (capwap_fragment_write_block_from_pos(handle, (uint8_t*)&temp, sizeof(uint16_t), writepos) != sizeof(uint16_t)) {
		return -1;
	}

	return sizeof(uint16_t);
}

/* */
static int capwap_fragment_write_u16(capwap_message_elements_handle handle, uint16_t data) {
	uint16_t temp = htons(data);
	if (capwap_fragment_write_block(handle, (uint8_t*)&temp, sizeof(uint16_t)) != sizeof(uint16_t)) {
		return -1;
	}

	return sizeof(uint16_t);
}

/* */
static int capwap_fragment_write_u32(capwap_message_elements_handle handle, uint32_t data) {
	uint32_t temp = htonl(data);
	if (capwap_fragment_write_block(handle, (uint8_t*)&temp, sizeof(uint32_t)) != sizeof(uint32_t)) {
		return -1;
	}

	return sizeof(uint32_t);
}

/* */
static struct capwap_packet_txmng* capwap_packet_txmng_create(struct capwap_header_data* data, unsigned short mtu) {
	unsigned short headerlength;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_list_item* firstitem;
	struct capwap_fragment_packet_item* fragmentpacket;
	struct capwap_header* header;

	/* */
	txmngpacket = (struct capwap_packet_txmng*)capwap_alloc(sizeof(struct capwap_packet_txmng));
	memset(txmngpacket, 0, sizeof(struct capwap_packet_txmng));

	txmngpacket->mtu = mtu;

	/* Fragment bucket */
	txmngpacket->fragmentlist = capwap_list_create();

	/* First packet */
	firstitem = capwap_packet_txmng_create_fragment_item(txmngpacket);
	fragmentpacket = (struct capwap_fragment_packet_item*)firstitem->item;

	/* Get capwap header information */
	header = (struct capwap_header*)&data->headerbuffer[0];
	headerlength = GET_HLEN_HEADER(header) * 4;

	/* Normalize packet to multiple of 8 bytes */
	fragmentpacket->size -= (fragmentpacket->size - headerlength) % 8;
	ASSERT(headerlength < fragmentpacket->size);

	/* Save capwap header */
	txmngpacket->header = (struct capwap_header*)fragmentpacket->buffer;
	memcpy(txmngpacket->header, header, headerlength);
	fragmentpacket->offset += headerlength;

	/* Configure basic IO write function */
	txmngpacket->write_ops.write_u8 = capwap_fragment_write_u8;
	txmngpacket->write_ops.write_u16 = capwap_fragment_write_u16;
	txmngpacket->write_ops.write_u32 = capwap_fragment_write_u32;
	txmngpacket->write_ops.write_block = capwap_fragment_write_block;

	return txmngpacket;
}

/* */
struct capwap_packet_txmng* capwap_packet_txmng_create_ctrl_message(struct capwap_header_data* data, unsigned long type, unsigned char seq, unsigned short mtu) {
	struct capwap_header* header;
	unsigned short length;
	struct capwap_packet_txmng* txmngpacket;
	struct capwap_fragment_packet_item* fragmentpacket;

	ASSERT(data != NULL);
	ASSERT(mtu > 0);

	header = (struct capwap_header *)data->headerbuffer;
	length = GET_HLEN_HEADER(header) * 4;

	/* Check MTU */
	if ((mtu > 0) && (mtu < (length + sizeof(struct capwap_control_message)))) {
		capwap_logging_debug("The mtu is too small: %hu", mtu);
		return NULL;
	}

	/* Create management packets */
	txmngpacket = capwap_packet_txmng_create(data, mtu);
	if (!txmngpacket) {
		return NULL;
	}

	/* Get single fragment */
	fragmentpacket = (struct capwap_fragment_packet_item*)txmngpacket->fragmentlist->last->item;
	ASSERT((fragmentpacket->offset + sizeof(struct capwap_control_message)) < fragmentpacket->size);

	/* Create message */
	txmngpacket->ctrlmsg = (struct capwap_control_message*)&fragmentpacket->buffer[fragmentpacket->offset];
	txmngpacket->ctrlmsg->type = htonl(type);
	txmngpacket->ctrlmsg->seq = seq;
	txmngpacket->ctrlmsg->length = htons(CAPWAP_CONTROL_MESSAGE_MIN_LENGTH);		/* sizeof(Msg Element Length) + sizeof(Flags) */
	txmngpacket->ctrlmsg->flags = 0;

	/* Prepare for save capwap element */
	fragmentpacket->offset += sizeof(struct capwap_control_message);

	return txmngpacket;
}

/* */
void capwap_packet_txmng_add_message_element(struct capwap_packet_txmng *txmngpacket,
					     const struct capwap_message_element_id id,
					     void *data)
{
	const struct capwap_message_elements_ops* func;
	struct write_block_from_pos writepos;

	ASSERT(txmngpacket != NULL);

	/* Retrieve message element function */
	func = capwap_get_message_element_ops(id);
	ASSERT(func != NULL);
	ASSERT(func->create != NULL);

	/*
		 0                   1                   2                   3
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|              Type             |             Length            |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|   Value ...   |
		+-+-+-+-+-+-+-+-+

		Type and Length is add to this function, only custom create write Value message element
	*/

	if (id.vendor != 0)
		txmngpacket->write_ops.write_u16((capwap_message_elements_handle)txmngpacket, CAPWAP_ELEMENT_VENDORPAYLOAD_TYPE);
	else
		txmngpacket->write_ops.write_u16((capwap_message_elements_handle)txmngpacket, id.type);

	/* Length of message element is calculate after create function */
	writepos.item = txmngpacket->fragmentlist->last;
	writepos.pos = ((struct capwap_fragment_packet_item*)writepos.item->item)->offset;
	txmngpacket->write_ops.write_u16((capwap_message_elements_handle)txmngpacket, 0);
	txmngpacket->writerpacketsize = 0;

	if (id.vendor != 0) {
		/* Write vendor header */
		txmngpacket->write_ops.write_u32((capwap_message_elements_handle)txmngpacket, id.vendor);
		txmngpacket->write_ops.write_u16((capwap_message_elements_handle)txmngpacket, id.type);
	}

	/* Build message element */
	func->create(data, (capwap_message_elements_handle)txmngpacket, &txmngpacket->write_ops);

	/* Write message element length */
	capwap_fragment_write_u16_from_pos((capwap_message_elements_handle)txmngpacket, txmngpacket->writerpacketsize, &writepos);
}

/* */
void capwap_packet_txmng_get_fragment_packets(struct capwap_packet_txmng* txmngpacket, struct capwap_list* fragmentlist, unsigned short fragmentid) {
	unsigned short fragmentoffset = 0;

	ASSERT(txmngpacket != NULL);
	ASSERT(fragmentlist != NULL);

	/* */
	while (txmngpacket->fragmentlist->first) {
		struct capwap_list_item* item = capwap_itemlist_remove_head(txmngpacket->fragmentlist);
		struct capwap_fragment_packet_item* fragmentpacket = (struct capwap_fragment_packet_item*)item->item;
		struct capwap_header* header = (struct capwap_header*)fragmentpacket->buffer;

		/* Check if require fragment */
		if (!fragmentoffset && !txmngpacket->fragmentlist->first) {
			SET_FLAG_F_HEADER(header, 0);
			SET_FRAGMENT_ID_HEADER(header, 0);
			SET_FRAGMENT_OFFSET_HEADER(header, 0);
			SET_FLAG_L_HEADER(header, 0);
		} else {
			SET_FLAG_F_HEADER(header, 1);
			SET_FRAGMENT_ID_HEADER(header, fragmentid);
			SET_FRAGMENT_OFFSET_HEADER(header, fragmentoffset);
			SET_FLAG_L_HEADER(header, (!txmngpacket->fragmentlist->first ? 1 : 0));

			/* Update fragment offset */
			fragmentoffset += fragmentpacket->offset % 8;
		}

		/* Transfer item to external list */
		capwap_itemlist_insert_after(fragmentlist, NULL, item);
	}
}

/* */
void capwap_packet_txmng_free(struct capwap_packet_txmng* txmngpacket) {
	if (txmngpacket) {
		capwap_list_free(txmngpacket->fragmentlist);
		capwap_free(txmngpacket);
	}
}

/* */
unsigned short capwap_fragment_read_ready(capwap_message_elements_handle handle) {
	struct capwap_packet_rxmng* rxmngpacket = (struct capwap_packet_rxmng*)handle;

	ASSERT(handle != NULL);

	return (rxmngpacket->readpos.item ? rxmngpacket->readerpacketallowed : 0);
}

/* */
static int capwap_fragment_read_block_from_pos(uint8_t* data, unsigned short length, struct read_block_from_pos* readpos, unsigned short lengthallowed) {
	unsigned short readdataleft;

	ASSERT(length > 0);
	ASSERT(readpos != NULL);

	readdataleft = (lengthallowed > 0 ? min(length, lengthallowed) : length);
	length = readdataleft;

	while (readpos->item && readdataleft) {
		struct capwap_fragment_packet_item* packet = (struct capwap_fragment_packet_item*)readpos->item->item;
		unsigned short bufferlength = packet->size - readpos->pos;
		unsigned short copylength = min(bufferlength, readdataleft);

		if (data) {
			/* Copy data from capwap packet */
			memcpy(&data[length - readdataleft], &packet->buffer[readpos->pos], copylength);
		}

		readdataleft -= copylength;
		readpos->pos += copylength;

		/* Check buffer */
		if (readpos->pos == packet->size) {
			/* Next packet */
			readpos->item = readpos->item->next;
			if (!readpos->item) {
				readpos->pos = 0;
				if (readdataleft) {
					capwap_logging_debug("Complete to read capwap packet but remain %hu byte to read", readdataleft);
				}
			} else {
				struct capwap_header* header;

				/* Skip capwap header */
				packet = (struct capwap_fragment_packet_item*)readpos->item->item;
				header = (struct capwap_header*)packet->buffer;
				readpos->pos = GET_HLEN_HEADER(header) * 4;
			}
		}
	}

	return (length - readdataleft);
}

static int capwap_fragment_read_block(capwap_message_elements_handle handle, uint8_t* data, unsigned short length) {
	unsigned short readlength;
	struct capwap_packet_rxmng* rxmngpacket;
	
	ASSERT(handle != NULL);

	rxmngpacket = (struct capwap_packet_rxmng*)handle;
	readlength = capwap_fragment_read_block_from_pos(data, length, &rxmngpacket->readpos, rxmngpacket->readerpacketallowed);
	rxmngpacket->readerpacketallowed -= readlength;

	return readlength;
}

/* */
static int capwap_fragment_read_u8(capwap_message_elements_handle handle, uint8_t* data) {
	if (capwap_fragment_read_block(handle, (uint8_t*)data, sizeof(uint8_t)) != sizeof(uint8_t)) {
		return -1;
	}

	return sizeof(uint8_t);
}

/* */
static int capwap_fragment_read_u16(capwap_message_elements_handle handle, uint16_t* data) {
	uint16_t temp;
	if (capwap_fragment_read_block(handle, (uint8_t*)&temp, sizeof(uint16_t)) != sizeof(uint16_t)) {
		return -1;
	}

	if (data) {
		*data = ntohs(temp);
	}

	return sizeof(uint16_t);
}

/* */
static int capwap_fragment_read_u32(capwap_message_elements_handle handle, uint32_t* data) {
	uint32_t temp;
	if (capwap_fragment_read_block(handle, (uint8_t*)&temp, sizeof(uint32_t)) != sizeof(uint32_t)) {
		return -1;
	}

	if (data) {
		*data = ntohl(temp);
	}

	return sizeof(uint32_t);
}

/* */
struct capwap_packet_rxmng* capwap_packet_rxmng_create_message(void) {
	struct capwap_packet_rxmng* rxmngpacket;

	/* */
	rxmngpacket = (struct capwap_packet_rxmng*)capwap_alloc(sizeof(struct capwap_packet_rxmng));
	memset(rxmngpacket, 0, sizeof(struct capwap_packet_rxmng));

	/* Fragment bucket */
	rxmngpacket->fragmentlist = capwap_list_create();

	return rxmngpacket;
}

/* */
static void capwap_packet_rxmng_complete(struct capwap_packet_rxmng* rxmngpacket) {
	ASSERT(rxmngpacket->packetlength > 0);

	/* Configure basic IO read function */
	rxmngpacket->read_ops.read_ready = capwap_fragment_read_ready;
	rxmngpacket->read_ops.read_u8 = capwap_fragment_read_u8;
	rxmngpacket->read_ops.read_u16 = capwap_fragment_read_u16;
	rxmngpacket->read_ops.read_u32 = capwap_fragment_read_u32;
	rxmngpacket->read_ops.read_block = capwap_fragment_read_block;

	/* Set reader value */
	rxmngpacket->readpos.item = rxmngpacket->fragmentlist->first;
	rxmngpacket->header = (struct capwap_header*)((struct capwap_fragment_packet_item*)rxmngpacket->fragmentlist->first->item)->buffer;
	rxmngpacket->readpos.pos = GET_HLEN_HEADER(rxmngpacket->header) * 4;

	/* Read message type */
	rxmngpacket->readerpacketallowed = sizeof(struct capwap_control_message);
	rxmngpacket->read_ops.read_u32((capwap_message_elements_handle)rxmngpacket, &rxmngpacket->ctrlmsg.type);
	rxmngpacket->read_ops.read_u8((capwap_message_elements_handle)rxmngpacket, &rxmngpacket->ctrlmsg.seq);
	rxmngpacket->read_ops.read_u16((capwap_message_elements_handle)rxmngpacket, &rxmngpacket->ctrlmsg.length);
	rxmngpacket->read_ops.read_u8((capwap_message_elements_handle)rxmngpacket, &rxmngpacket->ctrlmsg.flags);

	/* Position of capwap body */
	memcpy(&rxmngpacket->readbodypos, &rxmngpacket->readpos, sizeof(struct read_block_from_pos));
}

/* */
static struct capwap_list_item* capwap_packet_rxmng_create_fragment_item(void* data, int length) {
	struct capwap_list_item* item;
	struct capwap_fragment_packet_item* packet;

	item = capwap_itemlist_create(sizeof(struct capwap_fragment_packet_item) + length);
	packet = (struct capwap_fragment_packet_item*)item->item;
	packet->size = length;
	packet->offset = length;
	memcpy(packet->buffer, data, length);

	return item;
}

/* */
int capwap_packet_rxmng_add_recv_packet(struct capwap_packet_rxmng* rxmngpacket, void* data, int length) {
	struct capwap_header* header;

	ASSERT(rxmngpacket != NULL);
	ASSERT(data != NULL);
	ASSERT(length > 0);

	/* Parsing fragment capwap header */
	header = (struct capwap_header*)data;
	if (IS_FLAG_F_HEADER(header)) {
		struct capwap_list_item* itemsearch;
		struct capwap_fragment_packet_item* packetsearch;
		struct capwap_header* headersearch;
		unsigned short fragid = GET_FRAGMENT_ID_HEADER(header);
		unsigned short fragoffset = GET_FRAGMENT_OFFSET_HEADER(header);
		unsigned short headersize = GET_HLEN_HEADER(header) * 4;

		/* Size of payload is multiple of 64bits */
		if (((length - headersize) % 8) != 0) {
			capwap_logging_debug("Body capwap packet is not multiple of 64bit");
			return CAPWAP_WRONG_FRAGMENT;
		}

		/* Check fragment id */
		if (rxmngpacket->fragmentlist->count > 0) {
			itemsearch  = rxmngpacket->fragmentlist->first;
			packetsearch = (struct capwap_fragment_packet_item*)itemsearch->item;
			headersearch = (struct capwap_header*)packetsearch->buffer;

			if (fragid != GET_FRAGMENT_ID_HEADER(headersearch)) {
				capwap_logging_debug("Sent fragment packets with different fragment id");
				return CAPWAP_WRONG_FRAGMENT;
			}
		}

		/* Order fragment */
		if (!rxmngpacket->fragmentlist->count) {
			capwap_itemlist_insert_before(rxmngpacket->fragmentlist, NULL, capwap_packet_rxmng_create_fragment_item(data, length));
		} else {
			itemsearch = rxmngpacket->fragmentlist->first;
			while (itemsearch) {
				packetsearch = (struct capwap_fragment_packet_item*)itemsearch->item;
				headersearch = (struct capwap_header*)packetsearch->buffer;
				unsigned short fragoffsetsearch = GET_FRAGMENT_OFFSET_HEADER(headersearch);

				if (fragoffset < fragoffsetsearch) {
					capwap_itemlist_insert_before(rxmngpacket->fragmentlist, itemsearch, capwap_packet_rxmng_create_fragment_item(data, length));
					break;
				} else if ((fragoffset > fragoffsetsearch) && !itemsearch->next) {
					capwap_itemlist_insert_after(rxmngpacket->fragmentlist, NULL, capwap_packet_rxmng_create_fragment_item(data, length));
					break;
				} else {
					/* Check duplicate packet */
					if (packetsearch->size != length) {
						capwap_logging_debug("Duplicate fragment offset with different size");
						return CAPWAP_WRONG_FRAGMENT;
					}

					if (memcmp(packetsearch->buffer, data, packetsearch->size)) {
						capwap_logging_debug("Duplicate fragment offset with different packet");
						return CAPWAP_WRONG_FRAGMENT;
					}

					/* Duplicate packet */
					break;
				}

				/* Next fragment */
				itemsearch = itemsearch->next;
			}
		}

		/* Check complete only if receive last packet */
		ASSERT(rxmngpacket->fragmentlist->last != NULL);
		if (IS_FLAG_L_HEADER(header)) {
			unsigned short sanityfragoffset = 0;

			/* Sanity check and complete */
			rxmngpacket->packetlength = 0;
			itemsearch = rxmngpacket->fragmentlist->first;
			while (itemsearch) {
				packetsearch = (struct capwap_fragment_packet_item*)itemsearch->item;
				headersearch = (struct capwap_header*)packetsearch->buffer;
				unsigned short fragoffsetsearch = GET_FRAGMENT_OFFSET_HEADER(headersearch);
				unsigned short packetlength = packetsearch->size - GET_HLEN_HEADER(headersearch) * 4;
	
				/* Check fragment offset */
				if (sanityfragoffset < fragoffsetsearch) {
					return CAPWAP_REQUEST_MORE_FRAGMENT;
				} else if (sanityfragoffset > fragoffsetsearch) {
					capwap_list_flush(rxmngpacket->fragmentlist);
					capwap_logging_debug("Wrong fragment offset");
					return CAPWAP_WRONG_FRAGMENT;
				}

				/* Update fragment offset */
				rxmngpacket->packetlength += packetlength;
				sanityfragoffset += packetlength / 8;

				/* Next fragment */
				itemsearch = itemsearch->next;
			}

			/* Packet complete */
			capwap_packet_rxmng_complete(rxmngpacket);
			return CAPWAP_RECEIVE_COMPLETE_PACKET;
		}

		return CAPWAP_REQUEST_MORE_FRAGMENT;
	} else {
		/* Check if already received fragment packets */
		if (rxmngpacket->fragmentlist->count > 0) {
			/* Overlap fragment packet with complete packet */
			capwap_logging_debug("Overlap fragment packet with complete packet");
			return CAPWAP_WRONG_FRAGMENT;
		} else {
			struct capwap_header* header;

			/* */
			capwap_itemlist_insert_after(rxmngpacket->fragmentlist, NULL, capwap_packet_rxmng_create_fragment_item(data, length));
			header = (struct capwap_header*)data;
			rxmngpacket->packetlength = length - GET_HLEN_HEADER(header) * 4;

			/* */
			capwap_packet_rxmng_complete(rxmngpacket);
			return CAPWAP_RECEIVE_COMPLETE_PACKET;
		}
	}

	return CAPWAP_WRONG_FRAGMENT;
}

/* */
struct capwap_packet_rxmng* capwap_packet_rxmng_create_from_requestfragmentpacket(struct capwap_list* requestfragmentpacket) {
	struct capwap_packet_rxmng* rxmngpacket;
	struct capwap_list_item* fragment;
	int result = CAPWAP_WRONG_FRAGMENT;

	ASSERT(requestfragmentpacket != NULL);

	if (!requestfragmentpacket->count) {
		return NULL;
	}

	/* */
	rxmngpacket = capwap_packet_rxmng_create_message();

	/* */
	fragment = requestfragmentpacket->first;
	while (fragment != NULL) {
		struct capwap_fragment_packet_item* fragmentpacket = (struct capwap_fragment_packet_item*)fragment->item;

		/* Append fragment */
		result = capwap_packet_rxmng_add_recv_packet(rxmngpacket, fragmentpacket->buffer, fragmentpacket->offset);
		if (result == CAPWAP_WRONG_FRAGMENT) {
			break;
		}

		/* Next fragment */
		fragment = fragment->next;
	}

	/* */
	if (result != CAPWAP_RECEIVE_COMPLETE_PACKET) {
		capwap_packet_rxmng_free(rxmngpacket);
		rxmngpacket = NULL;
	}

	return rxmngpacket;
}

/* */
void capwap_packet_rxmng_free(struct capwap_packet_rxmng* rxmngpacket) {
	if (rxmngpacket) {
		capwap_list_free(rxmngpacket->fragmentlist);
		capwap_free(rxmngpacket);
	}
}
