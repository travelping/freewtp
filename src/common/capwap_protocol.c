#include "capwap.h"
#include "capwap_protocol.h"
#include "capwap_network.h"
#include "capwap_dfa.h"
#include "capwap_list.h"
#include "capwap_array.h"
#include "md5.h"

/* */
static struct capwap_fragment_sender* capwap_defragment_add_sender(capwap_fragment_list* defraglist, struct sockaddr_storage* sendaddr, struct capwap_header* header);
static struct capwap_list_item* capwap_defragment_create_packet(void* payload, int size, unsigned short offset);

/* Check valid packet */
int capwap_sanity_check(int isctrlsocket, int state, void* buffer, int buffersize, int dtlsctrlenable, int dtlsdataenable) {
	struct capwap_preamble* preamble;
	
	ASSERT(buffer != NULL);
	ASSERT(buffersize > sizeof(struct capwap_preamble));

	preamble = (struct capwap_preamble*)buffer;
	if (preamble->version != CAPWAP_PROTOCOL_VERSION) {
		return CAPWAP_WRONG_PACKET;
	}

	if (isctrlsocket) {
		if (dtlsctrlenable) {
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
	} else {
		if ((state != CAPWAP_DATA_CHECK_TO_RUN_STATE) && (state != CAPWAP_RUN_STATE) && (state != CAPWAP_UNDEF_STATE)) {
			return CAPWAP_WRONG_PACKET;
		}

		if (dtlsdataenable) {
			if ((preamble->type == CAPWAP_PREAMBLE_DTLS_HEADER) && (buffersize >= sizeof(struct capwap_dtls_header))) {
				return CAPWAP_DTLS_PACKET;
			}
		} else {
			if ((preamble->type == CAPWAP_PREAMBLE_HEADER) && (buffersize >= sizeof(struct capwap_header))) {
				struct capwap_header* header = (struct capwap_header*)preamble;
				if (buffersize >= GET_HLEN_HEADER(header) * 4) {
					return CAPWAP_PLAIN_PACKET;
				}
			}
		}
	}
	
	return CAPWAP_WRONG_PACKET;
}

/* */
int capwap_defragment_packets(struct sockaddr_storage* sendaddr, void* buffer, int buffersize, capwap_fragment_list* defraglist, struct capwap_packet* packet) {
	struct capwap_header* header = (struct capwap_header*)buffer;
	struct capwap_fragment_sender* defragsend;
	int headersize;

	ASSERT(sendaddr != NULL);
	ASSERT(buffer != NULL);
	ASSERT(buffersize > sizeof(struct capwap_header));
	ASSERT(defraglist != NULL);
	ASSERT(packet != NULL);

	headersize = GET_HLEN_HEADER(header) * 4;
	defragsend = capwap_defragment_find_sender(defraglist, sendaddr);	
	
	if (IS_FLAG_F_HEADER(header)) {
		struct capwap_list_item* searchpacket;
		struct capwap_fragment_packet* itempacket;
		unsigned short fragid = GET_FRAGMENT_ID_HEADER(header);
		unsigned short fragoffset = GET_FRAGMENT_OFFSET_HEADER(header);
		char* payload = (char*)buffer + headersize;
		int payloadsize = buffersize - headersize;
		
		/* Size of payload is multiple of 64bits */
		if ((payloadsize % 8) != 0) {
			return CAPWAP_WRONG_FRAGMENT;
		}
		
		if (!defragsend) {
			/* Create new defragment item */
			defragsend = capwap_defragment_add_sender(defraglist, sendaddr, header);
			if (!defragsend) {
				return CAPWAP_WRONG_FRAGMENT;
			}
		} else if (fragid != defragsend->fragment_id) {
			/* Wrong fragment id */
			capwap_defragment_remove_sender(defraglist, sendaddr);
			return CAPWAP_WRONG_FRAGMENT;
		} 

		if (fragoffset == 0) {
			/* Save header of the first packet of fragmentation */
			defragsend->header = (struct capwap_header*)capwap_clone(header, headersize);
		}

		/* Defragment payload */
		searchpacket = defragsend->packetlist->last;
		if (!searchpacket) {
			struct capwap_list_item* packet = capwap_defragment_create_packet(payload, payloadsize, fragoffset);
			capwap_itemlist_insert_before(defragsend->packetlist, NULL, packet);
		} else {
			while (searchpacket != NULL) {
				itempacket = (struct capwap_fragment_packet*)searchpacket->item;
				ASSERT(itempacket != NULL);
				
				if (itempacket->offset > fragoffset) {
					if (!searchpacket->prev) {
						struct capwap_list_item* packet = capwap_defragment_create_packet(payload, payloadsize, fragoffset);
						capwap_itemlist_insert_before(defragsend->packetlist, searchpacket, packet);
						break;
					}
				} else if (itempacket->offset < fragoffset) {
					if (!defragsend->islastrecv || (searchpacket != defragsend->packetlist->last)) {
						struct capwap_list_item* packet = capwap_defragment_create_packet(payload, payloadsize, fragoffset);
						capwap_itemlist_insert_after(defragsend->packetlist, searchpacket, packet);
					}
					
					break;
				} else {
					/* Duplicate packet */
					break;
				}
				
				/* Prev fragment */
				searchpacket = searchpacket->prev;
			}
		}

		/* If last packet, mark end of fragmentation */
		if (!defragsend->islastrecv) {
			defragsend->islastrecv = IS_FLAG_L_HEADER(header);
		}
		
		/* Check if defragmentation is completed */
		if (defragsend->islastrecv) {
			unsigned long checkoffset = 0;
			
			payloadsize = 0;
			searchpacket = defragsend->packetlist->first;
			while (searchpacket != NULL) {
				itempacket = (struct capwap_fragment_packet*)searchpacket->item;
				if (checkoffset != itempacket->offset) {
					return CAPWAP_REQUEST_MORE_FRAGMENT;
				}
				
				/* Next fragment */
				payloadsize += itempacket->size;
				checkoffset += itempacket->size / 8;
				searchpacket = searchpacket->next;
			}
			
			/* Defragment complete */
			ASSERT(defragsend->header != NULL);
			headersize = GET_HLEN_HEADER(defragsend->header) * 4;
			packet->packetsize = headersize + payloadsize;
			packet->header = (struct capwap_header*)capwap_alloc(packet->packetsize);
			if (!packet->header) {
				capwap_outofmemory();
			}
			
			/* Copy header and remove fragmention information */
			memcpy(packet->header, defragsend->header, headersize);
			SET_FLAG_F_HEADER(packet->header, 0);
			SET_FLAG_L_HEADER(packet->header, 0);
			SET_FRAGMENT_ID_HEADER(packet->header, 0);
			SET_FRAGMENT_OFFSET_HEADER(packet->header, 0);
			
			/* Copy payload */
			packet->payload = (char*)packet->header + headersize;
			payload = packet->payload;
			
			searchpacket = defragsend->packetlist->first;
			while (searchpacket != NULL) {
				itempacket = (struct capwap_fragment_packet*)searchpacket->item;
				memcpy(payload, itempacket->buffer, itempacket->size);
				payload += itempacket->size;
				
				/* Next */
				searchpacket = searchpacket->next;
			}
			
			capwap_defragment_remove_sender(defraglist, sendaddr);
			return CAPWAP_RECEIVE_COMPLETE_PACKET;
		}
		
		return CAPWAP_REQUEST_MORE_FRAGMENT;
	} else {
		/* Check if already received fragment packets */
		if (defragsend) {
			/* Overlap fragment packet with complete packet */
			capwap_defragment_remove_sender(defraglist, sendaddr);
		} else {
			/* Copy buffer */
			packet->packetsize = buffersize;
			packet->header = (struct capwap_header*)capwap_clone(buffer, packet->packetsize);
			packet->payload = (void*)((char*)buffer + headersize);
			
			return CAPWAP_RECEIVE_COMPLETE_PACKET;
		}
	}
	
	return CAPWAP_WRONG_FRAGMENT;
}

/* */
capwap_fragment_list* capwap_defragment_init_list(void) {
	return capwap_list_create();
}

/* */
static void capwap_defragment_free_packetlist(struct capwap_list* packetlist) {
	struct capwap_list_item* search;
	
	ASSERT(packetlist != NULL);
	
	search = packetlist->first;
	while (search) {
		struct capwap_fragment_packet* packet = (struct capwap_fragment_packet*)search->item;
		ASSERT(packet->buffer != NULL);
		
		capwap_free(packet->buffer);
		
		/* Next */
		search = search->next;
	}
	
	capwap_list_free(packetlist);
}

/* */
void capwap_defragment_flush_list(capwap_fragment_list* defraglist) {
	struct capwap_fragment_sender* item;
	
	ASSERT(defraglist != NULL);
	
	while (defraglist->first) {
		item = (struct capwap_fragment_sender*)defraglist->first->item;
		ASSERT(item != NULL);
		ASSERT(item->packetlist != NULL);

		capwap_defragment_free_packetlist(item->packetlist);
		capwap_itemlist_free(capwap_itemlist_remove(defraglist, defraglist->first));
	}
}

/* */
void capwap_defragment_free_list(capwap_fragment_list* defraglist) {
	ASSERT(defraglist != NULL);
	
	capwap_defragment_flush_list(defraglist);
	capwap_list_free(defraglist);
}

/* */
struct capwap_fragment_sender* capwap_defragment_find_sender(capwap_fragment_list* defraglist, struct sockaddr_storage* sendaddr) {
	struct capwap_fragment_sender* item;
	struct capwap_list_item* search;
	
	ASSERT(defraglist != NULL);
	ASSERT(sendaddr != NULL);

	search = defraglist->first;
	while (search) {
		item = (struct capwap_fragment_sender*)search->item;
		ASSERT(item != NULL);
		
		if (!capwap_compare_ip(sendaddr, &item->sendaddr)) {
			return item;
		}
		
		search = search->next;
	}

	return NULL;
}

/* */
static struct capwap_fragment_sender* capwap_defragment_add_sender(capwap_fragment_list* defraglist, struct sockaddr_storage* sendaddr, struct capwap_header* header) {
	struct capwap_list_item* item;
	struct capwap_fragment_sender* sender;
	int headersize;
	
	ASSERT(defraglist != NULL);
	ASSERT(sendaddr != NULL);
	ASSERT(header != NULL);
	
	item = capwap_itemlist_create(sizeof(struct capwap_fragment_sender));
	sender = (struct capwap_fragment_sender*)item->item;
	
	memset(sender, 0, sizeof(struct capwap_fragment_sender));
	memcpy(&sender->sendaddr, sendaddr, sizeof(struct sockaddr_storage));
	sender->fragment_id = GET_FRAGMENT_ID_HEADER(header);
	
	headersize = GET_HLEN_HEADER(header) * 4;
	sender->header = (struct capwap_header*)capwap_alloc(headersize);
	if (!sender->header) {
		capwap_outofmemory();
	}

	memcpy(sender->header, header, headersize);
	sender->packetlist = capwap_list_create();

	/* Add item to list */	
	capwap_itemlist_insert_after(defraglist, NULL, item);
	return sender;
}

/* */
int capwap_defragment_remove_sender(capwap_fragment_list* defraglist, struct sockaddr_storage* sendaddr) {
	int found = 0;
	struct capwap_fragment_sender* item;
	struct capwap_list_item* search;
	
	ASSERT(defraglist != NULL);
	ASSERT(sendaddr != NULL);

	search = defraglist->first;
	while (search) {
		item = (struct capwap_fragment_sender*)search->item;
		ASSERT(item != NULL);
		
		if (!capwap_compare_ip(sendaddr, &item->sendaddr)) {
			ASSERT(item->packetlist);

			found = 1;
			capwap_defragment_free_packetlist(item->packetlist);
			capwap_itemlist_free(capwap_itemlist_remove(defraglist, search));
			break;
		}
		
		search = search->next;
	}
	
	return found;
}

/* */
static struct capwap_list_item* capwap_defragment_create_packet(void* payload, int size, unsigned short offset) {
	struct capwap_fragment_packet* packet;
	struct capwap_list_item* item;
	
	ASSERT(payload != NULL);
	ASSERT(size > 0);
	
	/* New fragment */
	item = capwap_itemlist_create(sizeof(struct capwap_fragment_packet));
	packet = (struct capwap_fragment_packet*)item->item;
	
	memset(packet, 0, sizeof(struct capwap_fragment_packet));
	packet->buffer = capwap_clone(payload, size);
	packet->size = size;
	packet->offset = offset;

	return item;
}

/* */
void capwap_free_packet(struct capwap_packet* packet) {
	ASSERT(packet != NULL);
	
	if (packet->header) {
		capwap_free(packet->header);
		memset(packet, 0, sizeof(struct capwap_packet));
	}
}

/* Creare tx packet */
struct capwap_build_packet* capwap_tx_packet_create(unsigned short radioid, unsigned short binding) {
	struct capwap_build_packet* packet;
	struct capwap_header* header;
	
	packet = (struct capwap_build_packet*)capwap_alloc(sizeof(struct capwap_build_packet));
	if (!packet) {
		capwap_outofmemory();
	}
	
	memset(packet, 0, sizeof(struct capwap_build_packet));
	header = &packet->header;
	
	/* Standard configuration */
	SET_VERSION_HEADER(header, CAPWAP_PROTOCOL_VERSION);
	SET_TYPE_HEADER(header, CAPWAP_PREAMBLE_HEADER);
	SET_HLEN_HEADER(header, sizeof(struct capwap_header) / 4);
	SET_RID_HEADER(header, radioid);
	SET_WBID_HEADER(header, binding);
	
	/* Message elements list */
	packet->elementslist = capwap_list_create();

	return packet;
}

/* Destroy tx packet */
void capwap_build_packet_free(struct capwap_build_packet* buildpacket) {
	ASSERT(buildpacket != NULL);

	/* */
	capwap_list_free(buildpacket->elementslist);
	capwap_free(buildpacket);
}

/* Add radio macaddress to packet */
void capwap_build_packet_set_radio_macaddress(struct capwap_build_packet* buildpacket, int radiotype, char* macaddress) {
	struct capwap_header* header;
	
	ASSERT(buildpacket != NULL);
	
	header = &buildpacket->header;
	if (radiotype == CAPWAP_MACADDRESS_NONE) {
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
		ASSERT((radiotype == CAPWAP_MACADDRESS_EUI48) || (radiotype == CAPWAP_MACADDRESS_EUI64));
		
		if (IS_FLAG_M_HEADER(header)) {
			radio = GET_RADIO_MAC_ADDRESS_STRUCT(header);
			
			if (radio->length == radiotype) {
				/* Rewrite mac address */
				memcpy(radio->address, macaddress, radiotype);
				return;
			}
			
			/* Remove old radio mac address */
			capwap_build_packet_set_radio_macaddress(buildpacket, CAPWAP_MACADDRESS_NONE, NULL);
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

/* Add Wireless Specific Information to packet */
void capwap_build_packet_set_wireless_information(struct capwap_build_packet* buildpacket, void* buffer, unsigned char length) {
	struct capwap_header* header;
	int size;
	
	ASSERT(buildpacket != NULL);
	
	header = &buildpacket->header;

	/* Calculate size of header */
	size = sizeof(struct capwap_header) / 4;
	if (IS_FLAG_M_HEADER(header)) {
		struct capwap_mac_address* radio = GET_RADIO_MAC_ADDRESS_STRUCT(header);
		size += ((sizeof(struct capwap_mac_address) + radio->length) + 3) / 4;
	}

	/* Remove old wireless information */
	if (IS_FLAG_W_HEADER(header)) {
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
		SET_HLEN_HEADER(header, size);
	}
}

/* Set control message type */
void capwap_build_packet_set_control_message_type(struct capwap_build_packet* buildpacket, unsigned long type, unsigned char seq) {
	ASSERT(buildpacket != NULL);
	
	buildpacket->ctrlmsg.type = htonl(type);
	buildpacket->ctrlmsg.seq = seq;
	buildpacket->ctrlmsg.length = 0;
	buildpacket->ctrlmsg.flags = 0;
}

/* Add message element */
void capwap_build_packet_add_message_element(struct capwap_build_packet* buildpacket, struct capwap_message_element* element) {
	struct capwap_list_item* itemlist;
	unsigned long length;
	
	ASSERT(buildpacket != NULL);
	
	if ((element == NULL) || (element->length == 0)) {
		capwap_logging_debug("Warning, add null element to packet");
		return;
	}
	
	/* Create item and add into last position of list*/
	length = ntohs(element->length) + sizeof(struct capwap_message_element);
	itemlist = capwap_itemlist_create_with_item(element, length);
	capwap_itemlist_insert_after(buildpacket->elementslist, NULL, itemlist);

	/* */
	if (buildpacket->isctrlmsg) {
		buildpacket->ctrlmsg.length = htons(ntohs(buildpacket->ctrlmsg.length) + length);
	} else {
		buildpacket->datamsg.length = htons(ntohs(buildpacket->datamsg.length) + length);
	}
}

/* Generate fragment packets */
int capwap_fragment_build_packet(struct capwap_build_packet* buildpacket, capwap_fragment_packet_array* packets, unsigned short mtu, unsigned short fragmentid) {
	unsigned short i;
	unsigned short reqpacket;
	unsigned long length = 0;
	unsigned short headerlength = 0;
	struct capwap_header* header;
	unsigned short fragmentposition = 0;
	struct capwap_list_item* item = NULL;
	unsigned long itempos = 0;
	
	ASSERT(buildpacket != NULL);
	ASSERT(packets != NULL);
	
	/* Free array */
	capwap_fragment_free(packets);
	if ((mtu > 0) && (mtu < CAPWAP_HEADER_MAX_SIZE)) {
		/* Mtu must be greater than the maximum size of capwap header */
		capwap_logging_debug("The mtu is too small: %hu", mtu);
		return -1;
	}

	/* Get length raw packet */
	header = &buildpacket->header;
	headerlength = GET_HLEN_HEADER(header) * 4;
	if (buildpacket->isctrlmsg) {
		length = sizeof(struct capwap_control_message) + ntohs(buildpacket->ctrlmsg.length);
	} else if (IS_FLAG_K_HEADER(header)) {
		length = sizeof(struct capwap_data_message) + ntohs(buildpacket->datamsg.length);
	}
	
	/* Retrive number of request packet for send a capwap message */
	if (!mtu || ((headerlength + length) <= mtu)) {
		reqpacket = 1;
	} else {
		unsigned long lengthpayload = length;
		unsigned short mtupayload;
		
		/* Detect mtu payload */
		mtupayload = mtu - sizeof(struct capwap_header);
		mtupayload -= mtupayload % 8;
		
		/* Calculate number of request packets without size of header */
		if (IS_FLAG_M_HEADER(header)) {
			struct capwap_mac_address* radio = GET_RADIO_MAC_ADDRESS_STRUCT(header);
			lengthpayload += ((sizeof(struct capwap_mac_address) + radio->length) + 3) / 4;
		}
		
		if (IS_FLAG_W_HEADER(header)) {
			struct capwap_wireless_information* wireless = GET_WIRELESS_INFORMATION_STRUCT(header);
			lengthpayload += ((sizeof(struct capwap_wireless_information) + wireless->length) + 3) / 4;
		}
		
		/* Request packet padded */
		reqpacket = (lengthpayload + (mtupayload - 1)) / mtupayload;
	}
	
	/* Create packets */
	capwap_array_resize(packets, reqpacket);
	for (i = 0; i < reqpacket; i++) {
		long payloadsize = 0;
		struct capwap_packet* packet = (struct capwap_packet*)capwap_array_get_item_pointer(packets, i);
		memset(packet, 0, sizeof(struct capwap_packet));
		
		if (reqpacket == 1) {
			/* Build header */
			packet->packetsize = headerlength + length;
			packet->header = (struct capwap_header*)capwap_alloc(packet->packetsize);
			
			memcpy(packet->header, &buildpacket->header, headerlength);
			packet->payload = (void*)(((char*)packet->header) + headerlength);
			payloadsize = length;

			/* Disable fragmentation */
			SET_FLAG_F_HEADER(packet->header, 0);
			SET_FRAGMENT_ID_HEADER(packet->header, 0);
			SET_FRAGMENT_OFFSET_HEADER(packet->header, 0);
			SET_FLAG_L_HEADER(packet->header, 0);
		} else {
			unsigned short headerpos = ((i == 0) ? headerlength : sizeof(struct capwap_header));
			unsigned short mtupayload;
		
			/* Detect mtu payload */
			mtupayload = mtu - headerpos;
			mtupayload -= mtupayload % 8;
			
			/* Build header */
			packet->packetsize = headerpos + mtupayload;
			packet->header = (struct capwap_header*)capwap_alloc(packet->packetsize);
			memcpy(packet->header, &buildpacket->header, headerpos);
			packet->payload = (void*)(((char*)packet->header) + headerpos);
			payloadsize = mtupayload;
		
			if (i > 0) {
				/* Radio mac address and wireless information is sent only into first packet */
				SET_FLAG_M_HEADER(packet->header, 0);
				SET_FLAG_W_HEADER(packet->header, 0);
				SET_HLEN_HEADER(packet->header, sizeof(struct capwap_header) / 4);
			}
			
			/* Use fragmentation */
			SET_FLAG_F_HEADER(packet->header, 1);
			SET_FRAGMENT_ID_HEADER(packet->header, fragmentid);
			SET_FRAGMENT_OFFSET_HEADER(packet->header, fragmentposition);
			SET_FLAG_L_HEADER(packet->header, (((i + 1) == reqpacket) ? 1 : 0));
		}

		/* Build payload */
		if (length > 0) {
			char* pos = (char*)packet->payload;
			
			/* Data/Control Message */
			if (i == 0) {
				if (buildpacket->isctrlmsg) {
					/* Control Message header can not fragment */
					if (payloadsize < sizeof(struct capwap_control_message)) {
						capwap_logging_debug("Unable fragments packet, mtu is too small");
						capwap_fragment_free(packets);
						return -1;
					}
					
					memcpy(packet->payload, &buildpacket->ctrlmsg, sizeof(struct capwap_control_message));
					pos += sizeof(struct capwap_control_message);
					payloadsize -= sizeof(struct capwap_control_message);
				} else if (IS_FLAG_K_HEADER(header)) {
					/* Data Message header can not fragment */
					if (payloadsize < sizeof(struct capwap_data_message)) {
						capwap_logging_debug("Unable fragments packet, mtu is too small");
						capwap_fragment_free(packets);
						return -1;
					}
					
					memcpy(packet->payload, &buildpacket->datamsg, sizeof(struct capwap_data_message));
					pos += sizeof(struct capwap_data_message);
					payloadsize -= sizeof(struct capwap_data_message);
				}
				
				/* Configure message elements */
				item = buildpacket->elementslist->first;
				itempos = 0;
			}
			
			/* Add message elements */
			while ((item != NULL) && (payloadsize > 0)) {
				unsigned short elementcopy;
				unsigned short elementlength;
				struct capwap_message_element* element = (struct capwap_message_element*)item->item;

				ASSERT(element != NULL);
	
				/* Copy message element */
				elementlength = sizeof(struct capwap_message_element) + ntohs(element->length);
				elementcopy = min(elementlength - itempos, payloadsize);
				memcpy(pos, &((char*)element)[itempos], elementcopy);
				
				pos += elementcopy;
				itempos += elementcopy;
				payloadsize -= elementcopy;
				ASSERT(payloadsize >= 0);
				
				/* Next element */
				if (itempos == elementlength) {
					item = item->next;
					itempos = 0;
				}
			}
			
			if (((i + 1) == reqpacket) && (payloadsize > 0)) {
				packet->packetsize -= payloadsize;
			} else {
				ASSERT(payloadsize == 0);
			}
		}
	}
	
	/* Return 1 if fragment packet */
	return ((reqpacket > 1) ? 1 : 0);
}

/* */
void capwap_fragment_free(capwap_fragment_packet_array* packets) {
	unsigned long i;
	
	ASSERT(packets != NULL);
	
	if (packets->count == 0) {
		return;
	}
	
	for (i = 0; i < packets->count; i++) {
		capwap_free_packet((struct capwap_packet*)capwap_array_get_item_pointer(packets, i));
	}
	
	capwap_array_resize(packets, 0);
}

/* */
struct capwap_build_packet* capwap_rx_packet_create(void* buffer, int buffersize, int isctrlpacket) {
	struct capwap_build_packet* buildpacket;
	struct capwap_header* header;
	char* pos = (char*)buffer;
	int length;
	int controlsize;
	
	ASSERT(buffer != NULL);
	ASSERT(buffersize > 0);

	/* Header */
	header = (struct capwap_header*)buffer;
	length = GET_HLEN_HEADER(header) * 4;
	if (buffersize < length) {
		return NULL;
	}
	
	/* Build packet */
	buildpacket = (struct capwap_build_packet*)capwap_alloc(sizeof(struct capwap_build_packet));
	if (!buildpacket) {
		capwap_outofmemory();
	}
	
	/* */
	memset(buildpacket, 0, sizeof(struct capwap_build_packet));
	buildpacket->isctrlmsg = (isctrlpacket ? 1 : 0);
	
	/* Header packet */
	memcpy(&buildpacket->header, pos, length);
	pos += length;
	buffersize -= length;
	
	if (buildpacket->isctrlmsg) {
		if (buffersize < sizeof(struct capwap_control_message)) {
			capwap_logging_debug("Invalid capwap packet, size of control message body is great of raw packet");
			capwap_free(buildpacket);
			return NULL;
		}

		/* Control message header */
		memcpy(&buildpacket->ctrlmsg, pos, sizeof(struct capwap_control_message));
		pos += sizeof(struct capwap_control_message);
		buffersize -= sizeof(struct capwap_control_message);
		
		/* Check the packet size */
		controlsize = ntohs(buildpacket->ctrlmsg.length);
		if (controlsize > buffersize) {
			capwap_logging_debug("Invalid capwap packet, size of control message body is great of raw packet");
			capwap_free(buildpacket);
			return NULL;
		}
		
		/* Message elements list */
		buildpacket->elementslist = capwap_list_create();
		while (controlsize > 0) {
			struct capwap_message_element* element = (struct capwap_message_element*)pos;
			int elementsize = ntohs(element->length) + sizeof(struct capwap_message_element);
			struct capwap_list_item* itemlist;
			
			/* Clone message element */
			itemlist = capwap_itemlist_create(elementsize);
			memcpy(itemlist->item, pos, elementsize);
			capwap_itemlist_insert_after(buildpacket->elementslist, NULL, itemlist);
			
			/* Next */
			pos += elementsize;
			controlsize -= elementsize;
			buffersize -= elementsize;
		}
	} else {
		if (IS_FLAG_K_HEADER(&buildpacket->header)) {
			if (buffersize < sizeof(struct capwap_data_message)) {
				capwap_logging_debug("Invalid capwap packet, size of data message body is great of raw packet");
				capwap_free(buildpacket);
				return NULL;
			}
	
			/* Control message header */
			memcpy(&buildpacket->datamsg, pos, sizeof(struct capwap_data_message));
			pos += sizeof(struct capwap_data_message);
			buffersize -= sizeof(struct capwap_data_message);
			
			/* Check the packet size */
			controlsize = ntohs(buildpacket->datamsg.length);
			if (controlsize > buffersize) {
				capwap_logging_debug("Invalid capwap packet, size of data message body is great of raw packet");
				capwap_free(buildpacket);
				return NULL;
			}
			
			/* Message elements list */
			buildpacket->elementslist = capwap_list_create();
			while (controlsize > 0) {
				struct capwap_message_element* element = (struct capwap_message_element*)pos;
				int elementsize = ntohs(element->length) + sizeof(struct capwap_message_element);
				struct capwap_list_item* itemlist;
				
				/* Clone message element */
				itemlist = capwap_itemlist_create(elementsize);
				memcpy(itemlist->item, pos, elementsize);
				capwap_itemlist_insert_after(buildpacket->elementslist, NULL, itemlist);
				
				/* Next */
				pos += elementsize;
				controlsize -= elementsize;
				buffersize -= elementsize;
			}
		} else {
			/* TODO */
		}
	}
	
	return buildpacket;
}

/* */
unsigned long capwap_build_packet_validate(struct capwap_build_packet* buildpacket, capwap_unrecognized_element_array* reasonarray) {
	unsigned short binding;
	int ieee80211delta = CAPWAP_80211_MESSAGE_ELEMENTS_START - CAPWAP_MESSAGE_ELEMENTS_COUNT;
	int elements[CAPWAP_MESSAGE_ELEMENTS_COUNT + CAPWAP_80211_MESSAGE_ELEMENTS_COUNT];
	struct capwap_list_item* item;
	unsigned long result = CAPWAP_VALID_PACKET;
	struct capwap_resultcode_element* resultcodeelement = NULL;

	ASSERT(buildpacket != NULL);
	
	/* Reset flags */
	memset(elements, 0, sizeof(elements));
	
	/* Scan all elements */
	item = buildpacket->elementslist->first;
	while (item != NULL) {
		struct unrecognized_info info = { 0, 0 };
		struct capwap_message_element* elementitem = (struct capwap_message_element*)item->item;
		unsigned short type = ntohs(elementitem->type);
		struct capwap_message_elements_func* f = capwap_get_message_element(type);	\
		
		if (f && f->check && f->parsing) {
			if (f->check(elementitem)) {
				if (IS_MESSAGE_ELEMENTS(type)) {
					elements[type] = 1;
					if (type == CAPWAP_ELEMENT_RESULTCODE) {
						resultcodeelement = (struct capwap_resultcode_element*)f->parsing(elementitem);
					}
				} else if (IS_80211_MESSAGE_ELEMENTS(type)) {
					elements[type - ieee80211delta] = 1;
				} else {
					/* Unknown message element */
					info.element = type;
					info.reason = CAPWAP_REASON_UNKNOWN_MESSAGE_ELEMENT;
				}
			} else {
				/* Invalid message element */
				info.element = type;
				info.reason = CAPWAP_REASON_UNKNOWN_MESSAGE_ELEMENT_VALUE;
			}
		} else {
			/* Unable parsing message element */
			info.element = type;
			info.reason = CAPWAP_REASON_UNSUPPORTED_MESSAGE_ELEMENT;
		}
		
		/* Copy error */
		if ((info.element != 0) && reasonarray) {
			struct unrecognized_info* reasoninfo = capwap_array_get_item_pointer(reasonarray, reasonarray->count);
			
			memcpy(reasoninfo, &info, sizeof(struct unrecognized_info));
			result |= CAPWAP_UNRECOGNIZED_MSG_ELEMENT;
		}
		
		/* Next item */
		item = item->next;
	}
	
	/* Verify flags */
	binding = GET_WBID_HEADER(&buildpacket->header);
	switch (ntohl(buildpacket->ctrlmsg.type)) {
		case CAPWAP_DISCOVERY_REQUEST: {
			if (elements[CAPWAP_ELEMENT_DISCOVERYTYPE] && 
				elements[CAPWAP_ELEMENT_WTPBOARDDATA] && 
				elements[CAPWAP_ELEMENT_WTPDESCRIPTOR] && 
				elements[CAPWAP_ELEMENT_WTPFRAMETUNNELMODE] && 
				elements[CAPWAP_ELEMENT_WTPMACTYPE]) {
				
				if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
					if (!elements[CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION - ieee80211delta]) {
						result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
					}
				}
			} else {
				result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
			}
			
			break;
		}
		
		case CAPWAP_DISCOVERY_RESPONSE: {
			if (elements[CAPWAP_ELEMENT_ACDESCRIPTION] && 
				elements[CAPWAP_ELEMENT_ACNAME] &&
				(elements[CAPWAP_ELEMENT_CONTROLIPV4] || elements[CAPWAP_ELEMENT_CONTROLIPV6])) {
				
				if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
					if (!elements[CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION - ieee80211delta]) {
						result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
					}
				}
			} else {
				result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
			}
			
			break;
		}
		
		case CAPWAP_JOIN_REQUEST: {
			if (elements[CAPWAP_ELEMENT_LOCATION] && 
				elements[CAPWAP_ELEMENT_WTPBOARDDATA] && 
				elements[CAPWAP_ELEMENT_WTPDESCRIPTOR] && 
				elements[CAPWAP_ELEMENT_WTPNAME] && 
				elements[CAPWAP_ELEMENT_SESSIONID] && 
				elements[CAPWAP_ELEMENT_WTPFRAMETUNNELMODE] && 
				elements[CAPWAP_ELEMENT_WTPMACTYPE] && 
				elements[CAPWAP_ELEMENT_ECNSUPPORT] &&
				(elements[CAPWAP_ELEMENT_LOCALIPV4] || elements[CAPWAP_ELEMENT_LOCALIPV6])) {
				
				if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
					if (!elements[CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION - ieee80211delta]) {
						result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
					}
				}
			} else {
				result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
			}

			break;
		}
		
		case CAPWAP_JOIN_RESPONSE: {
			if (elements[CAPWAP_ELEMENT_RESULTCODE]) {
				if ((resultcodeelement->code == CAPWAP_RESULTCODE_SUCCESS) || (resultcodeelement->code == CAPWAP_RESULTCODE_SUCCESS_NAT_DETECTED)) {
					if (elements[CAPWAP_ELEMENT_ACDESCRIPTION] && 
						elements[CAPWAP_ELEMENT_ACNAME] && 
						elements[CAPWAP_ELEMENT_ECNSUPPORT] && 
						(elements[CAPWAP_ELEMENT_CONTROLIPV4] || elements[CAPWAP_ELEMENT_CONTROLIPV6]) && 
						(elements[CAPWAP_ELEMENT_LOCALIPV4] || elements[CAPWAP_ELEMENT_LOCALIPV6])) {
					
						if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
							if (!elements[CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION - ieee80211delta]) {
								result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
							}
						}
					} else {
						result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
					}
				} else if (resultcodeelement->code == CAPWAP_RESULTCODE_FAILURE_UNRECOGNIZED_MESSAGE_ELEMENT) {
					if (!elements[CAPWAP_ELEMENT_RETURNEDMESSAGE]) {
						result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
					}
				}
			} else {
				result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
			}

			break;
		}
		
		case CAPWAP_CONFIGURATION_STATUS_REQUEST: {
			if (elements[CAPWAP_ELEMENT_ACNAME] && 
				elements[CAPWAP_ELEMENT_RADIOADMSTATE] &&
				elements[CAPWAP_ELEMENT_STATISTICSTIMER] &&
				elements[CAPWAP_ELEMENT_WTPREBOOTSTAT]) {
				/* TODO binding */				
			} else {
				result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
			}
			
			break;
		}
		
		case CAPWAP_CONFIGURATION_STATUS_RESPONSE: {
			if (elements[CAPWAP_ELEMENT_TIMERS] && 
				elements[CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD] &&
				elements[CAPWAP_ELEMENT_IDLETIMEOUT] &&
				elements[CAPWAP_ELEMENT_WTPFALLBACK] &&
				(elements[CAPWAP_ELEMENT_ACIPV4LIST] || elements[CAPWAP_ELEMENT_ACIPV6LIST])) {
				/* TODO binding */				
			} else {
				result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
			}
			
			break;
		}
		
		case CAPWAP_CONFIGURATION_UPDATE_REQUEST: {
			break;
		}
		
		case CAPWAP_CONFIGURATION_UPDATE_RESPONSE: {
			break;
		}
		
		case CAPWAP_WTP_EVENT_REQUEST: {
			break;
		}
		
		case CAPWAP_WTP_EVENT_RESPONSE: {
			break;
		}

		case CAPWAP_CHANGE_STATE_EVENT_REQUEST: {
			if (elements[CAPWAP_ELEMENT_RADIOOPRSTATE] && 
				elements[CAPWAP_ELEMENT_RESULTCODE]) {
				/* TODO binding */				
			} else {
				result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
			}
			break;
		}
		
		case CAPWAP_CHANGE_STATE_EVENT_RESPONSE: {
			/* TODO binding */
			break;
		}
		
		case CAPWAP_ECHO_REQUEST: {
			break;
		}
		
		case CAPWAP_ECHO_RESPONSE: {
			break;
		}
		
		case CAPWAP_IMAGE_DATA_REQUEST: {
			break;
		}
		
		case CAPWAP_IMAGE_DATA_RESPONSE: {
			break;
		}
		
		case CAPWAP_RESET_REQUEST: {
			if (!elements[CAPWAP_ELEMENT_IMAGEIDENTIFIER]) {
				result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
			}

			break;
		}
		
		case CAPWAP_RESET_RESPONSE: {
			if (!elements[CAPWAP_ELEMENT_RESULTCODE]) {
				result |= CAPWAP_MISSING_MANDATORY_MSG_ELEMENT;
			}

			break;
		}
		
		case CAPWAP_PRIMARY_DISCOVERY_REQUEST: {
			break;
		}
		
		case CAPWAP_PRIMARY_DISCOVERY_RESPONSE: {
			break;
		}

		case CAPWAP_DATA_TRANSFER_REQUEST: {
			break;
		}
		
		case CAPWAP_DATA_TRANSFER_RESPONSE: {
			break;
		}
		
		case CAPWAP_CLEAR_CONFIGURATION_REQUEST: {
			break;
		}
		
		case CAPWAP_CLEAR_CONFIGURATION_RESPONSE: {
			break;
		}
		
		case CAPWAP_STATION_CONFIGURATION_REQUEST: {
			break;
		}
		
		case CAPWAP_STATION_CONFIGURATION_RESPONSE: {
			break;
		}
	}

	if (resultcodeelement) {
		capwap_get_message_element(CAPWAP_ELEMENT_RESULTCODE)->free(resultcodeelement);
	}

	return result;
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
		(type == CAPWAP_STATION_CONFIGURATION_REQUEST)) {
			
		/* Request type */
		return 1;
	}

	return 0;
}

/* Retrieve packet digest */
void capwap_get_packet_digest(void* buffer, unsigned long length, unsigned char packetdigest[16]) {
	MD5_CTX mdContext;
	
	ASSERT(buffer != NULL);
	ASSERT(length > 0);
	
	MD5Init(&mdContext);
	MD5Update(&mdContext, (unsigned char*)buffer, length);
	MD5Final(&mdContext);
	
	memcpy(&packetdigest[0], &mdContext.digest[0], sizeof(unsigned char) * 16);
}

/* Verify duplicate packet */
int capwap_recv_retrasmitted_request(struct capwap_dtls* dtls, struct capwap_packet* packet, unsigned char lastseqnumber, unsigned char packetdigest[16], struct capwap_socket* sock, capwap_fragment_packet_array* txfragmentpacket, struct sockaddr_storage* sendfromaddr, struct sockaddr_storage* sendtoaddr) {
	unsigned char recvpacketdigest[16];
	unsigned short lengthpayload;
	
	ASSERT(packet != NULL);
	ASSERT(sock != NULL);
	ASSERT(txfragmentpacket != NULL);
	ASSERT(sendtoaddr != NULL);

	lengthpayload = packet->packetsize - GET_HLEN_HEADER(packet->header) * 4;
	if (lengthpayload >= sizeof(struct capwap_control_message)) {
		struct capwap_control_message* ctrlmsg = (struct capwap_control_message*)packet->payload;
		
		/* Check if request */
		if (capwap_is_request_type(ntohl(ctrlmsg->type)) && (ctrlmsg->seq == lastseqnumber)) {
			/* Check packet digest */
			capwap_get_packet_digest((void*)packet->header, packet->packetsize, recvpacketdigest);
			if (!memcmp(&recvpacketdigest[0], &packetdigest[0], sizeof(unsigned char) * 16)) {
				int i;
				
				/* Retransmit response */
				for (i = 0; i < txfragmentpacket->count; i++) {
					struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(txfragmentpacket, i);
					ASSERT(txpacket != NULL);
					
					if (!capwap_crypt_sendto(dtls, sock->socket[sock->type], txpacket->header, txpacket->packetsize, sendfromaddr, sendtoaddr)) {
						capwap_logging_debug("Warning: error to resend response packet");
						break;
					}
				}
				
				return 1;
			}
		}
	}

	return 0;
}

/* Check valid message type */
int capwap_check_message_type(struct capwap_dtls* dtls, struct capwap_packet* packet, unsigned short mtu) {
	unsigned short lengthpayload;

	ASSERT(packet != NULL);
	ASSERT(mtu > 0);
	
	lengthpayload = packet->packetsize - GET_HLEN_HEADER(packet->header) * 4;
	if (lengthpayload >= sizeof(struct capwap_control_message)) {
		struct capwap_control_message* ctrlmsg = (struct capwap_control_message*)packet->payload;
		unsigned long type = ntohl(ctrlmsg->type);
		
		if ((type >= CAPWAP_FIRST_MESSAGE_TYPE) && (type <= CAPWAP_LAST_MESSAGE_TYPE)) {
			return 1;
		}
		
		/* Unknown message type */
		if ((type % 2) != 0) {
			int i;
			struct capwap_build_packet* responsepacket;
			struct capwap_resultcode_element resultcode = { CAPWAP_RESULTCODE_MSG_UNEXPECTED_UNRECOGNIZED_REQUEST };
			capwap_fragment_packet_array* txfragmentpacket = NULL;
			
			/* Odd message type, response with "Unrecognized Request" */
			responsepacket = capwap_tx_packet_create(CAPWAP_RADIOID_NONE, GET_WBID_HEADER(packet->header));
			responsepacket->isctrlmsg = 1;
			capwap_build_packet_set_control_message_type(responsepacket, type + 1, ctrlmsg->seq);
			capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_RESULTCODE_ELEMENT(&resultcode));

			txfragmentpacket = capwap_array_create(sizeof(struct capwap_packet), 0);
			if (capwap_fragment_build_packet(responsepacket, txfragmentpacket, mtu, 0) >= 0) {	
				for (i = 0; i < txfragmentpacket->count; i++) {
					struct capwap_packet* txpacket = (struct capwap_packet*)capwap_array_get_item_pointer(txfragmentpacket, i);
					ASSERT(txpacket != NULL);
					
					if (!capwap_crypt_sendto(dtls, packet->socket.socket[packet->socket.type], txpacket->header, txpacket->packetsize, &packet->remoteaddr, &packet->remoteaddr)) {
						break;
					}
				}
			}
			
			/* Free memory */
			capwap_fragment_free(txfragmentpacket);
			capwap_array_free(txfragmentpacket);
			capwap_build_packet_free(responsepacket);
		}
	}	
	
	return 0;
}

int capwap_get_sessionid_from_keepalive(struct capwap_build_packet* buildpacket, struct capwap_sessionid_element* session) {
	int found = 0;

	ASSERT(buildpacket != NULL);
	ASSERT(session != NULL);

	/* Check is Data Packet KeepAlive */
	if (IS_FLAG_K_HEADER(&buildpacket->header) && !capwap_build_packet_validate(buildpacket, NULL)) {
		struct capwap_list_item* item = buildpacket->elementslist->first;

		while (!found && (item != NULL)) {
			struct capwap_message_element* elementitem = (struct capwap_message_element*)item->item;
			unsigned short type = ntohs(elementitem->type);
			struct capwap_message_elements_func* f = capwap_get_message_element(type);
			
			ASSERT(f != NULL);
			ASSERT(f->parsing != NULL);
			
			switch (type) {
				case CAPWAP_ELEMENT_SESSIONID: {
					struct capwap_sessionid_element* tempsession;
					
					tempsession = (struct capwap_sessionid_element*)f->parsing(elementitem);
					memcpy(session, tempsession, sizeof(struct capwap_sessionid_element));
					f->free(tempsession);
					
					found = 1;
					break;
				}
			}
			
			/* Next element */
			item = item->next;
		}
	}
	
	return found;
}
