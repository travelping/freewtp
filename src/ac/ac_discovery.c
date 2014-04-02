#include "ac.h"
#include "capwap_protocol.h"
#include "ac_discovery.h"
#include "ac_session.h"

#define AC_DISCOVERY_CLEANUP_TIMEOUT					1000

struct ac_discovery_t {
	pthread_t threadid;
	int endthread;
	
	unsigned short fragmentid;
	unsigned char txseqnumber;
	
	capwap_event_t waitpacket;
	capwap_lock_t packetslock;
	struct capwap_list* packets;
};

struct ac_discovery_packet {
	int sendsock;
	struct sockaddr_storage sender;
	char data[0];
};

static struct ac_discovery_t g_ac_discovery;

/* */
void ac_discovery_add_packet(void* buffer, int buffersize, int sock, struct sockaddr_storage* sender) {
	struct capwap_list_item* item;
	struct ac_discovery_packet* packet;
	
	ASSERT(buffer != NULL);
	ASSERT(buffersize > 0);
	ASSERT(sock >= 0);
	ASSERT(sender != NULL);
	
	/* TODO: mettere un history delle discovery request già processate per non eseguirle di nuovo */
	/* L'elemento deve rimanere per la durata minima di una discovery request */
	
	/* Copy packet */
	item = capwap_itemlist_create(sizeof(struct ac_discovery_packet) + buffersize);
	packet = (struct ac_discovery_packet*)item->item;
	packet->sendsock = sock;
	memcpy(&packet->sender, sender, sizeof(struct sockaddr_storage));
	memcpy(packet->data, buffer, buffersize);
	
	/* Append to packets list */
	capwap_lock_enter(&g_ac_discovery.packetslock);
	capwap_itemlist_insert_after(g_ac_discovery.packets, NULL, item);
	capwap_event_signal(&g_ac_discovery.waitpacket);
	capwap_lock_exit(&g_ac_discovery.packetslock);
}

/* */
static struct capwap_packet_txmng* ac_create_discovery_response(struct capwap_parsed_packet* packet) {
	int i;
	unsigned short binding;
	struct capwap_list* controllist;
	struct capwap_list_item* item;
	struct capwap_header_data capwapheader;
	struct capwap_packet_txmng* txmngpacket;

	/* Check is valid binding */
	binding = GET_WBID_HEADER(packet->rxmngpacket->header);
	if (!ac_valid_binding(binding)) {
		return NULL;
	}

	/* Update statistics */
	ac_update_statistics();

	/* Build packet */
	capwap_header_init(&capwapheader, CAPWAP_RADIOID_NONE, binding);
	txmngpacket = capwap_packet_txmng_create_ctrl_message(&capwapheader, CAPWAP_DISCOVERY_RESPONSE, packet->rxmngpacket->ctrlmsg.seq, g_ac.mtu);

	/* Prepare discovery response */
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ACDESCRIPTION, &g_ac.descriptor);
	capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_ACNAME, &g_ac.acname);
	if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		struct capwap_array* wtpradioinformation = (struct capwap_array*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION);

		for (i = 0; i < wtpradioinformation->count; i++) {
			struct capwap_80211_wtpradioinformation_element* radio;

			radio = *(struct capwap_80211_wtpradioinformation_element**)capwap_array_get_item_pointer(wtpradioinformation, i);
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION, radio);
		}
	}

	/* Get information from any local address */
	controllist = capwap_list_create();
	ac_get_control_information(controllist);

	for (item = controllist->first; item != NULL; item = item->next) {
		struct ac_session_control* sessioncontrol = (struct ac_session_control*)item->item;
	
		if (sessioncontrol->localaddress.ss_family == AF_INET) {
			struct capwap_controlipv4_element element;

			memcpy(&element.address, &((struct sockaddr_in*)&sessioncontrol->localaddress)->sin_addr, sizeof(struct in_addr));
			element.wtpcount = sessioncontrol->count;
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_CONTROLIPV4, &element);
		} else if (sessioncontrol->localaddress.ss_family == AF_INET6) {
			struct capwap_controlipv6_element element;

			memcpy(&element.address, &((struct sockaddr_in6*)&sessioncontrol->localaddress)->sin6_addr, sizeof(struct in6_addr));
			element.wtpcount = sessioncontrol->count;
			capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_CONTROLIPV6, &element);
		}
	}

	capwap_list_free(controllist);

	/* CAPWAP_ELEMENT_VENDORPAYLOAD */					/* TODO */

	return txmngpacket;
}

/* Cleanup info discovery */
static void ac_discovery_cleanup(void) {
	/* Clean history discovery request */
	/* TODO */
}

/* */
static void ac_discovery_run(void) {
	int sizedata;
	struct capwap_list_item* itempacket;
	struct ac_discovery_packet* acpacket;
	struct capwap_parsed_packet packet;
	struct capwap_packet_rxmng* rxmngpacket;

	while (!g_ac_discovery.endthread) {
		/* Get packet */
		capwap_lock_enter(&g_ac_discovery.packetslock);

		itempacket = NULL; 
		if (g_ac_discovery.packets->count > 0) {
			itempacket = capwap_itemlist_remove_head(g_ac_discovery.packets);
		}

		capwap_lock_exit(&g_ac_discovery.packetslock);

		if (!itempacket) {
			/* Wait packet with timeout*/
			if (!capwap_event_wait_timeout(&g_ac_discovery.waitpacket, AC_DISCOVERY_CLEANUP_TIMEOUT)) {
				ac_discovery_cleanup();
			}
			
			continue;
		}

		/* */
		acpacket = (struct ac_discovery_packet*)itempacket->item;
		sizedata = itempacket->itemsize - sizeof(struct ac_discovery_packet);

		/* Accept only discovery request don't fragment */
		rxmngpacket = capwap_packet_rxmng_create_message(CAPWAP_CONTROL_PACKET);
		if (capwap_packet_rxmng_add_recv_packet(rxmngpacket, acpacket->data, sizedata) == CAPWAP_RECEIVE_COMPLETE_PACKET) {
			/* Validate message */
			if (capwap_check_message_type(rxmngpacket) == VALID_MESSAGE_TYPE) {
				/* Parsing packet */
				if (capwap_parsing_packet(rxmngpacket, NULL, &packet) == PARSING_COMPLETE) {
					/* Validate packet */
					if (!capwap_validate_parsed_packet(&packet, NULL)) {
						struct capwap_packet_txmng* txmngpacket;

						/* */
						capwap_logging_debug("Receive discovery request packet");

						/* Creare discovery response */
						txmngpacket = ac_create_discovery_response(&packet);
						if (txmngpacket) {
							struct capwap_list* responsefragmentpacket;

							/* Discovery response complete, get fragment packets */
							responsefragmentpacket = capwap_list_create();
							capwap_packet_txmng_get_fragment_packets(txmngpacket, responsefragmentpacket, g_ac_discovery.fragmentid);
							if (responsefragmentpacket->count > 1) {
								g_ac_discovery.fragmentid++;
							}

							/* Free packets manager */
							capwap_packet_txmng_free(txmngpacket);

							/* Send discovery response to WTP */
							if (!capwap_sendto_fragmentpacket(acpacket->sendsock, responsefragmentpacket, NULL, &acpacket->sender)) {
								capwap_logging_debug("Warning: error to send discovery response packet");
							}

							/* Don't buffering a packets sent */
							capwap_list_free(responsefragmentpacket);
						}
					}
				}

				/* Free resource */
				capwap_free_parsed_packet(&packet);
			}
		}

		/* Free resource */
		capwap_packet_rxmng_free(rxmngpacket);

		/* Free packet */
		capwap_itemlist_free(itempacket);
	}
}

/* */
static void* ac_discovery_thread(void* param) {
	
	capwap_logging_debug("Discovery start");
	ac_discovery_run();
	capwap_logging_debug("Discovery stop");

	/* Thread exit */
	pthread_exit(NULL);
	return NULL;	
}

/* */
int ac_discovery_start(void) {
	int result;
	
	memset(&g_ac_discovery, 0, sizeof(struct ac_discovery_t));

	/* Init */
	capwap_event_init(&g_ac_discovery.waitpacket);
	capwap_lock_init(&g_ac_discovery.packetslock);
	g_ac_discovery.packets = capwap_list_create();

	/* Create thread */
	result = pthread_create(&g_ac_discovery.threadid, NULL, ac_discovery_thread, NULL);
	if (result) {
		capwap_logging_debug("Unable create discovery thread");
		return 0;
	}
	
	return 1;
}

/* */
void ac_discovery_stop(void) {
	void* dummy;
	
	g_ac_discovery.endthread = 1;
	capwap_event_signal(&g_ac_discovery.waitpacket);
	pthread_join(g_ac_discovery.threadid, &dummy);

	/* Free memory */
	capwap_event_destroy(&g_ac_discovery.waitpacket);
	capwap_lock_destroy(&g_ac_discovery.packetslock);
	capwap_list_free(g_ac_discovery.packets);
}
