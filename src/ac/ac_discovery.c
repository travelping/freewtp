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
	capwap_lock_exit(&g_ac_discovery.packetslock);
	capwap_list_free(g_ac_discovery.packets);
}

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
static struct capwap_build_packet* ac_create_discovery_response(struct capwap_build_packet* packet, struct capwap_element_discovery_request* discoveryrequest, struct sockaddr_storage* sender) {
	int i;
	unsigned short binding;
	struct capwap_list* controllist;
	struct capwap_list_item* item;
	struct capwap_build_packet* responsepacket;

	ASSERT(packet != NULL);
	ASSERT(discoveryrequest != NULL);
	ASSERT(sender != NULL);

	/* Check is valid binding */
	binding = GET_WBID_HEADER(&packet->header);
	if (!ac_valid_binding(binding)) {
		return NULL;
	}

	/* Build packet */
	responsepacket = capwap_tx_packet_create(CAPWAP_RADIOID_NONE, binding);
	responsepacket->isctrlmsg = 1;
	
	/* Update statistics */
	ac_update_statistics();
	
	/* Prepare discovery response */
	capwap_build_packet_set_control_message_type(responsepacket, CAPWAP_DISCOVERY_RESPONSE, packet->ctrlmsg.seq);
	capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_ACDESCRIPTOR_ELEMENT(&g_ac.descriptor));
	capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_ACNAME_ELEMENT(&g_ac.acname));

	if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		for (i = 0; i < discoveryrequest->binding.ieee80211.wtpradioinformation->count; i++) {
			struct capwap_80211_wtpradioinformation_element* radio;

			radio = (struct capwap_80211_wtpradioinformation_element*)capwap_array_get_item_pointer(discoveryrequest->binding.ieee80211.wtpradioinformation, i);
			capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_80211_WTPRADIOINFORMATION_ELEMENT(radio));
		}
	} else {
		capwap_logging_debug("Unknown capwap binding");
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
			capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_CONTROLIPV4_ELEMENT(&element));
		} else if (sessioncontrol->localaddress.ss_family == AF_INET6) {
			struct capwap_controlipv6_element element;
			
			memcpy(&element.address, &((struct sockaddr_in6*)&sessioncontrol->localaddress)->sin6_addr, sizeof(struct in6_addr));
			element.wtpcount = sessioncontrol->count;
			capwap_build_packet_add_message_element(responsepacket, CAPWAP_CREATE_CONTROLIPV6_ELEMENT(&element));
		}
	}

	capwap_list_free(controllist);	
	
	/* CAPWAP_CREATE_VENDORSPECIFICPAYLOAD_ELEMENT */	/* TODO */

	return responsepacket;
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
	struct capwap_build_packet* buildpacket;
	struct ac_discovery_packet* packet;
	unsigned short binding;
	
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
		packet = (struct ac_discovery_packet*)itempacket->item;
		sizedata = itempacket->itemsize - sizeof(struct ac_discovery_packet);

		/* Parsing packet */
		buildpacket = capwap_rx_packet_create(packet->data, sizedata, 1);
		if (buildpacket) {
			if (!capwap_build_packet_validate(buildpacket, NULL)) {
				struct capwap_element_discovery_request discoveryrequest;
				
				/* */
				binding = GET_WBID_HEADER(&buildpacket->header);
				capwap_init_element_discovery_request(&discoveryrequest, binding);
				
				/* Parsing elements list */
				if (capwap_parsing_element_discovery_request(&discoveryrequest, buildpacket->elementslist->first)) {
					struct capwap_build_packet* txpacket;
					capwap_fragment_packet_array* responsefragmentpacket = NULL;

					/* Creare discovery response */
					txpacket = ac_create_discovery_response(buildpacket, &discoveryrequest, &packet->sender);
					if (txpacket) {
						int result = -1;
						
						if (!capwap_build_packet_validate(txpacket, NULL)) {
							responsefragmentpacket = capwap_array_create(sizeof(struct capwap_packet), 0);
							result = capwap_fragment_build_packet(txpacket, responsefragmentpacket, g_ac.mtu, g_ac_discovery.fragmentid);
							if (result == 1) {
								g_ac_discovery.fragmentid++;
							}
						} else {
							capwap_logging_debug("Warning: build invalid discovery response packet");
						}
		
						capwap_build_packet_free(txpacket);
	
						/* Send discovery response to WTP */
						if (result >= 0) {
							int i;
				
							for (i = 0; i < responsefragmentpacket->count; i++) {
								struct capwap_packet* sendpacket = (struct capwap_packet*)capwap_array_get_item_pointer(responsefragmentpacket, i);
								ASSERT(sendpacket != NULL);
								
								if (!capwap_sendto(packet->sendsock, sendpacket->header, sendpacket->packetsize, NULL, &packet->sender)) {
									capwap_logging_debug("Warning: error to send discovery response packet");
									break;
								}
							}
						}
					}
					
					/* Don't buffering a packets sent */
					if (responsefragmentpacket) {
						capwap_fragment_free(responsefragmentpacket);
						capwap_array_free(responsefragmentpacket);
					}
				}
				
				/* Free discovery request */
				capwap_free_element_discovery_request(&discoveryrequest, binding);
			}
			
			/* */
			capwap_build_packet_free(buildpacket);
		}

		/* Free packet */
		capwap_itemlist_free(itempacket);
	}
}

/* */
void* ac_discovery_thread(void* param) {
	
	capwap_logging_debug("Discovery start");
	ac_discovery_run();
	capwap_logging_debug("Discovery stop");

	/* Thread exit */
	pthread_exit(NULL);
	return NULL;	
}
