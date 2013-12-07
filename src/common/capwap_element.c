#include "capwap.h"
#include "capwap_element.h"
#include "capwap_protocol.h"
#include "capwap_array.h"

/* */
int capwap_get_message_element_category(uint16_t type) {
	switch (type) {
		case CAPWAP_ELEMENT_ACNAMEPRIORITY:
		case CAPWAP_ELEMENT_CONTROLIPV4:
		case CAPWAP_ELEMENT_CONTROLIPV6:
		case CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD:
		case CAPWAP_ELEMENT_RADIOADMSTATE:
		case CAPWAP_ELEMENT_RADIOOPRSTATE:
		case CAPWAP_ELEMENT_RETURNEDMESSAGE:
		case CAPWAP_ELEMENT_80211_ANTENNA:
		case CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL:
		case CAPWAP_ELEMENT_80211_IE:
		case CAPWAP_ELEMENT_80211_MACOPERATION:
		case CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY:
		case CAPWAP_ELEMENT_80211_OFDMCONTROL:
		case CAPWAP_ELEMENT_80211_RATESET:
		case CAPWAP_ELEMENT_80211_STATISTICS:
		case CAPWAP_ELEMENT_80211_SUPPORTEDRATES:
		case CAPWAP_ELEMENT_80211_TXPOWER:
		case CAPWAP_ELEMENT_80211_TXPOWERLEVEL:
		case CAPWAP_ELEMENT_80211_WTP_QOS:
		case CAPWAP_ELEMENT_80211_WTP_RADIO_CONF:
		case CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION: {
			return CAPWAP_MESSAGE_ELEMENT_ARRAY;
		}
	}

	return CAPWAP_MESSAGE_ELEMENT_SINGLE;
}

/* */
static struct capwap_message_elements_ops* capwap_message_elements[] = {
	/* CAPWAP_ELEMENT_ACDESCRIPTION */ &capwap_element_acdescriptor_ops,
	/* CAPWAP_ELEMENT_ACIPV4LIST */ &capwap_element_acipv4list_ops,
	/* CAPWAP_ELEMENT_ACIPV6LIST */ &capwap_element_acipv6list_ops,
	/* CAPWAP_ELEMENT_ACNAME */ &capwap_element_acname_ops,
	/* CAPWAP_ELEMENT_ACNAMEPRIORITY */ &capwap_element_acnamepriority_ops,
	/* CAPWAP_ELEMENT_ACTIMESTAMP */ &capwap_element_actimestamp_ops,
	/* CAPWAP_ELEMENT_ADDMACACL */ &capwap_element_addmacacl_ops,
	/* CAPWAP_ELEMENT_ADDSTATION */ &capwap_element_addstation_ops,
	/* Reserved */ NULL,
	/* CAPWAP_ELEMENT_CONTROLIPV4 */ &capwap_element_controlipv4_ops,
	/* CAPWAP_ELEMENT_CONTROLIPV6 */ &capwap_element_controlipv6_ops,
	/* CAPWAP_ELEMENT_TIMERS */ &capwap_element_timers_ops,
	/* CAPWAP_ELEMENT_DATATRANSFERDATA */ &capwap_element_datatransferdata_ops,
	/* CAPWAP_ELEMENT_DATATRANSFERMODE */ &capwap_element_datatransfermode_ops,
	/* CAPWAP_ELEMENT_DECRYPTERRORREPORT */ &capwap_element_decrypterrorreport_ops,
	/* CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD */ &capwap_element_decrypterrorreportperiod_ops,
	/* CAPWAP_ELEMENT_DELETEMACACL */ &capwap_element_deletemacacl_ops,
	/* CAPWAP_ELEMENT_DELETESTATION */ &capwap_element_deletestation_ops,
	/* Reserved */ NULL,
	/* CAPWAP_ELEMENT_DISCOVERYTYPE */ &capwap_element_discoverytype_ops,
	/* CAPWAP_ELEMENT_DUPLICATEIPV4 */ &capwap_element_duplicateipv4_ops,
	/* CAPWAP_ELEMENT_DUPLICATEIPV6 */ &capwap_element_duplicateipv6_ops,
	/* CAPWAP_ELEMENT_IDLETIMEOUT */ &capwap_element_idletimeout_ops,
	/* CAPWAP_ELEMENT_IMAGEDATA */ &capwap_element_imagedata_ops,
	/* CAPWAP_ELEMENT_IMAGEIDENTIFIER */ &capwap_element_imageidentifier_ops,
	/* CAPWAP_ELEMENT_IMAGEINFO */ &capwap_element_imageinfo_ops,
	/* CAPWAP_ELEMENT_INITIATEDOWNLOAD */ &capwap_element_initdownload_ops,
	/* CAPWAP_ELEMENT_LOCATION */ &capwap_element_location_ops,
	/* CAPWAP_ELEMENT_MAXIMUMLENGTH */ &capwap_element_maximumlength_ops,
	/* CAPWAP_ELEMENT_LOCALIPV4 */ &capwap_element_localipv4_ops,
	/* CAPWAP_ELEMENT_RADIOADMSTATE */ &capwap_element_radioadmstate_ops,
	/* CAPWAP_ELEMENT_RADIOOPRSTATE */ &capwap_element_radiooprstate_ops,
	/* CAPWAP_ELEMENT_RESULTCODE */ &capwap_element_resultcode_ops,
	/* CAPWAP_ELEMENT_RETURNEDMESSAGE */ &capwap_element_returnedmessage_ops,
	/* CAPWAP_ELEMENT_SESSIONID */ &capwap_element_sessionid_ops,
	/* CAPWAP_ELEMENT_STATISTICSTIMER */ &capwap_element_statisticstimer_ops,
	/* CAPWAP_ELEMENT_VENDORPAYLOAD */ &capwap_element_vendorpayload_ops,
	/* CAPWAP_ELEMENT_WTPBOARDDATA */ &capwap_element_wtpboarddata_ops,
	/* CAPWAP_ELEMENT_WTPDESCRIPTOR */ &capwap_element_wtpdescriptor_ops,
	/* CAPWAP_ELEMENT_WTPFALLBACK */ &capwap_element_wtpfallback_ops,
	/* CAPWAP_ELEMENT_WTPFRAMETUNNELMODE */ &capwap_element_wtpframetunnelmode_ops,
	/* Reserved */ NULL,
	/* Reserved */ NULL,
	/* CAPWAP_ELEMENT_WTPMACTYPE */ &capwap_element_wtpmactype_ops,
	/* CAPWAP_ELEMENT_WTPNAME */ &capwap_element_wtpname_ops,
	/* Reserved */ NULL,
	/* CAPWAP_ELEMENT_WTPRADIOSTAT */ &capwap_element_wtpradiostat_ops,
	/* CAPWAP_ELEMENT_WTPREBOOTSTAT */ &capwap_element_wtprebootstat_ops,
	/* CAPWAP_ELEMENT_WTPSTATICIPADDRESS */ &capwap_element_wtpstaticipaddress_ops,
	/* CAPWAP_ELEMENT_LOCALIPV6 */ &capwap_element_localipv6_ops,
	/* CAPWAP_ELEMENT_TRANSPORT */ &capwap_element_transport_ops,
	/* CAPWAP_ELEMENT_MTUDISCOVERY */ &capwap_element_mtudiscovery_ops,
	/* CAPWAP_ELEMENT_ECNSUPPORT */ &capwap_element_ecnsupport_ops
};

/* */
static struct capwap_message_elements_ops* capwap_80211_message_elements[] = {
	/* CAPWAP_ELEMENT_80211_ADD_WLAN */ &capwap_element_80211_addwlan_ops,
	/* CAPWAP_ELEMENT_80211_ANTENNA */ &capwap_element_80211_antenna_ops,
	/* CAPWAP_ELEMENT_80211_ASSIGN_BSSID */ &capwap_element_80211_assignbssid_ops,
	/* CAPWAP_ELEMENT_80211_DELETE_WLAN */ &capwap_element_80211_deletewlan_ops,
	/* CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL */ &capwap_element_80211_directsequencecontrol_ops,
	/* CAPWAP_ELEMENT_80211_IE */ &capwap_element_80211_ie_ops,
	/* CAPWAP_ELEMENT_80211_MACOPERATION */ &capwap_element_80211_macoperation_ops,
	/* CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES */ &capwap_element_80211_miccountermeasures_ops,
	/* CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY */ &capwap_element_80211_multidomaincapability_ops,
	/* CAPWAP_ELEMENT_80211_OFDMCONTROL */ &capwap_element_80211_ofdmcontrol_ops,
	/* CAPWAP_ELEMENT_80211_RATESET */ &capwap_element_80211_rateset_ops,
	/* CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT */ &capwap_element_80211_rsnaerrorreport_ops,
	/* CAPWAP_ELEMENT_80211_STATION */ &capwap_element_80211_station_ops,
	/* CAPWAP_ELEMENT_80211_STATION_QOS_PROFILE */ &capwap_element_80211_stationqos_ops,
	/* CAPWAP_ELEMENT_80211_STATION_SESSION_KEY_PROFILE */ &capwap_element_80211_stationkey_ops,
	/* CAPWAP_ELEMENT_80211_STATISTICS */ &capwap_element_80211_statistics_ops,
	/* CAPWAP_ELEMENT_80211_SUPPORTEDRATES */ &capwap_element_80211_supportedrates_ops,
	/* CAPWAP_ELEMENT_80211_TXPOWER */ &capwap_element_80211_txpower_ops,
	/* CAPWAP_ELEMENT_80211_TXPOWERLEVEL */ &capwap_element_80211_txpowerlevel_ops,
	/* CAPWAP_ELEMENT_80211_UPDATE_STATION_QOS */ &capwap_element_80211_updatestationqos_ops,
	/* CAPWAP_ELEMENT_80211_UPDATE_WLAN */ &capwap_element_80211_updatewlan_ops,
	/* CAPWAP_ELEMENT_80211_WTP_QOS */ &capwap_element_80211_wtpqos_ops,
	/* CAPWAP_ELEMENT_80211_WTP_RADIO_CONF */ &capwap_element_80211_wtpradioconf_ops,
	/* CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM */ &capwap_element_80211_wtpradiofailalarm_ops,
	/* CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION */ &capwap_element_80211_wtpradioinformation_ops
};

/* */
struct capwap_message_elements_ops* capwap_get_message_element_ops(unsigned short code) {
	if (IS_MESSAGE_ELEMENTS(code)) {
		return capwap_message_elements[code - CAPWAP_MESSAGE_ELEMENTS_START];
	} else if (IS_80211_MESSAGE_ELEMENTS(code)) {
		return capwap_80211_message_elements[code - CAPWAP_80211_MESSAGE_ELEMENTS_START];
	}
	
	return NULL;
}

/* */
struct capwap_list_item* capwap_get_message_element(struct capwap_parsed_packet* packet, uint16_t type) {
	struct capwap_list_item* search;

	ASSERT(packet != NULL);
	ASSERT(packet->messages != NULL);

	search = packet->messages->first;
	while (search) {
		struct capwap_message_element_itemlist* messageelement = (struct capwap_message_element_itemlist*)search->item;

		if (messageelement->type == type) {
			return search;
		}

		/* */
		search = search->next;
	}

	return NULL;
}

/* */
void* capwap_get_message_element_data(struct capwap_parsed_packet* packet, uint16_t type) {
	struct capwap_list_item* itemlist;
	struct capwap_message_element_itemlist* messageelement;

	/* Retrieve item list */
	itemlist = capwap_get_message_element(packet, type);
	if (!itemlist) {
		return NULL;
	}

	/* Get message element info */
	messageelement = (struct capwap_message_element_itemlist*)itemlist->item;
	ASSERT(messageelement != NULL);

	return messageelement->data;
}

/* */
int capwap_parsing_packet(struct capwap_packet_rxmng* rxmngpacket, struct capwap_connection* connection, struct capwap_parsed_packet* packet) {
	unsigned short binding;

	ASSERT(rxmngpacket != NULL);
	ASSERT(packet != NULL);

	/* */
	memset(packet, 0, sizeof(struct capwap_parsed_packet));
	packet->rxmngpacket = rxmngpacket;
	packet->connection = connection;
	packet->messages = capwap_list_create();

	binding = GET_WBID_HEADER(packet->rxmngpacket->header);

	/* Position reader to capwap body */
	memcpy(&rxmngpacket->readpos, &rxmngpacket->readbodypos, sizeof(struct read_block_from_pos));

	if (rxmngpacket->isctrlpacket) {
		unsigned short bodylength = rxmngpacket->ctrlmsg.length - CAPWAP_CONTROL_MESSAGE_MIN_LENGTH;
		while (bodylength > 0) {
			uint16_t type;
			uint16_t msglength;
			int category;
			struct capwap_list_item* itemlist;
			struct capwap_message_element_itemlist* messageelement;
			struct capwap_message_elements_ops* read_ops;

			/* Get type and length */
			rxmngpacket->readerpacketallowed = sizeof(struct capwap_message_element);
			if (rxmngpacket->read_ops.read_u16((capwap_message_elements_handle)rxmngpacket, &type) != sizeof(uint16_t)) {
				return INVALID_MESSAGE_ELEMENT;
			}

			/* Check type */
			if (!IS_VALID_MESSAGE_ELEMENTS(type)) {
				return UNRECOGNIZED_MESSAGE_ELEMENT;
			}

			/* Check binding */
			if (IS_80211_MESSAGE_ELEMENTS(type) && (binding != CAPWAP_WIRELESS_BINDING_IEEE80211)) {
				return UNRECOGNIZED_MESSAGE_ELEMENT;
			}

			if (rxmngpacket->read_ops.read_u16((capwap_message_elements_handle)rxmngpacket, &msglength) != sizeof(uint16_t)) {
				return INVALID_MESSAGE_ELEMENT;
			}

			/* Check length */
			if (msglength > bodylength) {
				return INVALID_MESSAGE_ELEMENT;
			}

			/* Reader function */
			read_ops = capwap_get_message_element_ops(type);
			if (!read_ops) {
				return INVALID_MESSAGE_ELEMENT;
			}

			/* Allowed to parsing only the size of message element */
			rxmngpacket->readerpacketallowed = msglength;

			/* */
			itemlist = capwap_get_message_element(packet, type);
			category = capwap_get_message_element_category(type);
			if (category == CAPWAP_MESSAGE_ELEMENT_SINGLE) {
				/* Check for multiple message element */
				if (itemlist) {
					return INVALID_MESSAGE_ELEMENT;
				}

				/* Create new message element */
				itemlist = capwap_itemlist_create(sizeof(struct capwap_message_element_itemlist));
				messageelement = (struct capwap_message_element_itemlist*)itemlist->item;
				messageelement->type = type;
				messageelement->category = CAPWAP_MESSAGE_ELEMENT_SINGLE;
				messageelement->data = read_ops->parsing_message_element((capwap_message_elements_handle)rxmngpacket, &rxmngpacket->read_ops);
				if (!messageelement->data) { 
					capwap_itemlist_free(itemlist);
					return INVALID_MESSAGE_ELEMENT; 
				}

				/* */
				capwap_itemlist_insert_after(packet->messages, NULL, itemlist);
			} else if (category == CAPWAP_MESSAGE_ELEMENT_ARRAY) {
				void* datamsgelement;
				struct capwap_array* arraymessageelement;

				if (itemlist) {
					messageelement = (struct capwap_message_element_itemlist*)itemlist->item;
					arraymessageelement = (struct capwap_array*)messageelement->data;
				} else {
					arraymessageelement = capwap_array_create(sizeof(void*), 0, 0);

					/* */
					itemlist = capwap_itemlist_create(sizeof(struct capwap_message_element_itemlist));
					messageelement = (struct capwap_message_element_itemlist*)itemlist->item;
					messageelement->type = type;
					messageelement->category = CAPWAP_MESSAGE_ELEMENT_ARRAY;
					messageelement->data = (void*)arraymessageelement;

					/* */
					capwap_itemlist_insert_after(packet->messages, NULL, itemlist);
				}

				/* Get message element */
				datamsgelement = read_ops->parsing_message_element((capwap_message_elements_handle)rxmngpacket, &rxmngpacket->read_ops);
				if (!datamsgelement) { 
					return INVALID_MESSAGE_ELEMENT;
				}

				/* */
				memcpy(capwap_array_get_item_pointer(arraymessageelement, arraymessageelement->count), &datamsgelement, sizeof(void*));
			}

			/* Check if read all data of message element */
			if (rxmngpacket->readerpacketallowed) {
				return INVALID_MESSAGE_ELEMENT;
			}

			/* */
			bodylength -= (msglength + sizeof(struct capwap_message_element));
		}
	} else if (IS_FLAG_K_HEADER(rxmngpacket->header)) {
		uint16_t type;
		uint16_t msglength;
		struct capwap_list_item* itemlist;
		struct capwap_message_element_itemlist* messageelement;
		struct capwap_message_elements_ops* read_ops;
		unsigned short bodylength = rxmngpacket->datamsg.length - CAPWAP_DATA_MESSAGE_KEEPALIVE_MIN_LENGTH;

		/* Get type and length */
		rxmngpacket->readerpacketallowed = sizeof(struct capwap_message_element);
		rxmngpacket->read_ops.read_u16((capwap_message_elements_handle)rxmngpacket, &type);
		rxmngpacket->read_ops.read_u16((capwap_message_elements_handle)rxmngpacket, &msglength);

		/* Check length */
		if ((msglength + sizeof(struct capwap_message_element)) != bodylength) {
			return INVALID_MESSAGE_ELEMENT;
		}

		/* Allowed to parsing only the size of message element */
		rxmngpacket->readerpacketallowed = msglength;
		if (type != CAPWAP_ELEMENT_SESSIONID) {
			return UNRECOGNIZED_MESSAGE_ELEMENT;
		}

		/* Retrieve session id */
		read_ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_SESSIONID);
		itemlist = capwap_itemlist_create(sizeof(struct capwap_message_element_itemlist));
		messageelement = (struct capwap_message_element_itemlist*)itemlist->item;
		messageelement->type = CAPWAP_ELEMENT_SESSIONID;
		messageelement->category = CAPWAP_MESSAGE_ELEMENT_SINGLE;
		messageelement->data = read_ops->parsing_message_element((capwap_message_elements_handle)rxmngpacket, &rxmngpacket->read_ops);
		if (!messageelement->data) { 
			capwap_itemlist_free(itemlist);
			return INVALID_MESSAGE_ELEMENT; 
		}

		/* */
		capwap_itemlist_insert_after(packet->messages, NULL, itemlist);
	}

	return PARSING_COMPLETE;
}

/* */
int capwap_validate_parsed_packet(struct capwap_parsed_packet* packet, struct capwap_array* returnedmessage) {
	unsigned short binding;
	struct capwap_resultcode_element* resultcode;

	ASSERT(packet != NULL);
	ASSERT(packet->rxmngpacket != NULL);

	binding = GET_WBID_HEADER(packet->rxmngpacket->header);

	if (packet->rxmngpacket->isctrlpacket) {
		switch (packet->rxmngpacket->ctrlmsg.type) {
			case CAPWAP_DISCOVERY_REQUEST: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_DISCOVERYTYPE) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPBOARDDATA) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPDESCRIPTOR) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPFRAMETUNNELMODE) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPMACTYPE)) {

					if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
						if (capwap_get_message_element(packet, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION)) {
							return 0;
						}
					} else {
						return 0;
					}
				}

				break;
			}

			case CAPWAP_DISCOVERY_RESPONSE: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_ACDESCRIPTION) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_ACNAME) &&
					(capwap_get_message_element(packet, CAPWAP_ELEMENT_CONTROLIPV4) || capwap_get_message_element(packet, CAPWAP_ELEMENT_CONTROLIPV6))) {

					if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
						if (capwap_get_message_element(packet, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION)) {
							return 0;
						}
					} else {
						return 0;
					}
				}

				/* Check if packet contains Result Code with Error Message */
				resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
				if (resultcode && !CAPWAP_RESULTCODE_OK(resultcode->code)) {
					return 0;
				}

				break;
			}

			case CAPWAP_JOIN_REQUEST: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_LOCATION) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPBOARDDATA) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPDESCRIPTOR) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPNAME) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_SESSIONID) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPFRAMETUNNELMODE) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPMACTYPE) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_ECNSUPPORT) &&
					(capwap_get_message_element(packet, CAPWAP_ELEMENT_LOCALIPV4) || capwap_get_message_element(packet, CAPWAP_ELEMENT_LOCALIPV6))) {

					if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
						if (capwap_get_message_element(packet, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION)) {
							return 0;
						}
					} else {
						return 0;
					}
				}

				break;
			}

			case CAPWAP_JOIN_RESPONSE: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_RESULTCODE) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_ACDESCRIPTION) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_ACNAME) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_ECNSUPPORT) &&
					(capwap_get_message_element(packet, CAPWAP_ELEMENT_CONTROLIPV4) || capwap_get_message_element(packet, CAPWAP_ELEMENT_CONTROLIPV6)) &&
					(capwap_get_message_element(packet, CAPWAP_ELEMENT_LOCALIPV4) || capwap_get_message_element(packet, CAPWAP_ELEMENT_LOCALIPV6))) {

					if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
						if (capwap_get_message_element(packet, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION)) {
							return 0;
						}
					} else {
						return 0;
					}
				}

				/* Check if packet contains Result Code with Error Message */
				resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
				if (resultcode && !CAPWAP_RESULTCODE_OK(resultcode->code)) {
					return 0;
				}

				break;
			}

			case CAPWAP_CONFIGURATION_STATUS_REQUEST: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_ACNAME) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_RADIOADMSTATE) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_STATISTICSTIMER) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPREBOOTSTAT)) {

					if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
						if (capwap_get_message_element(packet, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION)) {
							return 0;
						}
					} else {
						return 0;
					}
				}

				break;
			}

			case CAPWAP_CONFIGURATION_STATUS_RESPONSE: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_TIMERS) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_IDLETIMEOUT) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPFALLBACK) &&
					(capwap_get_message_element(packet, CAPWAP_ELEMENT_ACIPV4LIST) || capwap_get_message_element(packet, CAPWAP_ELEMENT_ACIPV6LIST))) {

					return 0;
				}

				/* Check if packet contains Result Code with Error Message */
				resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
				if (resultcode && !CAPWAP_RESULTCODE_OK(resultcode->code)) {
					return 0;
				}

				break;
			}

			case CAPWAP_CONFIGURATION_UPDATE_REQUEST: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_ACNAMEPRIORITY) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_ACTIMESTAMP) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_ADDMACACL) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_TIMERS) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_DELETEMACACL) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_IDLETIMEOUT) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_LOCATION) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_RADIOADMSTATE) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_STATISTICSTIMER) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPFALLBACK) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPNAME) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPSTATICIPADDRESS) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_IMAGEIDENTIFIER) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_VENDORPAYLOAD)) {

					return 0;
				}

				break;
			}

			case CAPWAP_CONFIGURATION_UPDATE_RESPONSE: {
				return 0;
			}

			case CAPWAP_WTP_EVENT_REQUEST: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_DUPLICATEIPV4) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_DUPLICATEIPV6) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPRADIOSTAT) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPREBOOTSTAT) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_DELETESTATION) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_VENDORPAYLOAD)) {

					return 0;
				}

				break;
			}

			case CAPWAP_WTP_EVENT_RESPONSE: {
				return 0;
			}

			case CAPWAP_CHANGE_STATE_EVENT_REQUEST: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_RADIOOPRSTATE) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_RESULTCODE)) {

					return 0;
				}

				break;
			}

			case CAPWAP_CHANGE_STATE_EVENT_RESPONSE: {
				return 0;
			}

			case CAPWAP_ECHO_REQUEST: {
				return 0;
			}

			case CAPWAP_ECHO_RESPONSE: {
				return 0;
			}

			case CAPWAP_IMAGE_DATA_REQUEST: {
				return 0;
			}

			case CAPWAP_IMAGE_DATA_RESPONSE: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_RESULTCODE)) {
					return 0;
				}

				break;
			}

			case CAPWAP_RESET_REQUEST: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_IMAGEIDENTIFIER)) {
					return 0;
				}

				break;
			}

			case CAPWAP_RESET_RESPONSE: {
				return 0;
			}

			case CAPWAP_PRIMARY_DISCOVERY_REQUEST: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_DISCOVERYTYPE) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPBOARDDATA) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPDESCRIPTOR) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPFRAMETUNNELMODE) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_WTPMACTYPE)) {

					if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
						if (capwap_get_message_element(packet, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION)) {
							return 0;
						}
					} else {
						return 0;
					}
				}

				break;
			}

			case CAPWAP_PRIMARY_DISCOVERY_RESPONSE: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_ACDESCRIPTION) &&
					capwap_get_message_element(packet, CAPWAP_ELEMENT_ACNAME) &&
					(capwap_get_message_element(packet, CAPWAP_ELEMENT_CONTROLIPV4) || capwap_get_message_element(packet, CAPWAP_ELEMENT_CONTROLIPV6))) {

					if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
						if (capwap_get_message_element(packet, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION)) {
							return 0;
						}
					} else {
						return 0;
					}
				}

				/* Check if packet contains Result Code with Error Message */
				resultcode = (struct capwap_resultcode_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_RESULTCODE);
				if (resultcode && !CAPWAP_RESULTCODE_OK(resultcode->code)) {
					return 0;
				}

				break;
			}

			case CAPWAP_DATA_TRANSFER_REQUEST: {
				/* TODO */
				break;
			}

			case CAPWAP_DATA_TRANSFER_RESPONSE: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_RESULTCODE)) {
					return 0;
				}

				break;
			}

			case CAPWAP_CLEAR_CONFIGURATION_REQUEST: {
				return 0;
			}

			case CAPWAP_CLEAR_CONFIGURATION_RESPONSE: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_RESULTCODE)) {
					return 0;
				}

				break;
			}

			case CAPWAP_STATION_CONFIGURATION_REQUEST: {
				/* TODO */
				break;
			}

			case CAPWAP_STATION_CONFIGURATION_RESPONSE: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_RESULTCODE)) {
					return 0;
				}

				break;
			}

			case CAPWAP_IEEE80211_WLAN_CONFIGURATION_REQUEST: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_80211_ADD_WLAN) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_80211_UPDATE_WLAN) ||
					capwap_get_message_element(packet, CAPWAP_ELEMENT_80211_DELETE_WLAN)) {

					return 0;
				}

				break;
			}

			case CAPWAP_IEEE80211_WLAN_CONFIGURATION_RESPONSE: {
				if (capwap_get_message_element(packet, CAPWAP_ELEMENT_RESULTCODE)) {
					return 0;
				}

				break;
			}
		}
	} else if (IS_FLAG_K_HEADER(packet->rxmngpacket->header)) {
		/* Keep alive data message require session id */
		if (capwap_get_message_element(packet, CAPWAP_ELEMENT_SESSIONID)) {
			return 0;
		}
	}

	return -1;
}

/* */
void capwap_free_parsed_packet(struct capwap_parsed_packet* packet) {
	int i;
	struct capwap_list_item* itemlist;
	struct capwap_message_element_itemlist* messageelement;
	struct capwap_message_elements_ops* msgops;

	ASSERT(packet != NULL);

	if (packet->rxmngpacket && packet->messages) {
		itemlist = packet->messages->first;
		while (itemlist) {
			messageelement = (struct capwap_message_element_itemlist*)itemlist->item;
			if (messageelement->data) {
				msgops = capwap_get_message_element_ops(messageelement->type);

				if (messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE) {
					msgops->free_message_element(messageelement->data);
				} else if (messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY) {
					struct capwap_array* arraymessageelement = (struct capwap_array*)messageelement->data;

					for (i = 0; i < arraymessageelement->count; i++) {
						msgops->free_message_element(*(void**)capwap_array_get_item_pointer(arraymessageelement, i));
					}

					/* */
					capwap_array_free(arraymessageelement);
				}
			}

			/* */
			itemlist = itemlist->next;
		}

		/* */
		packet->rxmngpacket = NULL;
		capwap_list_free(packet->messages);
		packet->messages = NULL;
	}

	/* */
	packet->connection = NULL;
}
