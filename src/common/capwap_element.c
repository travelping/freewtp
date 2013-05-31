#include "capwap.h"
#include "capwap_element.h"
#include "capwap_protocol.h"
#include "capwap_array.h"

/* Helper create parsed message element */
#define PARSING_MESSAGE_ELEMENT(data)																								\
	if (data) { return 1; }																											\
	data = read_ops->parsing_message_element((capwap_message_elements_handle)rxmngpacket, &rxmngpacket->read_ops);					\
	if (!data) { return 1; }

#define ARRAY_PARSING_MESSAGE_ELEMENT(data, type)																					\
	type msgelement;																												\
	if (!data) { data = capwap_array_create(sizeof(type), 0); }																		\
	msgelement = read_ops->parsing_message_element((capwap_message_elements_handle)rxmngpacket, &rxmngpacket->read_ops);			\
	if (!msgelement) { return 1; }																									\
	memcpy(capwap_array_get_item_pointer(data, data->count), &msgelement, sizeof(type));

/* Helper free parsed message element */
#define FREE_PARSED_MESSAGE_ELEMENT(type, data)																						\
	if (data) {																														\
		capwap_get_message_element_ops(type)->free_parsed_message_element(data);													\
		data = NULL;																												\
	}

#define FREE_ARRAY_PARSED_MESSAGE_ELEMENT(type, data)																				\
	if (data) {																														\
		unsigned long i;																											\
		for (i = 0; i < data->count; i++) {																							\
			capwap_get_message_element_ops(type)->free_parsed_message_element(*(void**)capwap_array_get_item_pointer(data, i));		\
		}																															\
		capwap_array_free(data);																									\
		data = NULL;																												\
	}

/* */
static struct capwap_message_elements_ops* capwap_message_elements[CAPWAP_MESSAGE_ELEMENTS_COUNT] = {
	/* CAPWAP_ELEMENT_ACDESCRIPTION */ &capwap_element_acdescriptor_ops,
	/* CAPWAP_ELEMENT_ACIPV4LIST */ &capwap_element_acipv4list_ops,
	/* CAPWAP_ELEMENT_ACIPV6LIST */ &capwap_element_acipv6list_ops,
	/* CAPWAP_ELEMENT_ACNAME */ &capwap_element_acname_ops,
	/* CAPWAP_ELEMENT_ACNAMEPRIORITY */ &capwap_element_acnamepriority_ops,
	/*  */ NULL,
	/*  */ NULL,
	/*  */ NULL,
	/* Reserved */ NULL,
	/* CAPWAP_ELEMENT_CONTROLIPV4 */ &capwap_element_controlipv4_ops,
	/* CAPWAP_ELEMENT_CONTROLIPV6 */ &capwap_element_controlipv6_ops,
	/* CAPWAP_ELEMENT_TIMERS */ &capwap_element_timers_ops,
	/*  */ NULL,
	/*  */ NULL,
	/*  */ NULL,
	/* CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD */ &capwap_element_decrypterrorreportperiod_ops,
	/*  */ NULL,
	/*  */ NULL,
	/* Reserved */ NULL,
	/* CAPWAP_ELEMENT_DISCOVERYTYPE */ &capwap_element_discoverytype_ops,
	/*  */ NULL,
	/*  */ NULL,
	/* CAPWAP_ELEMENT_IDLETIMEOUT */ &capwap_element_idletimeout_ops,
	/*  */ NULL,
	/* CAPWAP_ELEMENT_IMAGEIDENTIFIER */ &capwap_element_imageidentifier_ops,
	/*  */ NULL,
	/*  */ NULL,
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
	/*  */ NULL,	
	/* CAPWAP_ELEMENT_WTPREBOOTSTAT */ &capwap_element_wtprebootstat_ops,
	/* CAPWAP_ELEMENT_WTPSTATICIPADDRESS */ &capwap_element_wtpstaticipaddress_ops,
	/* CAPWAP_ELEMENT_LOCALIPV6 */ &capwap_element_localipv6_ops,
	/* CAPWAP_ELEMENT_TRANSPORT */ &capwap_element_transport_ops,
	/* CAPWAP_ELEMENT_MTUDISCOVERY */ &capwap_element_mtudiscovery_ops,
	/* CAPWAP_ELEMENT_ECNSUPPORT */ &capwap_element_ecnsupport_ops
};

/* */
static struct capwap_message_elements_ops* capwap_80211_message_elements[CAPWAP_MESSAGE_ELEMENTS_COUNT] = {
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
	/*  */ NULL,
	/*  */ NULL,
	/*  */ NULL,
	/*  */ NULL,
	/*  */ NULL,
	/* CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION */ &capwap_element_80211_wtpradioinformation_ops
};

/* */
struct capwap_message_elements_ops* capwap_get_message_element_ops(unsigned short code) {
	if ((code >= CAPWAP_MESSAGE_ELEMENTS_START) && (code <= CAPWAP_MESSAGE_ELEMENTS_STOP)) {
		return capwap_message_elements[code - CAPWAP_MESSAGE_ELEMENTS_START];
	} else if ((code >= CAPWAP_80211_MESSAGE_ELEMENTS_START) && (code <= CAPWAP_80211_MESSAGE_ELEMENTS_STOP)) {
		return capwap_80211_message_elements[code - CAPWAP_80211_MESSAGE_ELEMENTS_START];
	}
	
	return NULL;
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

	binding = GET_WBID_HEADER(packet->rxmngpacket->header);

	/* Position reader to capwap body */
	memcpy(&rxmngpacket->readpos, &rxmngpacket->readbodypos, sizeof(struct read_block_from_pos));

	if (rxmngpacket->isctrlpacket) {
		unsigned short bodylength = rxmngpacket->ctrlmsg.length - CAPWAP_CONTROL_MESSAGE_MIN_LENGTH;
		while (bodylength > 0) {
			uint16_t type;
			uint16_t msglength;
			struct capwap_message_elements_ops* read_ops;

			/* Get type and length */
			rxmngpacket->readerpacketallowed = sizeof(struct capwap_message_element);
			if (rxmngpacket->read_ops.read_u16((capwap_message_elements_handle)rxmngpacket, &type) != sizeof(uint16_t)) {
				/* TODO */
				return 1;
			}
			if (rxmngpacket->read_ops.read_u16((capwap_message_elements_handle)rxmngpacket, &msglength) != sizeof(uint16_t)) {
				/* TODO */
				return 1;
			}

			/* Check length */
			if (msglength > bodylength) {
				/* TODO */
				return 1;
			}

			/* */
			read_ops = capwap_get_message_element_ops(type);

			/* Allowed to parsing only the size of message element */
			rxmngpacket->readerpacketallowed = msglength;
			if (IS_MESSAGE_ELEMENTS(type) && read_ops) {
				/* Parsing standard message element */
				switch (type) {
					case CAPWAP_ELEMENT_ACDESCRIPTION: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.acdescriptor);
						break;
					}

					case CAPWAP_ELEMENT_ACIPV4LIST: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.acipv4list);
						break;
					}

					case CAPWAP_ELEMENT_ACIPV6LIST: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.acipv6list);
						break;
					}

					case CAPWAP_ELEMENT_ACNAME: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.acname);
						break;
					}

					case CAPWAP_ELEMENT_ACNAMEPRIORITY: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.acnamepriority, struct capwap_acnamepriority_element*);
						break;
					}

					case CAPWAP_ELEMENT_CONTROLIPV4: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.controlipv4, struct capwap_controlipv4_element*);
						break;
					}

					case CAPWAP_ELEMENT_CONTROLIPV6: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.controlipv6, struct capwap_controlipv6_element*);
						break;
					}

					case CAPWAP_ELEMENT_TIMERS: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.timers);
						break;
					}

					case CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.decrypterrorreportperiod, struct capwap_decrypterrorreportperiod_element*);
						break;
					}

					case CAPWAP_ELEMENT_DISCOVERYTYPE: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.discoverytype);
						break;
					}

					case CAPWAP_ELEMENT_IDLETIMEOUT: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.idletimeout);
						break;
					}

					case CAPWAP_ELEMENT_IMAGEIDENTIFIER: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.imageidentifier);
						break;
					}

					case CAPWAP_ELEMENT_LOCATION: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.location);
						break;
					}

					case CAPWAP_ELEMENT_MAXIMUMLENGTH: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.maximumlength);
						break;
					}

					case CAPWAP_ELEMENT_LOCALIPV4: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.localipv4);
						break;
					}

					case CAPWAP_ELEMENT_RADIOADMSTATE: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.radioadmstate, struct capwap_radioadmstate_element*);
						break;
					}

					case CAPWAP_ELEMENT_RADIOOPRSTATE: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.radiooprstate, struct capwap_radiooprstate_element*);
						break;
					}

					case CAPWAP_ELEMENT_RESULTCODE: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.resultcode);
						break;
					}

					case CAPWAP_ELEMENT_RETURNEDMESSAGE: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.returnedmessage, struct capwap_returnedmessage_element*);
						break;
					}

					case CAPWAP_ELEMENT_SESSIONID: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.sessionid);
						break;
					}

					case CAPWAP_ELEMENT_STATISTICSTIMER: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.statisticstimer);
						break;
					}

					case CAPWAP_ELEMENT_VENDORPAYLOAD: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.vendorpayload);
						break;
					}

					case CAPWAP_ELEMENT_WTPBOARDDATA: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.wtpboarddata);
						break;
					}

					case CAPWAP_ELEMENT_WTPDESCRIPTOR: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.wtpdescriptor);
						break;
					}

					case CAPWAP_ELEMENT_WTPFALLBACK: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.wtpfallback);
						break;
					}

					case CAPWAP_ELEMENT_WTPFRAMETUNNELMODE: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.wtpframetunnel);
						break;
					}

					case CAPWAP_ELEMENT_WTPMACTYPE: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.wtpmactype);
						break;
					}

					case CAPWAP_ELEMENT_WTPNAME: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.wtpname);
						break;
					}

					case CAPWAP_ELEMENT_WTPREBOOTSTAT: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.wtprebootstat);
						break;
					}

					case CAPWAP_ELEMENT_WTPSTATICIPADDRESS: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.wtpstaticipaddress);
						break;
					}

					case CAPWAP_ELEMENT_LOCALIPV6: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.localipv6);
						break;
					}

					case CAPWAP_ELEMENT_TRANSPORT: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.transport);
						break;
					}

					case CAPWAP_ELEMENT_MTUDISCOVERY: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.mtudiscovery);
						break;
					}

					case CAPWAP_ELEMENT_ECNSUPPORT: {
						PARSING_MESSAGE_ELEMENT(packet->messageelements.ecnsupport);
						break;
					}

					default: {
						/* TODO */
						return 1;
					}
				}
			} else if (IS_80211_MESSAGE_ELEMENTS(type) && read_ops) {
				if (binding != CAPWAP_WIRELESS_BINDING_IEEE80211) {
					/* TODO */
					return 1;
				}

				/* Parsing ieee80211 message element */
				switch (type) {
					case CAPWAP_ELEMENT_80211_ANTENNA: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.ieee80211.antenna, struct capwap_80211_antenna_element*);
						break;
					}

					case CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.ieee80211.directsequencecontrol, struct capwap_80211_directsequencecontrol_element*);
						break;
					}

					case CAPWAP_ELEMENT_80211_MACOPERATION: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.ieee80211.macoperation, struct capwap_80211_macoperation_element*);
						break;
					}

					case CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.ieee80211.multidomaincapability, struct capwap_80211_multidomaincapability_element*);
						break;
					}

					case CAPWAP_ELEMENT_80211_OFDMCONTROL: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.ieee80211.ofdmcontrol, struct capwap_80211_ofdmcontrol_element*);
						break;
					}

					case CAPWAP_ELEMENT_80211_RATESET: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.ieee80211.rateset, struct capwap_80211_rateset_element*);
						break;
					}

					case CAPWAP_ELEMENT_80211_SUPPORTEDRATES: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.ieee80211.supportedrates, struct capwap_80211_supportedrates_element*);
						break;
					}

					case CAPWAP_ELEMENT_80211_TXPOWER: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.ieee80211.txpower, struct capwap_80211_txpower_element*);
						break;
					}

					case CAPWAP_ELEMENT_80211_TXPOWERLEVEL: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.ieee80211.txpowerlevel, struct capwap_80211_txpowerlevel_element*);
						break;
					}

					case CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION: {
						ARRAY_PARSING_MESSAGE_ELEMENT(packet->messageelements.ieee80211.wtpradioinformation, struct capwap_80211_wtpradioinformation_element*);
						break;
					}

					default: {
						/* TODO */
						return 1;
					}
				}
			} else {
				/* TODO */
				return 1;
			}

			/* Check if read all data of message element */
			if (rxmngpacket->readerpacketallowed) {
				/* TODO */
				return 1;
			}

			/* */
			bodylength -= (msglength + sizeof(struct capwap_message_element));
		}
	} else if (IS_FLAG_K_HEADER(rxmngpacket->header)) {
		uint16_t type;
		uint16_t msglength;
		struct capwap_message_elements_ops* read_ops;
		unsigned short bodylength = rxmngpacket->datamsg.length - CAPWAP_DATA_MESSAGE_KEEPALIVE_MIN_LENGTH;

		/* Get type and length */
		rxmngpacket->readerpacketallowed = sizeof(struct capwap_message_element);
		rxmngpacket->read_ops.read_u16((capwap_message_elements_handle)rxmngpacket, &type);
		rxmngpacket->read_ops.read_u16((capwap_message_elements_handle)rxmngpacket, &msglength);

		/* Check length */
		if ((msglength + sizeof(struct capwap_message_element)) != bodylength) {
			/* TODO */
			return 1;
		}

		/* Allowed to parsing only the size of message element */
		rxmngpacket->readerpacketallowed = msglength;
		if (type != CAPWAP_ELEMENT_SESSIONID) {
			/* TODO */
			return 1;
		}

		/* Retrieve session id */
		read_ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_SESSIONID);
		packet->messageelements.sessionid = read_ops->parsing_message_element((capwap_message_elements_handle)rxmngpacket, &rxmngpacket->read_ops);
		if (!packet->messageelements.sessionid) {
			/* TODO */
			return 1; 
		}
	}

	return 0;
}

/* */
int capwap_validate_parsed_packet(struct capwap_parsed_packet* packet, struct capwap_array* returnedmessage) {
	unsigned short binding;

	ASSERT(packet != NULL);
	ASSERT(packet->rxmngpacket != NULL);

	binding = GET_WBID_HEADER(packet->rxmngpacket->header);

	if (packet->rxmngpacket->isctrlpacket) {
		switch (packet->rxmngpacket->ctrlmsg.type) {
			case CAPWAP_DISCOVERY_REQUEST: {
				if (packet->messageelements.discoverytype &&
					packet->messageelements.wtpboarddata &&
					packet->messageelements.wtpdescriptor &&
					packet->messageelements.wtpframetunnel &&
					packet->messageelements.wtpmactype) {

					if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
						if (packet->messageelements.ieee80211.wtpradioinformation) {
							return 0;
						}
					} else {
						return 0;
					}
				}

				break;
			}

			case CAPWAP_DISCOVERY_RESPONSE: {
				if (packet->messageelements.acdescriptor &&
					packet->messageelements.acname &&
					(packet->messageelements.controlipv4 || packet->messageelements.controlipv6)) {

					if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
						if (packet->messageelements.ieee80211.wtpradioinformation) {
							return 0;
						}
					} else {
						return 0;
					}
				}

				break;
			}

			case CAPWAP_JOIN_REQUEST: {
				if (packet->messageelements.location &&
					packet->messageelements.wtpboarddata &&
					packet->messageelements.wtpdescriptor &&
					packet->messageelements.wtpname &&
					packet->messageelements.sessionid &&
					packet->messageelements.wtpframetunnel &&
					packet->messageelements.wtpmactype &&
					packet->messageelements.ecnsupport &&
					(packet->messageelements.localipv4 || packet->messageelements.localipv6)) {

					if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
						if (packet->messageelements.ieee80211.wtpradioinformation) {
							return 0;
						}
					} else {
						return 0;
					}
				}

				break;
			}

			case CAPWAP_JOIN_RESPONSE: {
				if (packet->messageelements.resultcode &&
					packet->messageelements.acdescriptor &&
					packet->messageelements.acname &&
					packet->messageelements.ecnsupport &&
					(packet->messageelements.controlipv4 || packet->messageelements.controlipv6) &&
					(packet->messageelements.localipv4 || packet->messageelements.localipv6)) {

					if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
						if (packet->messageelements.ieee80211.wtpradioinformation) {
							return 0;
						}
					} else {
						return 0;
					}
				}

				break;
			}

			case CAPWAP_CONFIGURATION_STATUS_REQUEST: {
				if (packet->messageelements.acname &&
					packet->messageelements.radioadmstate &&
					packet->messageelements.statisticstimer &&
					packet->messageelements.wtprebootstat) {

					if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
						if (packet->messageelements.ieee80211.wtpradioinformation) {
							return 0;
						}
					} else {
						return 0;
					}
				}

				break;
			}

			case CAPWAP_CONFIGURATION_STATUS_RESPONSE: {
				if (packet->messageelements.timers &&
					packet->messageelements.decrypterrorreportperiod &&
					packet->messageelements.idletimeout &&
					packet->messageelements.wtpfallback &&
					(packet->messageelements.acipv4list || packet->messageelements.acipv6list)) {

					return 0;
				}

				break;
			}

			case CAPWAP_CONFIGURATION_UPDATE_REQUEST: {
				if (packet->messageelements.acnamepriority ||
					//packet->messageelements.actimestamp ||		TODO
					//packet->messageelements.addaclmac ||			TODO
					packet->messageelements.timers ||
					packet->messageelements.decrypterrorreportperiod ||
					//packet->messageelements.delaclmac ||			TODO
					packet->messageelements.idletimeout ||
					packet->messageelements.location ||
					packet->messageelements.radioadmstate ||
					packet->messageelements.statisticstimer ||
					packet->messageelements.wtpfallback ||
					packet->messageelements.wtpname ||
					packet->messageelements.wtpstaticipaddress ||
					packet->messageelements.imageidentifier ||
					packet->messageelements.vendorpayload) {

					return 0;
				}

				break;
			}

			case CAPWAP_CONFIGURATION_UPDATE_RESPONSE: {
				return 0;
			}

			case CAPWAP_WTP_EVENT_REQUEST: {
				if (packet->messageelements.decrypterrorreportperiod ||
					//packet->messageelements.duplicateipv4 ||				TODO
					//packet->messageelements.duplicateipv6 ||				TODO
					//packet->messageelements.wtpradiostat ||				TODO
					packet->messageelements.wtprebootstat ||
					//packet->messageelements.deletestation ||				TODO
					packet->messageelements.vendorpayload) {

					return 0;
				}

				break;
			}

			case CAPWAP_WTP_EVENT_RESPONSE: {
				return 0;
			}

			case CAPWAP_CHANGE_STATE_EVENT_REQUEST: {
				if (packet->messageelements.radiooprstate &&
					packet->messageelements.resultcode) {

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
				if (packet->messageelements.resultcode) {
					return 0;
				}

				break;
			}

			case CAPWAP_RESET_REQUEST: {
				if (packet->messageelements.imageidentifier) {
					return 0;
				}

				break;
			}

			case CAPWAP_RESET_RESPONSE: {
				return 0;
			}

			case CAPWAP_PRIMARY_DISCOVERY_REQUEST: {
				if (packet->messageelements.discoverytype &&
					packet->messageelements.wtpboarddata &&
					packet->messageelements.wtpdescriptor &&
					packet->messageelements.wtpframetunnel &&
					packet->messageelements.wtpmactype) {

					if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
						if (packet->messageelements.ieee80211.wtpradioinformation) {
							return 0;
						}
					} else {
						return 0;
					}
				}

				break;
			}

			case CAPWAP_PRIMARY_DISCOVERY_RESPONSE: {
				if (packet->messageelements.acdescriptor &&
					packet->messageelements.acname &&
					(packet->messageelements.controlipv4 || packet->messageelements.controlipv6)) {

					if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
						if (packet->messageelements.ieee80211.wtpradioinformation) {
							return 0;
						}
					} else {
						return 0;
					}
				}

				break;
			}

			case CAPWAP_DATA_TRANSFER_REQUEST: {
				/* TODO */
				break;
			}

			case CAPWAP_DATA_TRANSFER_RESPONSE: {
				if (packet->messageelements.resultcode) {
					return 0;
				}

				break;
			}

			case CAPWAP_CLEAR_CONFIGURATION_REQUEST: {
				return 0;
			}

			case CAPWAP_CLEAR_CONFIGURATION_RESPONSE: {
				if (packet->messageelements.resultcode) {
					return 0;
				}

				break;
			}

			case CAPWAP_STATION_CONFIGURATION_REQUEST: {
				/* TODO */
				break;
			}

			case CAPWAP_STATION_CONFIGURATION_RESPONSE: {
				if (packet->messageelements.resultcode) {
					return 0;
				}

				break;
			}
		}
	} else if (IS_FLAG_K_HEADER(packet->rxmngpacket->header)) {
		/* Keep alive data message require session id */
		if (packet->messageelements.sessionid) {
			return 0;
		}
	}

	return 1;
}

/* */
void capwap_free_parsed_packet(struct capwap_parsed_packet* packet) {
	ASSERT(packet != NULL);

	if (packet->rxmngpacket) {
		unsigned short binding = GET_WBID_HEADER(packet->rxmngpacket->header);

		/* */
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_ACDESCRIPTION, packet->messageelements.acdescriptor);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_ACIPV4LIST, packet->messageelements.acipv4list);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_ACIPV6LIST, packet->messageelements.acipv6list);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_ACNAME, packet->messageelements.acname);
		FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_ACNAMEPRIORITY, packet->messageelements.acnamepriority);
		FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_CONTROLIPV4, packet->messageelements.controlipv4);
		FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_CONTROLIPV6, packet->messageelements.controlipv6);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_TIMERS, packet->messageelements.timers);
		FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD, packet->messageelements.decrypterrorreportperiod);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_DISCOVERYTYPE, packet->messageelements.discoverytype);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_IDLETIMEOUT, packet->messageelements.idletimeout);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_IMAGEIDENTIFIER, packet->messageelements.imageidentifier);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_LOCATION, packet->messageelements.location);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_MAXIMUMLENGTH, packet->messageelements.maximumlength);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_LOCALIPV4, packet->messageelements.localipv4);
		FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_RADIOADMSTATE, packet->messageelements.radioadmstate);
		FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_RADIOOPRSTATE, packet->messageelements.radiooprstate);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_RESULTCODE, packet->messageelements.resultcode);
		FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_RETURNEDMESSAGE, packet->messageelements.returnedmessage);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_SESSIONID, packet->messageelements.sessionid);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_STATISTICSTIMER, packet->messageelements.statisticstimer);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_VENDORPAYLOAD, packet->messageelements.vendorpayload);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_WTPBOARDDATA, packet->messageelements.wtpboarddata);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_WTPDESCRIPTOR, packet->messageelements.wtpdescriptor);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_WTPFALLBACK, packet->messageelements.wtpfallback);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_WTPFRAMETUNNELMODE, packet->messageelements.wtpframetunnel);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_WTPMACTYPE, packet->messageelements.wtpmactype);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_WTPNAME, packet->messageelements.wtpname);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_WTPREBOOTSTAT, packet->messageelements.wtprebootstat);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_WTPSTATICIPADDRESS, packet->messageelements.wtpstaticipaddress);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_LOCALIPV6, packet->messageelements.localipv6);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_TRANSPORT, packet->messageelements.transport);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_MTUDISCOVERY, packet->messageelements.mtudiscovery);
		FREE_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_ECNSUPPORT, packet->messageelements.ecnsupport);

		if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
			FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_80211_ANTENNA, packet->messageelements.ieee80211.antenna);
			FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL, packet->messageelements.ieee80211.directsequencecontrol);
			FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_80211_MACOPERATION, packet->messageelements.ieee80211.macoperation);
			FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY, packet->messageelements.ieee80211.multidomaincapability);
			FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_80211_OFDMCONTROL, packet->messageelements.ieee80211.ofdmcontrol);
			FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_80211_RATESET, packet->messageelements.ieee80211.rateset);
			FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_80211_SUPPORTEDRATES, packet->messageelements.ieee80211.supportedrates);
			FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_80211_TXPOWER, packet->messageelements.ieee80211.txpower);
			FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_80211_TXPOWERLEVEL, packet->messageelements.ieee80211.txpowerlevel);
			FREE_ARRAY_PARSED_MESSAGE_ELEMENT(CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION, packet->messageelements.ieee80211.wtpradioinformation);
		}

		/* */
		packet->rxmngpacket = NULL;
	}

	/* */
	packet->connection = NULL;
}
