#include "capwap.h"
#include "capwap_element.h"
#include "capwap_protocol.h"
#include "capwap_array.h"

/* */
#define element_ops(Id, Ops) [(Id) - CAPWAP_MESSAGE_ELEMENTS_START] = &(Ops)
static const struct capwap_message_elements_ops * capwap_message_elements[] = {
	element_ops(CAPWAP_ELEMENT_ACDESCRIPTION_TYPE,			capwap_element_acdescriptor_ops),
	element_ops(CAPWAP_ELEMENT_ACIPV4LIST_TYPE,			capwap_element_acipv4list_ops),
	element_ops(CAPWAP_ELEMENT_ACIPV6LIST_TYPE,			capwap_element_acipv6list_ops),
	element_ops(CAPWAP_ELEMENT_ACNAME_TYPE,				capwap_element_acname_ops),
	element_ops(CAPWAP_ELEMENT_ACNAMEPRIORITY_TYPE,			capwap_element_acnamepriority_ops),
	element_ops(CAPWAP_ELEMENT_ACTIMESTAMP_TYPE,			capwap_element_actimestamp_ops),
	element_ops(CAPWAP_ELEMENT_ADDMACACL_TYPE,			capwap_element_addmacacl_ops),
	element_ops(CAPWAP_ELEMENT_ADDSTATION_TYPE,			capwap_element_addstation_ops),
	element_ops(CAPWAP_ELEMENT_CONTROLIPV4_TYPE,			capwap_element_controlipv4_ops),
	element_ops(CAPWAP_ELEMENT_CONTROLIPV6_TYPE,			capwap_element_controlipv6_ops),
	element_ops(CAPWAP_ELEMENT_TIMERS_TYPE,				capwap_element_timers_ops),
	element_ops(CAPWAP_ELEMENT_DATATRANSFERDATA_TYPE,		capwap_element_datatransferdata_ops),
	element_ops(CAPWAP_ELEMENT_DATATRANSFERMODE_TYPE,		capwap_element_datatransfermode_ops),
	element_ops(CAPWAP_ELEMENT_DECRYPTERRORREPORT_TYPE,		capwap_element_decrypterrorreport_ops),
	element_ops(CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD_TYPE,	capwap_element_decrypterrorreportperiod_ops),
	element_ops(CAPWAP_ELEMENT_DELETEMACACL_TYPE,			capwap_element_deletemacacl_ops),
	element_ops(CAPWAP_ELEMENT_DELETESTATION_TYPE,			capwap_element_deletestation_ops),
	element_ops(CAPWAP_ELEMENT_DISCOVERYTYPE_TYPE,			capwap_element_discoverytype_ops),
	element_ops(CAPWAP_ELEMENT_DUPLICATEIPV4_TYPE,			capwap_element_duplicateipv4_ops),
	element_ops(CAPWAP_ELEMENT_DUPLICATEIPV6_TYPE,			capwap_element_duplicateipv6_ops),
	element_ops(CAPWAP_ELEMENT_IDLETIMEOUT_TYPE,			capwap_element_idletimeout_ops),
	element_ops(CAPWAP_ELEMENT_IMAGEDATA_TYPE,			capwap_element_imagedata_ops),
	element_ops(CAPWAP_ELEMENT_IMAGEIDENTIFIER_TYPE,		capwap_element_imageidentifier_ops),
	element_ops(CAPWAP_ELEMENT_IMAGEINFO_TYPE,			capwap_element_imageinfo_ops),
	element_ops(CAPWAP_ELEMENT_INITIATEDOWNLOAD_TYPE,		capwap_element_initdownload_ops),
	element_ops(CAPWAP_ELEMENT_LOCATION_TYPE,			capwap_element_location_ops),
	element_ops(CAPWAP_ELEMENT_MAXIMUMLENGTH_TYPE,			capwap_element_maximumlength_ops),
	element_ops(CAPWAP_ELEMENT_LOCALIPV4_TYPE,			capwap_element_localipv4_ops),
	element_ops(CAPWAP_ELEMENT_RADIOADMSTATE_TYPE,			capwap_element_radioadmstate_ops),
	element_ops(CAPWAP_ELEMENT_RADIOOPRSTATE_TYPE,			capwap_element_radiooprstate_ops),
	element_ops(CAPWAP_ELEMENT_RESULTCODE_TYPE,			capwap_element_resultcode_ops),
	element_ops(CAPWAP_ELEMENT_RETURNEDMESSAGE_TYPE,		capwap_element_returnedmessage_ops),
	element_ops(CAPWAP_ELEMENT_SESSIONID_TYPE,			capwap_element_sessionid_ops),
	element_ops(CAPWAP_ELEMENT_STATISTICSTIMER_TYPE,		capwap_element_statisticstimer_ops),
	element_ops(CAPWAP_ELEMENT_VENDORPAYLOAD_TYPE,			capwap_element_vendorpayload_ops),
	element_ops(CAPWAP_ELEMENT_WTPBOARDDATA_TYPE,			capwap_element_wtpboarddata_ops),
	element_ops(CAPWAP_ELEMENT_WTPDESCRIPTOR_TYPE,			capwap_element_wtpdescriptor_ops),
	element_ops(CAPWAP_ELEMENT_WTPFALLBACK_TYPE,			capwap_element_wtpfallback_ops),
	element_ops(CAPWAP_ELEMENT_WTPFRAMETUNNELMODE_TYPE,		capwap_element_wtpframetunnelmode_ops),
	element_ops(CAPWAP_ELEMENT_WTPMACTYPE_TYPE,			capwap_element_wtpmactype_ops),
	element_ops(CAPWAP_ELEMENT_WTPNAME_TYPE,			capwap_element_wtpname_ops),
	element_ops(CAPWAP_ELEMENT_WTPRADIOSTAT_TYPE,			capwap_element_wtpradiostat_ops),
	element_ops(CAPWAP_ELEMENT_WTPREBOOTSTAT_TYPE,			capwap_element_wtprebootstat_ops),
	element_ops(CAPWAP_ELEMENT_WTPSTATICIPADDRESS_TYPE,		capwap_element_wtpstaticipaddress_ops),
	element_ops(CAPWAP_ELEMENT_LOCALIPV6_TYPE,			capwap_element_localipv6_ops),
	element_ops(CAPWAP_ELEMENT_TRANSPORT_TYPE,			capwap_element_transport_ops),
	element_ops(CAPWAP_ELEMENT_MTUDISCOVERY_TYPE,			capwap_element_mtudiscovery_ops),
	element_ops(CAPWAP_ELEMENT_ECNSUPPORT_TYPE,			capwap_element_ecnsupport_ops)
};
#undef element_ops

/* */
#define element_ops(Id, Ops) [(Id) - CAPWAP_80211_MESSAGE_ELEMENTS_START] = &(Ops)
static const struct capwap_message_elements_ops * capwap_80211_message_elements[] = {
	element_ops(CAPWAP_ELEMENT_80211_ADD_WLAN_TYPE,				capwap_element_80211_addwlan_ops),
	element_ops(CAPWAP_ELEMENT_80211_ANTENNA_TYPE,				capwap_element_80211_antenna_ops),
	element_ops(CAPWAP_ELEMENT_80211_ASSIGN_BSSID_TYPE,			capwap_element_80211_assignbssid_ops),
	element_ops(CAPWAP_ELEMENT_80211_DELETE_WLAN_TYPE,			capwap_element_80211_deletewlan_ops),
	element_ops(CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL_TYPE,		capwap_element_80211_directsequencecontrol_ops),
	element_ops(CAPWAP_ELEMENT_80211_IE_TYPE,				capwap_element_80211_ie_ops),
	element_ops(CAPWAP_ELEMENT_80211_MACOPERATION_TYPE,			capwap_element_80211_macoperation_ops),
	element_ops(CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES_TYPE,		capwap_element_80211_miccountermeasures_ops),
	element_ops(CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY_TYPE,		capwap_element_80211_multidomaincapability_ops),
	element_ops(CAPWAP_ELEMENT_80211_OFDMCONTROL_TYPE,			capwap_element_80211_ofdmcontrol_ops),
	element_ops(CAPWAP_ELEMENT_80211_RATESET_TYPE,				capwap_element_80211_rateset_ops),
	element_ops(CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT_TYPE,		capwap_element_80211_rsnaerrorreport_ops),
	element_ops(CAPWAP_ELEMENT_80211_STATION_TYPE,				capwap_element_80211_station_ops),
	element_ops(CAPWAP_ELEMENT_80211_STATION_QOS_PROFILE_TYPE,		capwap_element_80211_stationqos_ops),
	element_ops(CAPWAP_ELEMENT_80211_STATION_SESSION_KEY_PROFILE_TYPE,	capwap_element_80211_stationkey_ops),
	element_ops(CAPWAP_ELEMENT_80211_STATISTICS_TYPE,			capwap_element_80211_statistics_ops),
	element_ops(CAPWAP_ELEMENT_80211_SUPPORTEDRATES_TYPE,			capwap_element_80211_supportedrates_ops),
	element_ops(CAPWAP_ELEMENT_80211_TXPOWER_TYPE,				capwap_element_80211_txpower_ops),
	element_ops(CAPWAP_ELEMENT_80211_TXPOWERLEVEL_TYPE,			capwap_element_80211_txpowerlevel_ops),
	element_ops(CAPWAP_ELEMENT_80211_UPDATE_STATION_QOS_TYPE,		capwap_element_80211_updatestationqos_ops),
	element_ops(CAPWAP_ELEMENT_80211_UPDATE_WLAN_TYPE,			capwap_element_80211_updatewlan_ops),
	element_ops(CAPWAP_ELEMENT_80211_WTP_QOS_TYPE,				capwap_element_80211_wtpqos_ops),
	element_ops(CAPWAP_ELEMENT_80211_WTP_RADIO_CONF_TYPE,			capwap_element_80211_wtpradioconf_ops),
	element_ops(CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM_TYPE,		capwap_element_80211_wtpradiofailalarm_ops),
	element_ops(CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION_TYPE,		capwap_element_80211_wtpradioinformation_ops)
};
#undef element_ops

/* */
#define element_ops(Id, Ops) [(Id) - 1] = &(Ops)
static const struct capwap_message_elements_ops * capwap_vendor_travelping_message_elements[] = {
	element_ops(CAPWAP_ELEMENT_80211N_RADIO_CONF_TYPE,	capwap_element_80211n_radioconf_ops),
	element_ops(CAPWAP_ELEMENT_80211N_STATION_INFO_TYPE,	capwap_element_80211n_station_info_ops)
};
#undef element_ops

/* */
const struct capwap_message_elements_ops *
capwap_get_message_element_ops(const struct capwap_message_element_id id)
{
#define ARRAY_SIZE(x)  (sizeof((x)) / sizeof((x)[0]))

	switch (id.vendor) {
	case 0:
		if (id.type >= CAPWAP_MESSAGE_ELEMENTS_START &&
		    id.type - CAPWAP_MESSAGE_ELEMENTS_START < ARRAY_SIZE(capwap_message_elements)) {
			return capwap_message_elements[id.type - CAPWAP_MESSAGE_ELEMENTS_START];
		}
		else if (id.type >= CAPWAP_80211_MESSAGE_ELEMENTS_START &&
			 id.type - CAPWAP_80211_MESSAGE_ELEMENTS_START < ARRAY_SIZE(capwap_80211_message_elements)) {
			return capwap_80211_message_elements[id.type - CAPWAP_80211_MESSAGE_ELEMENTS_START];
		}
		break;

	case CAPWAP_VENDOR_TRAVELPING_ID:
		if (id.type >= 1 &&
		    id.type - 1 < ARRAY_SIZE(capwap_vendor_travelping_message_elements))
			return capwap_vendor_travelping_message_elements[id.type - 1];
		break;
	}

	return NULL;
#undef ARRAY_SIZE
}

/* */
struct capwap_list_item* capwap_get_message_element(struct capwap_parsed_packet* packet,
						    const struct capwap_message_element_id id)
{
	struct capwap_list_item* search;

	ASSERT(packet != NULL);
	ASSERT(packet->messages != NULL);

	search = packet->messages->first;
	while (search) {
		struct capwap_message_element_itemlist* messageelement =
			(struct capwap_message_element_itemlist*)search->item;

		if (memcmp(&messageelement->id, &id, sizeof(id)) == 0)
			return search;

		/* */
		search = search->next;
	}

	return NULL;
}

/* */
void* capwap_get_message_element_data(struct capwap_parsed_packet* packet,
				      const struct capwap_message_element_id id)
{
	struct capwap_list_item* itemlist;
	struct capwap_message_element_itemlist* messageelement;

	/* Retrieve item list */
	itemlist = capwap_get_message_element(packet, id);
	if (!itemlist) {
		return NULL;
	}

	/* Get message element info */
	messageelement = (struct capwap_message_element_itemlist*)itemlist->item;
	ASSERT(messageelement != NULL);

	return messageelement->data;
}

/* */
int capwap_parsing_packet(struct capwap_packet_rxmng* rxmngpacket, struct capwap_parsed_packet* packet) {
	unsigned short binding;
	unsigned short bodylength;

	ASSERT(rxmngpacket != NULL);
	ASSERT(packet != NULL);

	/* */
	memset(packet, 0, sizeof(struct capwap_parsed_packet));
	packet->rxmngpacket = rxmngpacket;
	packet->messages = capwap_list_create();

	binding = GET_WBID_HEADER(packet->rxmngpacket->header);

	/* Position reader to capwap body */
	memcpy(&rxmngpacket->readpos, &rxmngpacket->readbodypos, sizeof(struct read_block_from_pos));

	/* */
	bodylength = rxmngpacket->ctrlmsg.length - CAPWAP_CONTROL_MESSAGE_MIN_LENGTH;
	while (bodylength > 0) {
		struct capwap_message_element_id id = { .vendor = 0 };
		uint16_t msglength;
		struct capwap_list_item* itemlist;
		struct capwap_message_element_itemlist* messageelement;
		void *element;
		const struct capwap_message_elements_ops* read_ops;

		/* Get type and length */
		rxmngpacket->readerpacketallowed = sizeof(struct capwap_message_element);
		if (rxmngpacket->read_ops.read_u16((capwap_message_elements_handle)rxmngpacket, &id.type) != sizeof(uint16_t) ||
		    rxmngpacket->read_ops.read_u16((capwap_message_elements_handle)rxmngpacket, &msglength) != sizeof(uint16_t) ||
		    msglength > bodylength)
			return INVALID_MESSAGE_ELEMENT;

		/* Allowed to parsing only the size of message element */
		rxmngpacket->readerpacketallowed = msglength;

		/* Check binding */
		if (IS_80211_MESSAGE_ELEMENTS(id) &&
		    (binding != CAPWAP_WIRELESS_BINDING_IEEE80211))
			return UNRECOGNIZED_MESSAGE_ELEMENT;

		capwap_logging_debug("MESSAGE ELEMENT: %d", id.type);

		if (id.type == CAPWAP_ELEMENT_VENDORPAYLOAD_TYPE) {
			struct capwap_message_element_id vendor_id;

			if (msglength < 7) {
				capwap_logging_debug("Invalid Vendor Specific Payload element: underbuffer");
				return INVALID_MESSAGE_ELEMENT;
			}
			if ((msglength - 6) > CAPWAP_VENDORPAYLOAD_MAXLENGTH) {
				capwap_logging_debug("Invalid Vendor Specific Payload element: overbuffer");
				return INVALID_MESSAGE_ELEMENT;
			}

			rxmngpacket->read_ops.read_u32((capwap_message_elements_handle)rxmngpacket, &vendor_id.vendor);
			rxmngpacket->read_ops.read_u16((capwap_message_elements_handle)rxmngpacket, &vendor_id.type);

			capwap_logging_debug("VENDOR MESSAGE ELEMENT: %06x:%d", id.vendor, id.type);

			read_ops = capwap_get_message_element_ops(vendor_id);
			capwap_logging_debug("vendor read_ops: %p", read_ops);
			if (read_ops) {
				id = vendor_id;
				element = read_ops->parse((capwap_message_elements_handle)rxmngpacket, &rxmngpacket->read_ops);
			} else {
				read_ops = capwap_get_message_element_ops(id);
				element = capwap_unknown_vendorpayload_element_parsing((capwap_message_elements_handle)rxmngpacket,
										       &rxmngpacket->read_ops, msglength - 6, vendor_id);
			}
		} else {
			/* Reader function */
			read_ops = capwap_get_message_element_ops(id);
			capwap_logging_debug("read_ops: %p", read_ops);

			if (!read_ops)
				return UNRECOGNIZED_MESSAGE_ELEMENT;

			/* Get message element */
			element = read_ops->parse((capwap_message_elements_handle)rxmngpacket, &rxmngpacket->read_ops);
		}

		if (!element)
			return INVALID_MESSAGE_ELEMENT;

		/* */
		itemlist = capwap_get_message_element(packet, id);
		if (read_ops->category == CAPWAP_MESSAGE_ELEMENT_SINGLE) {
			/* Check for multiple message element */
			if (itemlist) {
				return INVALID_MESSAGE_ELEMENT;
			}

			/* Create new message element */
			itemlist = capwap_itemlist_create(sizeof(struct capwap_message_element_itemlist));
			messageelement = (struct capwap_message_element_itemlist*)itemlist->item;
			messageelement->id = id;
			messageelement->category = CAPWAP_MESSAGE_ELEMENT_SINGLE;
			messageelement->data = element;

			/* */
			capwap_itemlist_insert_after(packet->messages, NULL, itemlist);
		}
		else if (read_ops->category == CAPWAP_MESSAGE_ELEMENT_ARRAY) {
			struct capwap_array* arraymessageelement;

			if (itemlist) {
				messageelement = (struct capwap_message_element_itemlist*)itemlist->item;
				arraymessageelement = (struct capwap_array*)messageelement->data;
			} else {
				arraymessageelement = capwap_array_create(sizeof(void*), 0, 0);

				/* */
				itemlist = capwap_itemlist_create(sizeof(struct capwap_message_element_itemlist));
				messageelement = (struct capwap_message_element_itemlist*)itemlist->item;
				messageelement->id = id;
				messageelement->category = CAPWAP_MESSAGE_ELEMENT_ARRAY;
				messageelement->data = (void*)arraymessageelement;

				/* */
				capwap_itemlist_insert_after(packet->messages, NULL, itemlist);
			}

			/* */
			*(void **)capwap_array_get_item_pointer(arraymessageelement, arraymessageelement->count) = element;
		}

		/* Check if read all data of message element */
		if (rxmngpacket->readerpacketallowed) {
			return INVALID_MESSAGE_ELEMENT;
		}

		/* */
		bodylength -= (msglength + sizeof(struct capwap_message_element));
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
				return 0;
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
				return 0;
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
				return 0;
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
			if (capwap_get_message_element(packet, CAPWAP_ELEMENT_ADDSTATION)) {
				if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
					if (capwap_get_message_element(packet, CAPWAP_ELEMENT_80211_STATION)) {
						return 0;
					}
				} else {
					return 0;
				}
			} else if (capwap_get_message_element(packet, CAPWAP_ELEMENT_DELETESTATION)) {
				return 0;
			}

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

	return -1;
}

/* */
void capwap_free_parsed_packet(struct capwap_parsed_packet* packet) {
	int i;
	struct capwap_list_item* itemlist;
	struct capwap_message_element_itemlist* messageelement;
	const struct capwap_message_elements_ops* msgops;

	ASSERT(packet != NULL);

	if (packet->rxmngpacket && packet->messages) {
		itemlist = packet->messages->first;
		while (itemlist) {
			messageelement = (struct capwap_message_element_itemlist*)itemlist->item;
			if (messageelement->data) {
				msgops = capwap_get_message_element_ops(messageelement->id);

				if (messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE) {
					msgops->free(messageelement->data);
				} else if (messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY) {
					struct capwap_array* arraymessageelement = (struct capwap_array*)messageelement->data;

					for (i = 0; i < arraymessageelement->count; i++) {
						msgops->free(*(void**)capwap_array_get_item_pointer(arraymessageelement, i));
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
}
