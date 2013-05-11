#include "capwap.h"
#include "capwap_element.h"
#include "capwap_protocol.h"
#include "capwap_array.h"

static struct capwap_message_elements_func standard_message_elements[CAPWAP_MESSAGE_ELEMENTS_COUNT] = {
	/* CAPWAP_ELEMENT_ACDESCRIPTION */ { capwap_acdescriptor_element_create, capwap_acdescriptor_element_validate, capwap_acdescriptor_element_parsing, capwap_acdescriptor_element_free },
	/* CAPWAP_ELEMENT_ACIPV4LIST */ { capwap_acipv4list_element_create, capwap_acipv4list_element_validate, capwap_acipv4list_element_parsing, capwap_acipv4list_element_free },
	/* CAPWAP_ELEMENT_ACIPV6LIST */ { capwap_acipv6list_element_create, capwap_acipv6list_element_validate, capwap_acipv6list_element_parsing, capwap_acipv6list_element_free },
	/* CAPWAP_ELEMENT_ACNAME */ { capwap_acname_element_create, capwap_acname_element_validate, capwap_acname_element_parsing, capwap_acname_element_free },
	/* CAPWAP_ELEMENT_ACNAMEPRIORITY */ { capwap_acnamepriority_element_create, capwap_acnamepriority_element_validate, capwap_acnamepriority_element_parsing, capwap_acnamepriority_element_free },
	/*  */ { NULL, NULL },
	/*  */ { NULL, NULL },
	/*  */ { NULL, NULL },
	/* Reserved */ { NULL, NULL },
	/* CAPWAP_ELEMENT_CONTROLIPV4 */ { capwap_controlipv4_element_create, capwap_controlipv4_element_validate, capwap_controlipv4_element_parsing, capwap_controlipv4_element_free },
	/* CAPWAP_ELEMENT_CONTROLIPV6 */ { capwap_controlipv6_element_create, capwap_controlipv6_element_validate, capwap_controlipv6_element_parsing, capwap_controlipv6_element_free },
	/* CAPWAP_ELEMENT_TIMERS */ { capwap_timers_element_create, capwap_timers_element_validate, capwap_timers_element_parsing, capwap_timers_element_free },
	/*  */ { NULL, NULL },
	/*  */ { NULL, NULL },
	/*  */ { NULL, NULL },
	/* CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD */ { capwap_decrypterrorreportperiod_element_create, capwap_decrypterrorreportperiod_element_validate, capwap_decrypterrorreportperiod_element_parsing, capwap_decrypterrorreportperiod_element_free },
	/*  */ { NULL, NULL },
	/*  */ { NULL, NULL },
	/* Reserved */ { NULL, NULL },
	/* CAPWAP_ELEMENT_DISCOVERYTYPE */ { capwap_discoverytype_element_create, capwap_discoverytype_element_validate, capwap_discoverytype_element_parsing, capwap_discoverytype_element_free },
	/*  */ { NULL, NULL },	
	/*  */ { NULL, NULL },	
	/* CAPWAP_ELEMENT_IDLETIMEOUT */ { capwap_idletimeout_element_create, capwap_idletimeout_element_validate, capwap_idletimeout_element_parsing, capwap_idletimeout_element_free },	
	/*  */ { NULL, NULL },	
	/* CAPWAP_ELEMENT_IMAGEIDENTIFIER */ { capwap_imageidentifier_element_create, capwap_imageidentifier_element_validate, capwap_imageidentifier_element_parsing, capwap_imageidentifier_element_free },	
	/*  */ { NULL, NULL },	
	/*  */ { NULL, NULL },	
	/* CAPWAP_ELEMENT_LOCATION */ { capwap_location_element_create, capwap_location_element_validate, capwap_location_element_parsing, capwap_location_element_free },	
	/* CAPWAP_ELEMENT_MAXIMUMLENGTH */ { capwap_maximumlength_element_create, capwap_maximumlength_element_validate, capwap_maximumlength_element_parsing, capwap_maximumlength_element_free },	
	/* CAPWAP_ELEMENT_LOCALIPV4 */ { capwap_localipv4_element_create, capwap_localipv4_element_validate, capwap_localipv4_element_parsing, capwap_localipv4_element_free },	
	/* CAPWAP_ELEMENT_RADIOADMSTATE */ { capwap_radioadmstate_element_create, capwap_radioadmstate_element_validate, capwap_radioadmstate_element_parsing, capwap_radioadmstate_element_free },	
	/* CAPWAP_ELEMENT_RADIOOPRSTATE */ { capwap_radiooprstate_element_create, capwap_radiooprstate_element_validate, capwap_radiooprstate_element_parsing, capwap_radiooprstate_element_free },	
	/* CAPWAP_ELEMENT_RESULTCODE */ { capwap_resultcode_element_create, capwap_resultcode_element_validate, capwap_resultcode_element_parsing, capwap_resultcode_element_free },
	/* CAPWAP_ELEMENT_RETURNEDMESSAGE */ { capwap_returnedmessage_element_create, capwap_returnedmessage_element_validate, capwap_returnedmessage_element_parsing, capwap_returnedmessage_element_free },
	/* CAPWAP_ELEMENT_SESSIONID */ { capwap_sessionid_element_create, capwap_sessionid_element_validate, capwap_sessionid_element_parsing, capwap_sessionid_element_free },	
	/* CAPWAP_ELEMENT_STATISTICSTIMER */ { capwap_statisticstimer_element_create, capwap_statisticstimer_element_validate, capwap_statisticstimer_element_parsing, capwap_statisticstimer_element_free },	
	/* CAPWAP_ELEMENT_VENDORPAYLOAD */ { capwap_vendorpayload_element_create, capwap_vendorpayload_element_validate, capwap_vendorpayload_element_parsing, capwap_vendorpayload_element_free },	
	/* CAPWAP_ELEMENT_WTPBOARDDATA */ { capwap_wtpboarddata_element_create, capwap_wtpboarddata_element_validate, capwap_wtpboarddata_element_parsing, capwap_wtpboarddata_element_free },
	/* CAPWAP_ELEMENT_WTPDESCRIPTOR */ { capwap_wtpdescriptor_element_create, capwap_wtpdescriptor_element_validate, capwap_wtpdescriptor_element_parsing, capwap_wtpdescriptor_element_free },
	/* CAPWAP_ELEMENT_WTPFALLBACK */ { capwap_wtpfallback_element_create, capwap_wtpfallback_element_validate, capwap_wtpfallback_element_parsing, capwap_wtpfallback_element_free },	
	/* CAPWAP_ELEMENT_WTPFRAMETUNNELMODE */ { capwap_wtpframetunnelmode_element_create, capwap_wtpframetunnelmode_element_validate, capwap_wtpframetunnelmode_element_parsing, capwap_wtpframetunnelmode_element_free },
	/* Reserved */ { NULL, NULL },	
	/* Reserved */ { NULL, NULL },	
	/* CAPWAP_ELEMENT_WTPMACTYPE */ { capwap_wtpmactype_element_create, capwap_wtpmactype_element_validate, capwap_wtpmactype_element_parsing, capwap_wtpmactype_element_free },
	/* CAPWAP_ELEMENT_WTPNAME */ { capwap_wtpname_element_create, capwap_wtpname_element_validate, capwap_wtpname_element_parsing, capwap_wtpname_element_free },
	/* Reserved */ { NULL, NULL },	
	/*  */ { NULL, NULL },	
	/* CAPWAP_ELEMENT_WTPREBOOTSTAT */ { capwap_wtprebootstat_element_create, capwap_wtprebootstat_element_validate, capwap_wtprebootstat_element_parsing, capwap_wtprebootstat_element_free },	
	/* CAPWAP_ELEMENT_WTPSTATICIPADDRESS */ { capwap_wtpstaticipaddress_element_create, capwap_wtpstaticipaddress_element_validate, capwap_wtpstaticipaddress_element_parsing, capwap_wtpstaticipaddress_element_free },	
	/* CAPWAP_ELEMENT_LOCALIPV6 */ { capwap_localipv6_element_create, capwap_localipv6_element_validate, capwap_localipv6_element_parsing, capwap_localipv6_element_free },	
	/* CAPWAP_ELEMENT_TRANSPORT */ { capwap_transport_element_create, capwap_transport_element_validate, capwap_transport_element_parsing, capwap_transport_element_free },	
	/* CAPWAP_ELEMENT_MTUDISCOVERY */ { capwap_mtudiscovery_element_create, capwap_mtudiscovery_element_validate, capwap_mtudiscovery_element_parsing, capwap_mtudiscovery_element_free },	
	/* CAPWAP_ELEMENT_ECNSUPPORT */ { capwap_ecnsupport_element_create, capwap_ecnsupport_element_validate, capwap_ecnsupport_element_parsing, capwap_ecnsupport_element_free },
};

static struct capwap_message_elements_func ieee80211_message_elements[CAPWAP_80211_MESSAGE_ELEMENTS_COUNT] = {
	/*  */ { NULL, NULL },
	/* CAPWAP_ELEMENT_80211_ANTENNA */ { capwap_80211_antenna_element_create, capwap_80211_antenna_element_validate, capwap_80211_antenna_element_parsing, capwap_80211_antenna_element_free },
	/*  */ { NULL, NULL },
	/*  */ { NULL, NULL },
	/* CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL */ { capwap_80211_dscontrol_element_create, capwap_80211_dscontrol_element_validate, capwap_80211_dscontrol_element_parsing, capwap_80211_dscontrol_element_free },
	/*  */ { NULL, NULL },
	/* CAPWAP_ELEMENT_80211_MACOPERATION */ { capwap_80211_macoperation_element_create, capwap_80211_macoperation_element_validate, capwap_80211_macoperation_element_parsing, capwap_80211_macoperation_element_free },
	/*  */ { NULL, NULL },
	/* CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY */ { capwap_80211_multidomaincapability_element_create, capwap_80211_multidomaincapability_element_validate, capwap_80211_multidomaincapability_element_parsing, capwap_80211_multidomaincapability_element_free },
	/* CAPWAP_ELEMENT_80211_OFDMCONTROL */ { capwap_80211_ofdmcontrol_element_create, capwap_80211_ofdmcontrol_element_validate, capwap_80211_ofdmcontrol_element_parsing, capwap_80211_ofdmcontrol_element_free },
	/* CAPWAP_ELEMENT_80211_RATESET */ { capwap_80211_rateset_element_create, capwap_80211_rateset_element_validate, capwap_80211_rateset_element_parsing, capwap_80211_rateset_element_free },
	/*  */ { NULL, NULL },
	/*  */ { NULL, NULL },
	/*  */ { NULL, NULL },
	/*  */ { NULL, NULL },
	/*  */ { NULL, NULL },
	/* CAPWAP_ELEMENT_80211_SUPPORTEDRATES */ { capwap_80211_supportedrates_element_create, capwap_80211_supportedrates_element_validate, capwap_80211_supportedrates_element_parsing, capwap_80211_supportedrates_element_free },
	/* CAPWAP_ELEMENT_80211_TXPOWER */ { capwap_80211_txpower_element_create, capwap_80211_txpower_element_validate, capwap_80211_txpower_element_parsing, capwap_80211_txpower_element_free },
	/* CAPWAP_ELEMENT_80211_TXPOWERLEVEL */ { capwap_80211_txpowerlevel_element_create, capwap_80211_txpowerlevel_element_validate, capwap_80211_txpowerlevel_element_parsing, capwap_80211_txpowerlevel_element_free },
	/*  */ { NULL, NULL },
	/*  */ { NULL, NULL },
	/*  */ { NULL, NULL },
	/*  */ { NULL, NULL },
	/*  */ { NULL, NULL },
	/* CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION */ { capwap_80211_wtpradioinformation_element_create, capwap_80211_wtpradioinformation_element_validate, capwap_80211_wtpradioinformation_element_parsing, capwap_80211_wtpradioinformation_element_free },
};

/* */
struct capwap_message_elements_func* capwap_get_message_element(unsigned long code) {
	if ((code >= CAPWAP_MESSAGE_ELEMENTS_START) && (code <= CAPWAP_MESSAGE_ELEMENTS_STOP)) {
		return &standard_message_elements[code - CAPWAP_MESSAGE_ELEMENTS_START];
	} else if ((code >= CAPWAP_80211_MESSAGE_ELEMENTS_START) && (code <= CAPWAP_80211_MESSAGE_ELEMENTS_STOP)) {
		return &ieee80211_message_elements[code - CAPWAP_80211_MESSAGE_ELEMENTS_START];
	}
	
	return NULL;
}

/* */
void capwap_init_element_discovery_request(struct capwap_element_discovery_request* element, unsigned short binding) {
	ASSERT(element != NULL);

	memset(element, 0, sizeof(struct capwap_element_discovery_request));
	
	if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		element->binding.ieee80211.wtpradioinformation = capwap_array_create(sizeof(struct capwap_80211_wtpradioinformation_element*), 0);
	}
}

/* */
int capwap_parsing_element_discovery_request(struct capwap_element_discovery_request* element, struct capwap_list_item* item) {
	ASSERT(element != NULL);

	while (item != NULL) {
		struct capwap_message_element* elementitem = (struct capwap_message_element*)item->item;
		unsigned short type = ntohs(elementitem->type);
		struct capwap_message_elements_func* f = capwap_get_message_element(type);
		
		ASSERT(f != NULL);
		ASSERT(f->parsing != NULL);
		
		switch (type) {
			case CAPWAP_ELEMENT_DISCOVERYTYPE: {
				element->discoverytype = (struct capwap_discoverytype_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_WTPBOARDDATA: {
				element->wtpboarddata = (struct capwap_wtpboarddata_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_WTPDESCRIPTOR: {
				element->wtpdescriptor = (struct capwap_wtpdescriptor_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_WTPFRAMETUNNELMODE: {
				element->wtpframetunnel = (struct capwap_wtpframetunnelmode_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_WTPMACTYPE: {
				element->wtpmactype = (struct capwap_wtpmactype_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_MTUDISCOVERY: {
				element->mtudiscovery = (struct capwap_mtudiscovery_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_VENDORPAYLOAD: {
				element->vendorpayload = (struct capwap_vendorpayload_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION: {
				struct capwap_80211_wtpradioinformation_element** radio;
				
				radio = (struct capwap_80211_wtpradioinformation_element**)capwap_array_get_item_pointer(element->binding.ieee80211.wtpradioinformation, element->binding.ieee80211.wtpradioinformation->count);
				*radio = (struct capwap_80211_wtpradioinformation_element*)f->parsing(elementitem);
				break;
			}
		}
		
		/* Next element */
		item = item->next;
	}

	return 1;
}

/* */
void capwap_free_element_discovery_request(struct capwap_element_discovery_request* element, unsigned short binding) {
	unsigned long i;
	struct capwap_message_elements_func* f;

	ASSERT(element != NULL);

	if (element->discoverytype) {
		capwap_get_message_element(CAPWAP_ELEMENT_DISCOVERYTYPE)->free(element->discoverytype);
	}
	
	if (element->wtpboarddata) {
		capwap_get_message_element(CAPWAP_ELEMENT_WTPBOARDDATA)->free(element->wtpboarddata);
	}
	
	if (element->wtpdescriptor) {
		capwap_get_message_element(CAPWAP_ELEMENT_WTPDESCRIPTOR)->free(element->wtpdescriptor);
	}
	
	if (element->wtpframetunnel) {
		capwap_get_message_element(CAPWAP_ELEMENT_WTPFRAMETUNNELMODE)->free(element->wtpframetunnel);
	}
	
	if (element->wtpmactype) {
		capwap_get_message_element(CAPWAP_ELEMENT_WTPMACTYPE)->free(element->wtpmactype);
	}
	
	if (element->mtudiscovery) {
		capwap_get_message_element(CAPWAP_ELEMENT_MTUDISCOVERY)->free(element->mtudiscovery);
	}

	if (element->vendorpayload) {
		capwap_get_message_element(CAPWAP_ELEMENT_VENDORPAYLOAD)->free(element->vendorpayload);
	}
	
	if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		if (element->binding.ieee80211.wtpradioinformation->count > 0) {
			f = capwap_get_message_element(CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION);
			
			for (i = 0; i < element->binding.ieee80211.wtpradioinformation->count; i++) {					
				f->free(*(struct capwap_80211_wtpradioinformation_element**)capwap_array_get_item_pointer(element->binding.ieee80211.wtpradioinformation, i));
			}
		}
		
		capwap_array_free(element->binding.ieee80211.wtpradioinformation);
	}

	/* Clean */	
	memset(element, 0, sizeof(struct capwap_element_discovery_request));
}

/* */
void capwap_init_element_discovery_response(struct capwap_element_discovery_response* element, unsigned short binding) {
	ASSERT(element != NULL);

	memset(element, 0, sizeof(struct capwap_element_discovery_response));
	
	element->controlipv4 = capwap_array_create(sizeof(struct capwap_controlipv4_element*), 0);
	element->controlipv6 = capwap_array_create(sizeof(struct capwap_controlipv6_element*), 0);
	
	if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		element->binding.ieee80211.wtpradioinformation = capwap_array_create(sizeof(struct capwap_80211_wtpradioinformation_element*), 0);
	}
}

/* */
int capwap_parsing_element_discovery_response(struct capwap_element_discovery_response* element, struct capwap_list_item* item) {
	ASSERT(element != NULL);
	
	while (item != NULL) {
		struct capwap_message_element* elementitem = (struct capwap_message_element*)item->item;
		unsigned short type = ntohs(elementitem->type);
		struct capwap_message_elements_func* f = capwap_get_message_element(type);
		
		ASSERT(f != NULL);
		ASSERT(f->parsing != NULL);
		
		switch (type) {
			case CAPWAP_ELEMENT_ACDESCRIPTION: {
				element->acdescriptor = (struct capwap_acdescriptor_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_ACNAME: {
				element->acname = (struct capwap_acname_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_CONTROLIPV4: {
				struct capwap_controlipv4_element** controlipv4;
				
				controlipv4 = (struct capwap_controlipv4_element**)capwap_array_get_item_pointer(element->controlipv4, element->controlipv4->count);
				*controlipv4 = (struct capwap_controlipv4_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_CONTROLIPV6: {
				struct capwap_controlipv6_element** controlipv6;
				
				controlipv6 = (struct capwap_controlipv6_element**)capwap_array_get_item_pointer(element->controlipv6, element->controlipv6->count);
				*controlipv6 = (struct capwap_controlipv6_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_VENDORPAYLOAD: {
				element->vendorpayload = (struct capwap_vendorpayload_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION: {
				struct capwap_80211_wtpradioinformation_element** radio;
				
				radio = (struct capwap_80211_wtpradioinformation_element**)capwap_array_get_item_pointer(element->binding.ieee80211.wtpradioinformation, element->binding.ieee80211.wtpradioinformation->count);
				*radio = (struct capwap_80211_wtpradioinformation_element*)f->parsing(elementitem);
				break;
			}
		}
		
		/* Next element */
		item = item->next;
	}
	
	return 1;
}

/* */
void capwap_free_element_discovery_response(struct capwap_element_discovery_response* element, unsigned short binding) {
	unsigned long i;
	struct capwap_message_elements_func* f;
	
	ASSERT(element != NULL);

	if (element->acdescriptor) {
		capwap_get_message_element(CAPWAP_ELEMENT_ACDESCRIPTION)->free(element->acdescriptor);
	}
	
	if (element->acname) {
		capwap_get_message_element(CAPWAP_ELEMENT_ACNAME)->free(element->acname);
	}
	
	if (element->controlipv4->count > 0) {
		f = capwap_get_message_element(CAPWAP_ELEMENT_CONTROLIPV4);
		
		for (i = 0; i < element->controlipv4->count; i++) {					
			f->free(*(struct capwap_controlipv4_element**)capwap_array_get_item_pointer(element->controlipv4, i));
		}
	}
	capwap_array_free(element->controlipv4);
	
	if (element->controlipv6->count > 0) {
		f = capwap_get_message_element(CAPWAP_ELEMENT_CONTROLIPV6);
		
		for (i = 0; i < element->controlipv6->count; i++) {					
			f->free(*(struct capwap_controlipv6_element**)capwap_array_get_item_pointer(element->controlipv6, i));
		}
	}
	capwap_array_free(element->controlipv6);

	if (element->vendorpayload) {
		capwap_get_message_element(CAPWAP_ELEMENT_VENDORPAYLOAD)->free(element->vendorpayload);
	}

	if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		if (element->binding.ieee80211.wtpradioinformation->count > 0) {
			f = capwap_get_message_element(CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION);
			
			for (i = 0; i < element->binding.ieee80211.wtpradioinformation->count; i++) {					
				f->free(*(struct capwap_80211_wtpradioinformation_element**)capwap_array_get_item_pointer(element->binding.ieee80211.wtpradioinformation, i));
			}
		}
		
		capwap_array_free(element->binding.ieee80211.wtpradioinformation);
	}

	/* Clean */	
	memset(element, 0, sizeof(struct capwap_element_discovery_response));
}

/* */
void capwap_init_element_join_request(struct capwap_element_join_request* element, unsigned short binding) {
	ASSERT(element != NULL);

	memset(element, 0, sizeof(struct capwap_element_join_request));
	
	if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		element->binding.ieee80211.wtpradioinformation = capwap_array_create(sizeof(struct capwap_80211_wtpradioinformation_element*), 0);
	}
}

/* */
int capwap_parsing_element_join_request(struct capwap_element_join_request* element, struct capwap_list_item* item) {
	ASSERT(element);

	while (item != NULL) {
		struct capwap_message_element* elementitem = (struct capwap_message_element*)item->item;
		unsigned short type = ntohs(elementitem->type);
		struct capwap_message_elements_func* f = capwap_get_message_element(type);
		
		ASSERT(f != NULL);
		ASSERT(f->parsing != NULL);
		
		switch (type) {
			case CAPWAP_ELEMENT_LOCATION: {
				element->locationdata = (struct capwap_location_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_WTPBOARDDATA: {
				element->wtpboarddata = (struct capwap_wtpboarddata_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_WTPDESCRIPTOR: {
				element->wtpdescriptor = (struct capwap_wtpdescriptor_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_WTPNAME: {
				element->wtpname = (struct capwap_wtpname_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_SESSIONID: {
				element->sessionid = (struct capwap_sessionid_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_WTPFRAMETUNNELMODE: {
				element->wtpframetunnel = (struct capwap_wtpframetunnelmode_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_WTPMACTYPE: {
				element->wtpmactype = (struct capwap_wtpmactype_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_ECNSUPPORT: {
				element->ecnsupport = (struct capwap_ecnsupport_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_LOCALIPV4: {
				element->localipv4 = (struct capwap_localipv4_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_LOCALIPV6: {
				element->localipv6 = (struct capwap_localipv6_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_TRANSPORT: {
				element->trasport = (struct capwap_transport_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_MAXIMUMLENGTH: {
				element->maxiumlength = (struct capwap_maximumlength_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_WTPREBOOTSTAT: {
				element->wtprebootstat = (struct capwap_wtprebootstat_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_VENDORPAYLOAD: {
				element->vendorpayload = (struct capwap_vendorpayload_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION: {
				struct capwap_80211_wtpradioinformation_element** radio;
				
				radio = (struct capwap_80211_wtpradioinformation_element**)capwap_array_get_item_pointer(element->binding.ieee80211.wtpradioinformation, element->binding.ieee80211.wtpradioinformation->count);
				*radio = (struct capwap_80211_wtpradioinformation_element*)f->parsing(elementitem);
				break;
			}
		}
		
		/* Next element */
		item = item->next;
	}

	return 1;
}

/* */
void capwap_free_element_join_request(struct capwap_element_join_request* element, unsigned short binding) {
	unsigned long i;
	struct capwap_message_elements_func* f;

	ASSERT(element != NULL);
	
	if (element->locationdata) {
		capwap_get_message_element(CAPWAP_ELEMENT_LOCATION)->free(element->locationdata);
	}
	
	if (element->wtpboarddata) {
		capwap_get_message_element(CAPWAP_ELEMENT_WTPBOARDDATA)->free(element->wtpboarddata);
	}
	
	if (element->wtpdescriptor) {
		capwap_get_message_element(CAPWAP_ELEMENT_WTPDESCRIPTOR)->free(element->wtpdescriptor);
	}
	
	if (element->wtpname) {
		capwap_get_message_element(CAPWAP_ELEMENT_WTPNAME)->free(element->wtpname);
	}
	
	if (element->sessionid) {
		capwap_get_message_element(CAPWAP_ELEMENT_SESSIONID)->free(element->sessionid);
	}
	
	if (element->wtpframetunnel) {
		capwap_get_message_element(CAPWAP_ELEMENT_WTPFRAMETUNNELMODE)->free(element->wtpframetunnel);
	}
	
	if (element->wtpmactype) {
		capwap_get_message_element(CAPWAP_ELEMENT_WTPMACTYPE)->free(element->wtpmactype);
	}
	
	if (element->ecnsupport) {
		capwap_get_message_element(CAPWAP_ELEMENT_ECNSUPPORT)->free(element->ecnsupport);
	}
	
	if (element->localipv4) {
		capwap_get_message_element(CAPWAP_ELEMENT_LOCALIPV4)->free(element->localipv4);
	}
	
	if (element->localipv6) {
		capwap_get_message_element(CAPWAP_ELEMENT_LOCALIPV6)->free(element->localipv6);
	}
	
	if (element->trasport) {
		capwap_get_message_element(CAPWAP_ELEMENT_TRANSPORT)->free(element->trasport);
	}
	
	if (element->maxiumlength) {
		capwap_get_message_element(CAPWAP_ELEMENT_MAXIMUMLENGTH)->free(element->maxiumlength);
	}
	
	if (element->wtprebootstat) {
		capwap_get_message_element(CAPWAP_ELEMENT_WTPREBOOTSTAT)->free(element->wtprebootstat);
	}
	
	if (element->vendorpayload) {
		capwap_get_message_element(CAPWAP_ELEMENT_VENDORPAYLOAD)->free(element->vendorpayload);
	}

	if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		if (element->binding.ieee80211.wtpradioinformation->count > 0) {
			f = capwap_get_message_element(CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION);
			
			for (i = 0; i < element->binding.ieee80211.wtpradioinformation->count; i++) {					
				f->free(*(struct capwap_80211_wtpradioinformation_element**)capwap_array_get_item_pointer(element->binding.ieee80211.wtpradioinformation, i));
			}
		}
		
		capwap_array_free(element->binding.ieee80211.wtpradioinformation);
	}

	/* Clean */	
	memset(element, 0, sizeof(struct capwap_element_join_request));
}

/* */
void capwap_init_element_join_response(struct capwap_element_join_response* element, unsigned short binding) {
	ASSERT(element != NULL);

	memset(element, 0, sizeof(struct capwap_element_join_response));

	element->returnedmessage = capwap_array_create(sizeof(struct capwap_returnedmessage_element*), 0);
	element->controlipv4 = capwap_array_create(sizeof(struct capwap_controlipv4_element*), 0);
	element->controlipv6 = capwap_array_create(sizeof(struct capwap_controlipv6_element*), 0);
	
	if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		element->binding.ieee80211.wtpradioinformation = capwap_array_create(sizeof(struct capwap_80211_wtpradioinformation_element*), 0);
	}
}

/* */
int capwap_parsing_element_join_response(struct capwap_element_join_response* element, struct capwap_list_item* item) {
	ASSERT(element != NULL);
	
	while (item != NULL) {
		struct capwap_message_element* elementitem = (struct capwap_message_element*)item->item;
		unsigned short type = ntohs(elementitem->type);
		struct capwap_message_elements_func* f = capwap_get_message_element(type);
		
		ASSERT(f != NULL);
		ASSERT(f->parsing != NULL);
		
		switch (type) {
			case CAPWAP_ELEMENT_RESULTCODE: {
				element->resultcode = (struct capwap_resultcode_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_RETURNEDMESSAGE: {
				struct capwap_returnedmessage_element** returnedmessage;
				
				returnedmessage = (struct capwap_returnedmessage_element**)capwap_array_get_item_pointer(element->returnedmessage, element->returnedmessage->count);
				*returnedmessage = (struct capwap_returnedmessage_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_ACDESCRIPTION: {
				element->acdescriptor = (struct capwap_acdescriptor_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_ACNAME: {
				element->acname = (struct capwap_acname_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_ECNSUPPORT: {
				element->ecnsupport = (struct capwap_ecnsupport_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_CONTROLIPV4: {
				struct capwap_controlipv4_element** controlipv4;
				
				controlipv4 = (struct capwap_controlipv4_element**)capwap_array_get_item_pointer(element->controlipv4, element->controlipv4->count);
				*controlipv4 = (struct capwap_controlipv4_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_CONTROLIPV6: {
				struct capwap_controlipv6_element** controlipv6;
				
				controlipv6 = (struct capwap_controlipv6_element**)capwap_array_get_item_pointer(element->controlipv6, element->controlipv6->count);
				*controlipv6 = (struct capwap_controlipv6_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_LOCALIPV4: {
				element->localipv4 = (struct capwap_localipv4_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_LOCALIPV6: {
				element->localipv6 = (struct capwap_localipv6_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_ACIPV4LIST: {
				element->acipv4list = (capwap_acipv4list_element_array*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_ACIPV6LIST: {
				element->acipv6list = (capwap_acipv6list_element_array*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_TRANSPORT: {
				element->trasport = (struct capwap_transport_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_IMAGEIDENTIFIER: {
				element->imageidentifier = (struct capwap_imageidentifier_element*)f->parsing(elementitem);
				break;
			}
			
			case CAPWAP_ELEMENT_MAXIMUMLENGTH: {
				element->maxiumlength = (struct capwap_maximumlength_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_VENDORPAYLOAD: {
				element->vendorpayload = (struct capwap_vendorpayload_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION: {
				struct capwap_80211_wtpradioinformation_element** radio;
				
				radio = (struct capwap_80211_wtpradioinformation_element**)capwap_array_get_item_pointer(element->binding.ieee80211.wtpradioinformation, element->binding.ieee80211.wtpradioinformation->count);
				*radio = (struct capwap_80211_wtpradioinformation_element*)f->parsing(elementitem);
				break;
			}
		}
		
		/* Next element */
		item = item->next;
	}
	
	return 1;
}

/* */
void capwap_free_element_join_response(struct capwap_element_join_response* element, unsigned short binding) {
	unsigned long i;
	struct capwap_message_elements_func* f;

	ASSERT(element != NULL);

	if (element->resultcode) {
		capwap_get_message_element(CAPWAP_ELEMENT_RESULTCODE)->free(element->resultcode);
	}

	if (element->returnedmessage->count > 0) {
		f = capwap_get_message_element(CAPWAP_ELEMENT_RETURNEDMESSAGE);
		
		for (i = 0; i < element->returnedmessage->count; i++) {					
			f->free(*(struct capwap_returnedmessage_element**)capwap_array_get_item_pointer(element->returnedmessage, i));
		}
	}
	capwap_array_free(element->returnedmessage);

	if (element->acdescriptor) {
		capwap_get_message_element(CAPWAP_ELEMENT_ACDESCRIPTION)->free(element->acdescriptor);
	}

	if (element->acname) {
		capwap_get_message_element(CAPWAP_ELEMENT_ACNAME)->free(element->acname);
	}

	if (element->ecnsupport) {
		capwap_get_message_element(CAPWAP_ELEMENT_ECNSUPPORT)->free(element->ecnsupport);
	}

	if (element->controlipv4->count > 0) {
		f = capwap_get_message_element(CAPWAP_ELEMENT_CONTROLIPV4);
		
		for (i = 0; i < element->controlipv4->count; i++) {					
			f->free(*(struct capwap_controlipv4_element**)capwap_array_get_item_pointer(element->controlipv4, i));
		}
	}
	capwap_array_free(element->controlipv4);
	
	if (element->controlipv6->count > 0) {
		f = capwap_get_message_element(CAPWAP_ELEMENT_CONTROLIPV6);
		
		for (i = 0; i < element->controlipv6->count; i++) {					
			f->free(*(struct capwap_controlipv6_element**)capwap_array_get_item_pointer(element->controlipv6, i));
		}
	}
	capwap_array_free(element->controlipv6);

	if (element->localipv4) {
		capwap_get_message_element(CAPWAP_ELEMENT_LOCALIPV4)->free(element->localipv4);
	}
	
	if (element->localipv6) {
		capwap_get_message_element(CAPWAP_ELEMENT_LOCALIPV6)->free(element->localipv6);
	}

	if (element->acipv4list) {
		capwap_get_message_element(CAPWAP_ELEMENT_ACIPV4LIST)->free(element->acipv4list);
	}

	if (element->acipv6list) {
		capwap_get_message_element(CAPWAP_ELEMENT_ACIPV6LIST)->free(element->acipv6list);
	}

	if (element->trasport) {
		capwap_get_message_element(CAPWAP_ELEMENT_TRANSPORT)->free(element->trasport);
	}

	if (element->imageidentifier) {
		capwap_get_message_element(CAPWAP_ELEMENT_IMAGEIDENTIFIER)->free(element->imageidentifier);
	}

	if (element->maxiumlength) {
		capwap_get_message_element(CAPWAP_ELEMENT_MAXIMUMLENGTH)->free(element->maxiumlength);
	}

	if (element->vendorpayload) {
		capwap_get_message_element(CAPWAP_ELEMENT_VENDORPAYLOAD)->free(element->vendorpayload);
	}

	if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		if (element->binding.ieee80211.wtpradioinformation->count > 0) {
			f = capwap_get_message_element(CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION);
			
			for (i = 0; i < element->binding.ieee80211.wtpradioinformation->count; i++) {					
				f->free(*(struct capwap_80211_wtpradioinformation_element**)capwap_array_get_item_pointer(element->binding.ieee80211.wtpradioinformation, i));
			}
		}
		
		capwap_array_free(element->binding.ieee80211.wtpradioinformation);
	}

	/* Clean */	
	memset(element, 0, sizeof(struct capwap_element_join_response));
}

/* */
void capwap_init_element_configurationstatus_request(struct capwap_element_configurationstatus_request* element, unsigned short binding) {
	ASSERT(element != NULL);

	memset(element, 0, sizeof(struct capwap_element_configurationstatus_request));
	
	element->radioadmstatus = capwap_array_create(sizeof(struct capwap_radioadmstate_element*), 0);
	element->acnamepriority = capwap_array_create(sizeof(struct capwap_acnamepriority_element*), 0);
}

/* */
int capwap_parsing_element_configurationstatus_request(struct capwap_element_configurationstatus_request* element, struct capwap_list_item* item) {
	ASSERT(element != NULL);

	while (item != NULL) {
		struct capwap_message_element* elementitem = (struct capwap_message_element*)item->item;
		unsigned short type = ntohs(elementitem->type);
		struct capwap_message_elements_func* f = capwap_get_message_element(type);
		
		ASSERT(f != NULL);
		ASSERT(f->parsing != NULL);
		
		switch (type) {
			case CAPWAP_ELEMENT_ACNAME: {
				element->acname = (struct capwap_acname_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_RADIOADMSTATE: {
				struct capwap_radioadmstate_element** radioadmstate;
				
				radioadmstate = (struct capwap_radioadmstate_element**)capwap_array_get_item_pointer(element->radioadmstatus, element->radioadmstatus->count);
				*radioadmstate = (struct capwap_radioadmstate_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_STATISTICSTIMER: {
				element->statisticstimer = (struct capwap_statisticstimer_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_WTPREBOOTSTAT: {
				element->wtprebootstat = (struct capwap_wtprebootstat_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_ACNAMEPRIORITY: {
				struct capwap_acnamepriority_element** acnamepriority;
				
				acnamepriority = (struct capwap_acnamepriority_element**)capwap_array_get_item_pointer(element->acnamepriority, element->acnamepriority->count);
				*acnamepriority = (struct capwap_acnamepriority_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_TRANSPORT: {
				element->trasport = (struct capwap_transport_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_WTPSTATICIPADDRESS: {
				element->wtpstaticipaddress = (struct capwap_wtpstaticipaddress_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_VENDORPAYLOAD: {
				element->vendorpayload = (struct capwap_vendorpayload_element*)f->parsing(elementitem);
				break;
			}
		}

		/* Next element */
		item = item->next;
	}
	
	return 1;
}

/* */
void capwap_free_element_configurationstatus_request(struct capwap_element_configurationstatus_request* element, unsigned short binding) {
	unsigned long i;
	struct capwap_message_elements_func* f;

	ASSERT(element != NULL);

	if (element->acname) {
		capwap_get_message_element(CAPWAP_ELEMENT_ACNAME)->free(element->acname);
	}
	
	if (element->radioadmstatus->count > 0) {
		f = capwap_get_message_element(CAPWAP_ELEMENT_RADIOADMSTATE);
		
		for (i = 0; i < element->radioadmstatus->count; i++) {					
			f->free(*(struct capwap_radioadmstate_element**)capwap_array_get_item_pointer(element->radioadmstatus, i));
		}
	}
	capwap_array_free(element->radioadmstatus);
	
	if (element->statisticstimer) {
		capwap_get_message_element(CAPWAP_ELEMENT_STATISTICSTIMER)->free(element->statisticstimer);
	}

	if (element->wtprebootstat) {
		capwap_get_message_element(CAPWAP_ELEMENT_WTPREBOOTSTAT)->free(element->wtprebootstat);
	}

	if (element->acnamepriority->count > 0) {
		f = capwap_get_message_element(CAPWAP_ELEMENT_ACNAMEPRIORITY);
		
		for (i = 0; i < element->acnamepriority->count; i++) {					
			f->free(*(struct capwap_acnamepriority_element**)capwap_array_get_item_pointer(element->acnamepriority, i));
		}
	}
	capwap_array_free(element->acnamepriority);

	if (element->trasport) {
		capwap_get_message_element(CAPWAP_ELEMENT_TRANSPORT)->free(element->trasport);
	}

	if (element->wtpstaticipaddress) {
		capwap_get_message_element(CAPWAP_ELEMENT_WTPSTATICIPADDRESS)->free(element->wtpstaticipaddress);
	}

	if (element->vendorpayload) {
		capwap_get_message_element(CAPWAP_ELEMENT_VENDORPAYLOAD)->free(element->vendorpayload);
	}

	/* Clean */	
	memset(element, 0, sizeof(struct capwap_element_configurationstatus_request));
}

/* */
void capwap_init_element_configurationstatus_response(struct capwap_element_configurationstatus_response* element, unsigned short binding) {
	ASSERT(element != NULL);

	memset(element, 0, sizeof(struct capwap_element_configurationstatus_response));

	element->decrypterrorresultperiod = capwap_array_create(sizeof(struct capwap_decrypterrorreport_element*), 0);
	element->radiooprstatus = capwap_array_create(sizeof(struct capwap_radiooprstate_element*), 0);
}

/* */
int capwap_parsing_element_configurationstatus_response(struct capwap_element_configurationstatus_response* element, struct capwap_list_item* item) {
	ASSERT(element != NULL);

	while (item != NULL) {
		struct capwap_message_element* elementitem = (struct capwap_message_element*)item->item;
		unsigned short type = ntohs(elementitem->type);
		struct capwap_message_elements_func* f = capwap_get_message_element(type);
		
		ASSERT(f != NULL);
		ASSERT(f->parsing != NULL);
		
		switch (type) {
			case CAPWAP_ELEMENT_TIMERS: {
				element->timers = (struct capwap_timers_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD: {
				struct capwap_decrypterrorreport_element** decrypterrorresultperiod;
				
				decrypterrorresultperiod = (struct capwap_decrypterrorreport_element**)capwap_array_get_item_pointer(element->decrypterrorresultperiod, element->decrypterrorresultperiod->count);
				*decrypterrorresultperiod = (struct capwap_decrypterrorreport_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_IDLETIMEOUT: {
				element->idletimeout = (struct capwap_idletimeout_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_WTPFALLBACK: {
				element->wtpfallback = (struct capwap_wtpfallback_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_ACIPV4LIST: {
				element->acipv4list = (capwap_acipv4list_element_array*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_ACIPV6LIST: {
				element->acipv6list = (capwap_acipv6list_element_array*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_RADIOOPRSTATE: {
				struct capwap_radiooprstate_element** radiooprstatus;
				
				radiooprstatus = (struct capwap_radiooprstate_element**)capwap_array_get_item_pointer(element->radiooprstatus, element->radiooprstatus->count);
				*radiooprstatus = (struct capwap_radiooprstate_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_WTPSTATICIPADDRESS: {
				element->wtpstaticipaddress = (struct capwap_wtpstaticipaddress_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_VENDORPAYLOAD: {
				element->vendorpayload = (struct capwap_vendorpayload_element*)f->parsing(elementitem);
				break;
			}
		}
		
		/* Next element */
		item = item->next;
	}
	
	return 1;
}

/* */
void capwap_free_element_configurationstatus_response(struct capwap_element_configurationstatus_response* element, unsigned short binding) {
	unsigned long i;
	struct capwap_message_elements_func* f;

	ASSERT(element != NULL);

	if (element->timers) {
		capwap_get_message_element(CAPWAP_ELEMENT_TIMERS)->free(element->timers);
	}

	if (element->decrypterrorresultperiod->count > 0) {
		f = capwap_get_message_element(CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD);
		
		for (i = 0; i < element->decrypterrorresultperiod->count; i++) {					
			f->free(*(struct capwap_decrypterrorreport_element**)capwap_array_get_item_pointer(element->decrypterrorresultperiod, i));
		}
	}
	capwap_array_free(element->decrypterrorresultperiod);

	if (element->idletimeout) {
		capwap_get_message_element(CAPWAP_ELEMENT_IDLETIMEOUT)->free(element->idletimeout);
	}

	if (element->wtpfallback) {
		capwap_get_message_element(CAPWAP_ELEMENT_WTPFALLBACK)->free(element->wtpfallback);
	}

	if (element->acipv4list) {
		capwap_get_message_element(CAPWAP_ELEMENT_ACIPV4LIST)->free(element->acipv4list);
	}

	if (element->acipv6list) {
		capwap_get_message_element(CAPWAP_ELEMENT_ACIPV6LIST)->free(element->acipv6list);
	}

	if (element->radiooprstatus->count > 0) {
		f = capwap_get_message_element(CAPWAP_ELEMENT_RADIOOPRSTATE);
		
		for (i = 0; i < element->radiooprstatus->count; i++) {					
			f->free(*(struct capwap_radiooprstate_element**)capwap_array_get_item_pointer(element->radiooprstatus, i));
		}
	}
	capwap_array_free(element->radiooprstatus);

	if (element->wtpstaticipaddress) {
		capwap_get_message_element(CAPWAP_ELEMENT_WTPSTATICIPADDRESS)->free(element->wtpstaticipaddress);
	}

	if (element->vendorpayload) {
		capwap_get_message_element(CAPWAP_ELEMENT_VENDORPAYLOAD)->free(element->vendorpayload);
	}

	/* Clean */	
	memset(element, 0, sizeof(struct capwap_element_configurationstatus_response));
}

/* */
void capwap_init_element_changestateevent_request(struct capwap_element_changestateevent_request* element, unsigned short binding) {
	ASSERT(element != NULL);

	memset(element, 0, sizeof(struct capwap_element_changestateevent_request));

	element->radiooprstatus = capwap_array_create(sizeof(struct capwap_radiooprstate_element*), 0);
	element->returnedmessage = capwap_array_create(sizeof(struct capwap_returnedmessage_element*), 0);
}

/* */
int capwap_parsing_element_changestateevent_request(struct capwap_element_changestateevent_request* element, struct capwap_list_item* item) {
	ASSERT(element != NULL);

	while (item != NULL) {
		struct capwap_message_element* elementitem = (struct capwap_message_element*)item->item;
		unsigned short type = ntohs(elementitem->type);
		struct capwap_message_elements_func* f = capwap_get_message_element(type);
		
		ASSERT(f != NULL);
		ASSERT(f->parsing != NULL);
		
		switch (type) {
			case CAPWAP_ELEMENT_RADIOOPRSTATE: {
				struct capwap_radiooprstate_element** radiooprstatus;
				
				radiooprstatus = (struct capwap_radiooprstate_element**)capwap_array_get_item_pointer(element->radiooprstatus, element->radiooprstatus->count);
				*radiooprstatus = (struct capwap_radiooprstate_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_RESULTCODE: {
				element->resultcode = (struct capwap_resultcode_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_RETURNEDMESSAGE: {
				struct capwap_returnedmessage_element** returnedmessage;
				
				returnedmessage = (struct capwap_returnedmessage_element**)capwap_array_get_item_pointer(element->returnedmessage, element->returnedmessage->count);
				*returnedmessage = (struct capwap_returnedmessage_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_VENDORPAYLOAD: {
				element->vendorpayload = (struct capwap_vendorpayload_element*)f->parsing(elementitem);
				break;
			}
		}
		
		/* Next element */
		item = item->next;
	}
	
	return 1;
}

/* */
void capwap_free_element_changestateevent_request(struct capwap_element_changestateevent_request* element, unsigned short binding) {
	unsigned long i;
	struct capwap_message_elements_func* f;

	ASSERT(element != NULL);

	if (element->radiooprstatus->count > 0) {
		f = capwap_get_message_element(CAPWAP_ELEMENT_RADIOOPRSTATE);
		
		for (i = 0; i < element->radiooprstatus->count; i++) {
			f->free(*(struct capwap_radiooprstate_element**)capwap_array_get_item_pointer(element->radiooprstatus, i));
		}
	}
	capwap_array_free(element->radiooprstatus);

	if (element->resultcode) {
		capwap_get_message_element(CAPWAP_ELEMENT_RESULTCODE)->free(element->resultcode);
	}

	if (element->returnedmessage->count > 0) {
		f = capwap_get_message_element(CAPWAP_ELEMENT_RETURNEDMESSAGE);
		
		for (i = 0; i < element->returnedmessage->count; i++) {
			f->free(*(struct capwap_returnedmessage_element**)capwap_array_get_item_pointer(element->returnedmessage, i));
		}
	}
	capwap_array_free(element->returnedmessage);

	if (element->vendorpayload) {
		capwap_get_message_element(CAPWAP_ELEMENT_VENDORPAYLOAD)->free(element->vendorpayload);
	}

	/* Clean */	
	memset(element, 0, sizeof(struct capwap_element_changestateevent_request));
}

/* */
void capwap_init_element_changestateevent_response(struct capwap_element_changestateevent_response* element, unsigned short binding) {
	ASSERT(element != NULL);

	memset(element, 0, sizeof(struct capwap_element_changestateevent_response));
}

/* */
int capwap_parsing_element_changestateevent_response(struct capwap_element_changestateevent_response* element, struct capwap_list_item* item) {
	ASSERT(element != NULL);

	while (item != NULL) {
		struct capwap_message_element* elementitem = (struct capwap_message_element*)item->item;
		unsigned short type = ntohs(elementitem->type);
		struct capwap_message_elements_func* f = capwap_get_message_element(type);
		
		ASSERT(f != NULL);
		ASSERT(f->parsing != NULL);
		
		switch (type) {
			case CAPWAP_ELEMENT_VENDORPAYLOAD: {
				element->vendorpayload = (struct capwap_vendorpayload_element*)f->parsing(elementitem);
				break;
			}
		}
		
		/* Next element */
		item = item->next;
	}
	
	return 1;
}

/* */
void capwap_free_element_changestateevent_response(struct capwap_element_changestateevent_response* element, unsigned short binding) {
	ASSERT(element != NULL);

	if (element->vendorpayload) {
		capwap_get_message_element(CAPWAP_ELEMENT_VENDORPAYLOAD)->free(element->vendorpayload);
	}

	/* Clean */	
	memset(element, 0, sizeof(struct capwap_element_changestateevent_response));
}

/* */
void capwap_init_element_echo_request(struct capwap_element_echo_request* element, unsigned short binding) {
	ASSERT(element != NULL);

	memset(element, 0, sizeof(struct capwap_element_echo_request));
}

/* */
int capwap_parsing_element_echo_request(struct capwap_element_echo_request* element, struct capwap_list_item* item) {
	ASSERT(element != NULL);

	while (item != NULL) {
		struct capwap_message_element* elementitem = (struct capwap_message_element*)item->item;
		unsigned short type = ntohs(elementitem->type);
		struct capwap_message_elements_func* f = capwap_get_message_element(type);
		
		ASSERT(f != NULL);
		ASSERT(f->parsing != NULL);
		
		switch (type) {
			case CAPWAP_ELEMENT_VENDORPAYLOAD: {
				element->vendorpayload = (struct capwap_vendorpayload_element*)f->parsing(elementitem);
				break;
			}
		}
		
		/* Next element */
		item = item->next;
	}
	
	return 1;
}

/* */
void capwap_free_element_echo_request(struct capwap_element_echo_request* element, unsigned short binding) {
	ASSERT(element != NULL);

	if (element->vendorpayload) {
		capwap_get_message_element(CAPWAP_ELEMENT_VENDORPAYLOAD)->free(element->vendorpayload);
	}

	/* Clean */	
	memset(element, 0, sizeof(struct capwap_element_echo_request));
}

/* */
void capwap_init_element_echo_response(struct capwap_element_echo_response* element, unsigned short binding) {
	ASSERT(element != NULL);

	memset(element, 0, sizeof(struct capwap_element_echo_response));
}

/* */
int capwap_parsing_element_echo_response(struct capwap_element_echo_response* element, struct capwap_list_item* item) {
	ASSERT(element != NULL);

	while (item != NULL) {
		struct capwap_message_element* elementitem = (struct capwap_message_element*)item->item;
		unsigned short type = ntohs(elementitem->type);
		struct capwap_message_elements_func* f = capwap_get_message_element(type);
		
		ASSERT(f != NULL);
		ASSERT(f->parsing != NULL);
		
		switch (type) {
			case CAPWAP_ELEMENT_VENDORPAYLOAD: {
				element->vendorpayload = (struct capwap_vendorpayload_element*)f->parsing(elementitem);
				break;
			}
		}
		
		/* Next element */
		item = item->next;
	}
	
	return 1;
}

/* */
void capwap_free_element_echo_response(struct capwap_element_echo_response* element, unsigned short binding) {
	ASSERT(element != NULL);

	if (element->vendorpayload) {
		capwap_get_message_element(CAPWAP_ELEMENT_VENDORPAYLOAD)->free(element->vendorpayload);
	}

	/* Clean */	
	memset(element, 0, sizeof(struct capwap_element_echo_response));
}

/* */
void capwap_init_element_reset_request(struct capwap_element_reset_request* element, unsigned short binding) {
	ASSERT(element != NULL);

	memset(element, 0, sizeof(struct capwap_element_reset_request));
}

/* */
int capwap_parsing_element_reset_request(struct capwap_element_reset_request* element, struct capwap_list_item* item) {
	ASSERT(element != NULL);

	while (item != NULL) {
		struct capwap_message_element* elementitem = (struct capwap_message_element*)item->item;
		unsigned short type = ntohs(elementitem->type);
		struct capwap_message_elements_func* f = capwap_get_message_element(type);
		
		ASSERT(f != NULL);
		ASSERT(f->parsing != NULL);
		
		switch (type) {
			case CAPWAP_ELEMENT_IMAGEIDENTIFIER: {
				element->imageidentifier = (struct capwap_imageidentifier_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_VENDORPAYLOAD: {
				element->vendorpayload = (struct capwap_vendorpayload_element*)f->parsing(elementitem);
				break;
			}
		}
		
		/* Next element */
		item = item->next;
	}
	
	return 1;
}

/* */
void capwap_free_element_reset_request(struct capwap_element_reset_request* element, unsigned short binding) {
	ASSERT(element != NULL);

	if (element->imageidentifier) {
		capwap_get_message_element(CAPWAP_ELEMENT_IMAGEIDENTIFIER)->free(element->imageidentifier);
	}

	if (element->vendorpayload) {
		capwap_get_message_element(CAPWAP_ELEMENT_VENDORPAYLOAD)->free(element->vendorpayload);
	}

	/* Clean */	
	memset(element, 0, sizeof(struct capwap_element_reset_request));
}

/* */
void capwap_init_element_reset_response(struct capwap_element_reset_response* element, unsigned short binding) {
	ASSERT(element != NULL);

	memset(element, 0, sizeof(struct capwap_element_reset_response));
}

/* */
int capwap_parsing_element_reset_response(struct capwap_element_reset_response* element, struct capwap_list_item* item) {
	ASSERT(element != NULL);

	while (item != NULL) {
		struct capwap_message_element* elementitem = (struct capwap_message_element*)item->item;
		unsigned short type = ntohs(elementitem->type);
		struct capwap_message_elements_func* f = capwap_get_message_element(type);
		
		ASSERT(f != NULL);
		ASSERT(f->parsing != NULL);
		
		switch (type) {
			case CAPWAP_ELEMENT_RESULTCODE: {
				element->resultcode = (struct capwap_resultcode_element*)f->parsing(elementitem);
				break;
			}

			case CAPWAP_ELEMENT_VENDORPAYLOAD: {
				element->vendorpayload = (struct capwap_vendorpayload_element*)f->parsing(elementitem);
				break;
			}
		}
		
		/* Next element */
		item = item->next;
	}
	
	return 1;
}

/* */
void capwap_free_element_reset_response(struct capwap_element_reset_response* element, unsigned short binding) {
	ASSERT(element != NULL);

	if (element->resultcode) {
		capwap_get_message_element(CAPWAP_ELEMENT_RESULTCODE)->free(element->resultcode);
	}

	if (element->vendorpayload) {
		capwap_get_message_element(CAPWAP_ELEMENT_VENDORPAYLOAD)->free(element->vendorpayload);
	}

	/* Clean */	
	memset(element, 0, sizeof(struct capwap_element_reset_response));
}
