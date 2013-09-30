#include "ac.h"
#include "ac_json.h"
#include <json/json.h>

/* */
void ac_json_ieee80211_init(struct ac_json_ieee80211_wtpradio* wtpradio) {
	ASSERT(wtpradio != NULL);

	memset(wtpradio, 0, sizeof(struct ac_json_ieee80211_wtpradio));
}

/* */
void ac_json_ieee80211_free(struct ac_json_ieee80211_wtpradio* wtpradio) {
	int i;

	ASSERT(wtpradio != NULL);

	for (i = 0; i < RADIOID_MAX_COUNT; i++) {
		struct ac_json_ieee80211_item* item = &wtpradio->items[i];

		if (item->iearray) {
			capwap_array_free(item->iearray);
		}
	}
}

/* */
int ac_json_ieee80211_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, struct capwap_message_element_itemlist* messageelement) {
	int i;

	ASSERT(wtpradio != NULL);
	ASSERT(messageelement != NULL);

	switch (messageelement->type) {
		case CAPWAP_ELEMENT_80211_ADD_WLAN: {
			struct capwap_80211_addwlan_element* addwlan = (struct capwap_80211_addwlan_element*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE);

			if (wtpradio->items[addwlan->radioid - 1].addwlan) {
				return 0;
			}

			wtpradio->items[addwlan->radioid - 1].valid = 1;
			wtpradio->items[addwlan->radioid - 1].addwlan = addwlan;
			break;
		}

		case CAPWAP_ELEMENT_80211_ANTENNA: {
			struct capwap_array* antennaarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < antennaarray->count; i++) {
				struct capwap_80211_antenna_element* antenna = *(struct capwap_80211_antenna_element**)capwap_array_get_item_pointer(antennaarray, i);

				if (wtpradio->items[antenna->radioid - 1].antenna) {
					return 0;
				}

				wtpradio->items[antenna->radioid - 1].valid = 1;
				wtpradio->items[antenna->radioid - 1].antenna = antenna;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_ASSIGN_BSSID: {
			struct capwap_80211_assignbssid_element* assignbssid = (struct capwap_80211_assignbssid_element*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE);

			if (wtpradio->items[assignbssid->radioid - 1].assignbssid) {
				return 0;
			}

			wtpradio->items[assignbssid->radioid - 1].valid = 1;
			wtpradio->items[assignbssid->radioid - 1].assignbssid = assignbssid;
			break;
		}

		case CAPWAP_ELEMENT_80211_DELETE_WLAN: {
			struct capwap_80211_deletewlan_element* deletewlan = (struct capwap_80211_deletewlan_element*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE);

			if (wtpradio->items[deletewlan->radioid - 1].deletewlan) {
				return 0;
			}

			wtpradio->items[deletewlan->radioid - 1].valid = 1;
			wtpradio->items[deletewlan->radioid - 1].deletewlan = deletewlan;
			break;
		}

		case CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL: {
			struct capwap_array* directsequencecontrolarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < directsequencecontrolarray->count; i++) {
				struct capwap_80211_directsequencecontrol_element* directsequencecontrol = *(struct capwap_80211_directsequencecontrol_element**)capwap_array_get_item_pointer(directsequencecontrolarray, i);

				if (wtpradio->items[directsequencecontrol->radioid - 1].directsequencecontrol) {
					return 0;
				}

				wtpradio->items[directsequencecontrol->radioid - 1].valid = 1;
				wtpradio->items[directsequencecontrol->radioid - 1].directsequencecontrol = directsequencecontrol;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_IE: {
			struct capwap_array* iearray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < iearray->count; i++) {
				struct capwap_80211_ie_element* ie = *(struct capwap_80211_ie_element**)capwap_array_get_item_pointer(iearray, i);

				if (!wtpradio->items[ie->radioid - 1].iearray) {
					wtpradio->items[ie->radioid - 1].iearray = capwap_array_create(sizeof(struct capwap_80211_ie_element*), 0, 0);
				}

				wtpradio->items[ie->radioid - 1].valid = 1;
				memcpy(capwap_array_get_item_pointer(wtpradio->items[ie->radioid - 1].iearray, wtpradio->items[ie->radioid - 1].iearray->count), &ie, sizeof(struct capwap_80211_ie_element*));
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_MACOPERATION: {
			struct capwap_array* macoperationarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < macoperationarray->count; i++) {
				struct capwap_80211_macoperation_element* macoperation = *(struct capwap_80211_macoperation_element**)capwap_array_get_item_pointer(macoperationarray, i);

				if (wtpradio->items[macoperation->radioid - 1].macoperation) {
					return 0;
				}

				wtpradio->items[macoperation->radioid - 1].valid = 1;
				wtpradio->items[macoperation->radioid - 1].macoperation = macoperation;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES: {
			struct capwap_80211_miccountermeasures_element* miccountermeasures = (struct capwap_80211_miccountermeasures_element*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE);

			if (wtpradio->items[miccountermeasures->radioid - 1].miccountermeasures) {
				return 0;
			}

			wtpradio->items[miccountermeasures->radioid - 1].valid = 1;
			wtpradio->items[miccountermeasures->radioid - 1].miccountermeasures = miccountermeasures;

			break;
		}

		case CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY: {
			struct capwap_array* multidomaincapabilityarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < multidomaincapabilityarray->count; i++) {
				struct capwap_80211_multidomaincapability_element* multidomaincapability = *(struct capwap_80211_multidomaincapability_element**)capwap_array_get_item_pointer(multidomaincapabilityarray, i);

				if (wtpradio->items[multidomaincapability->radioid - 1].multidomaincapability) {
					return 0;
				}

				wtpradio->items[multidomaincapability->radioid - 1].valid = 1;
				wtpradio->items[multidomaincapability->radioid - 1].multidomaincapability = multidomaincapability;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_OFDMCONTROL: {
			struct capwap_array* ofdmcontrolarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < ofdmcontrolarray->count; i++) {
				struct capwap_80211_ofdmcontrol_element* ofdmcontrol = *(struct capwap_80211_ofdmcontrol_element**)capwap_array_get_item_pointer(ofdmcontrolarray, i);

				if (wtpradio->items[ofdmcontrol->radioid - 1].ofdmcontrol) {
					return 0;
				}

				wtpradio->items[ofdmcontrol->radioid - 1].valid = 1;
				wtpradio->items[ofdmcontrol->radioid - 1].ofdmcontrol = ofdmcontrol;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_RATESET: {
			struct capwap_array* ratesetarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < ratesetarray->count; i++) {
				struct capwap_80211_rateset_element* rateset = *(struct capwap_80211_rateset_element**)capwap_array_get_item_pointer(ratesetarray, i);

				if (wtpradio->items[rateset->radioid - 1].rateset) {
					return 0;
				}

				wtpradio->items[rateset->radioid - 1].valid = 1;
				wtpradio->items[rateset->radioid - 1].rateset = rateset;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT: {
			struct capwap_80211_rsnaerrorreport_element* rsnaerrorreport = (struct capwap_80211_rsnaerrorreport_element*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE);

			if (wtpradio->items[rsnaerrorreport->radioid - 1].rsnaerrorreport) {
				return 0;
			}

			wtpradio->items[rsnaerrorreport->radioid - 1].valid = 1;
			wtpradio->items[rsnaerrorreport->radioid - 1].rsnaerrorreport = rsnaerrorreport;
			break;
		}

		case CAPWAP_ELEMENT_80211_STATISTICS: {
			struct capwap_array* statisticsarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < statisticsarray->count; i++) {
				struct capwap_80211_statistics_element* statistics = *(struct capwap_80211_statistics_element**)capwap_array_get_item_pointer(statisticsarray, i);

				if (wtpradio->items[statistics->radioid - 1].statistics) {
					return 0;
				}

				wtpradio->items[statistics->radioid - 1].valid = 1;
				wtpradio->items[statistics->radioid - 1].statistics = statistics;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_SUPPORTEDRATES: {
			struct capwap_array* supportedratesarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < supportedratesarray->count; i++) {
				struct capwap_80211_supportedrates_element* supportedrates = *(struct capwap_80211_supportedrates_element**)capwap_array_get_item_pointer(supportedratesarray, i);

				if (wtpradio->items[supportedrates->radioid - 1].supportedrates) {
					return 0;
				}

				wtpradio->items[supportedrates->radioid - 1].valid = 1;
				wtpradio->items[supportedrates->radioid - 1].supportedrates = supportedrates;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_TXPOWER: {
			struct capwap_array* txpowerarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < txpowerarray->count; i++) {
				struct capwap_80211_txpower_element* txpower = *(struct capwap_80211_txpower_element**)capwap_array_get_item_pointer(txpowerarray, i);

				if (wtpradio->items[txpower->radioid - 1].txpower) {
					return 0;
				}

				wtpradio->items[txpower->radioid - 1].valid = 1;
				wtpradio->items[txpower->radioid - 1].txpower = txpower;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_TXPOWERLEVEL: {
			struct capwap_array* txpowerlevelarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < txpowerlevelarray->count; i++) {
				struct capwap_80211_txpowerlevel_element* txpowerlevel = *(struct capwap_80211_txpowerlevel_element**)capwap_array_get_item_pointer(txpowerlevelarray, i);

				if (wtpradio->items[txpowerlevel->radioid - 1].txpowerlevel) {
					return 0;
				}

				wtpradio->items[txpowerlevel->radioid - 1].valid = 1;
				wtpradio->items[txpowerlevel->radioid - 1].txpowerlevel = txpowerlevel;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_UPDATE_WLAN: {
			struct capwap_80211_updatewlan_element* updatewlan = (struct capwap_80211_updatewlan_element*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE);

			if (wtpradio->items[updatewlan->radioid - 1].updatewlan) {
				return 0;
			}

			wtpradio->items[updatewlan->radioid - 1].valid = 1;
			wtpradio->items[updatewlan->radioid - 1].updatewlan = updatewlan;
			break;
		}

		case CAPWAP_ELEMENT_80211_WTP_QOS: {
			struct capwap_array* wtpqosarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < wtpqosarray->count; i++) {
				struct capwap_80211_wtpqos_element* wtpqos = *(struct capwap_80211_wtpqos_element**)capwap_array_get_item_pointer(wtpqosarray, i);

				if (wtpradio->items[wtpqos->radioid - 1].wtpqos) {
					return 0;
				}

				wtpradio->items[wtpqos->radioid - 1].valid = 1;
				wtpradio->items[wtpqos->radioid - 1].wtpqos = wtpqos;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_WTP_RADIO_CONF: {
			struct capwap_array* wtpradioconfarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < wtpradioconfarray->count; i++) {
				struct capwap_80211_wtpradioconf_element* wtpradioconf = *(struct capwap_80211_wtpradioconf_element**)capwap_array_get_item_pointer(wtpradioconfarray, i);

				if (wtpradio->items[wtpradioconf->radioid - 1].wtpradioconf) {
					return 0;
				}

				wtpradio->items[wtpradioconf->radioid - 1].valid = 1;
				wtpradio->items[wtpradioconf->radioid - 1].wtpradioconf = wtpradioconf;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM: {
			struct capwap_80211_wtpradiofailalarm_element* wtpradiofailalarm = (struct capwap_80211_wtpradiofailalarm_element*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE);

			if (wtpradio->items[wtpradiofailalarm->radioid - 1].wtpradiofailalarm) {
				return 0;
			}

			wtpradio->items[wtpradiofailalarm->radioid - 1].valid = 1;
			wtpradio->items[wtpradiofailalarm->radioid - 1].wtpradiofailalarm = wtpradiofailalarm;
			break;
		}

		case CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION: {
			struct capwap_array* wtpradioinformationarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < wtpradioinformationarray->count; i++) {
				struct capwap_80211_wtpradioinformation_element* wtpradioinformation = *(struct capwap_80211_wtpradioinformation_element**)capwap_array_get_item_pointer(wtpradioinformationarray, i);

				if (wtpradio->items[wtpradioinformation->radioid - 1].wtpradioinformation) {
					return 0;
				}

				wtpradio->items[wtpradioinformation->radioid - 1].valid = 1;
				wtpradio->items[wtpradioinformation->radioid - 1].wtpradioinformation = wtpradioinformation;
			}

			break;
		}
	}

	return 1;
}

/* */
struct json_object* ac_json_ieee80211_getjson(struct ac_json_ieee80211_wtpradio* wtpradio) {
	int i;
	struct json_object* jsonarray;
	struct json_object* jsonitems;
	struct json_object* jsonitem;

	jsonarray = json_object_new_array();
	for (i = 0; i < RADIOID_MAX_COUNT; i++) {
		struct ac_json_ieee80211_item* item = &wtpradio->items[i];

		if (!item->valid) {
			continue;
		}

		/* */
		jsonitems = json_object_new_object();

		/* Radio Id */
		json_object_object_add(jsonitems, "RadioID", json_object_new_int(i + 1));

		if (item->addwlan) {
		}

		if (item->antenna) {
			struct json_object* jsonantenna;

			jsonantenna = json_object_new_array();
			for (i = 0; i < item->antenna->selections->count; i++) {
				json_object_array_add(jsonantenna, json_object_new_int((int)*(uint8_t*)capwap_array_get_item_pointer(item->antenna->selections, i)));
			}

			jsonitem = json_object_new_object();
			json_object_object_add(jsonitem, "Diversity", json_object_new_boolean((item->antenna->diversity == CAPWAP_ANTENNA_DIVERSITY_ENABLE) ? 1 : 0));
			json_object_object_add(jsonitem, "Combiner", json_object_new_int((int)item->antenna->combiner));
			json_object_object_add(jsonitem, "AntennaSelection", jsonantenna);
			json_object_object_add(jsonitems, "IEEE80211Antenna", jsonitem);
		}

		if (item->assignbssid) {
		}

		if (item->deletewlan) {
		}

		if (item->directsequencecontrol) {
			jsonitem = json_object_new_object();
			json_object_object_add(jsonitem, "CurrentChan", json_object_new_int((int)item->directsequencecontrol->currentchannel));
			json_object_object_add(jsonitem, "CurrentCCA", json_object_new_int((int)item->directsequencecontrol->currentcca));
			json_object_object_add(jsonitem, "EnergyDetectThreshold", json_object_new_int((int)item->directsequencecontrol->enerydetectthreshold));
			json_object_object_add(jsonitems, "IEEE80211DirectSequenceControl", jsonitem);
		}

		if (item->iearray) {
		}

		if (item->macoperation) {
			jsonitem = json_object_new_object();
			json_object_object_add(jsonitem, "RTSThreshold", json_object_new_int((int)item->macoperation->rtsthreshold));
			json_object_object_add(jsonitem, "ShortRetry", json_object_new_int((int)item->macoperation->shortretry));
			json_object_object_add(jsonitem, "LongRetry", json_object_new_int((int)item->macoperation->longretry));
			json_object_object_add(jsonitem, "FragmentationThreshold", json_object_new_int((int)item->macoperation->fragthreshold));
			json_object_object_add(jsonitem, "TxMSDULifetime", json_object_new_int((int)item->macoperation->txmsdulifetime));
			json_object_object_add(jsonitem, "RxMSDULifetime", json_object_new_int((int)item->macoperation->rxmsdulifetime));
			json_object_object_add(jsonitems, "IEEE80211MACOperation", jsonitem);
		}

		if (item->miccountermeasures) {
		}

		if (item->multidomaincapability) {
			jsonitem = json_object_new_object();
			json_object_object_add(jsonitem, "FirstChannel", json_object_new_int((int)item->multidomaincapability->firstchannel));
			json_object_object_add(jsonitem, "NumberChannels", json_object_new_int((int)item->multidomaincapability->numberchannels));
			json_object_object_add(jsonitem, "MaxTxPowerLevel", json_object_new_int((int)item->multidomaincapability->maxtxpowerlevel));
			json_object_object_add(jsonitems, "IEEE80211MultiDomainCapability", jsonitem);
		}

		if (item->ofdmcontrol) {
			jsonitem = json_object_new_object();
			json_object_object_add(jsonitem, "CurrentChan", json_object_new_int((int)item->ofdmcontrol->currentchannel));
			json_object_object_add(jsonitem, "BandSupport", json_object_new_int((int)item->ofdmcontrol->bandsupport));
			json_object_object_add(jsonitem, "TIThreshold", json_object_new_int((int)item->ofdmcontrol->tithreshold));
			json_object_object_add(jsonitems, "IEEE80211OFDMControl", jsonitem);
		}

		if (item->rateset) {
		}

		if (item->rsnaerrorreport) {
		}

		if (item->statistics) {
		}

		if (item->supportedrates) {
			struct json_object* jsonrates;

			jsonrates = json_object_new_array();
			for (i = 0; i < item->supportedrates->supportedratescount; i++) {
				json_object_array_add(jsonrates, json_object_new_int((int)item->supportedrates->supportedrates[i]));
			}

			json_object_object_add(jsonitems, "IEEE80211SupportedRates", jsonrates);
		}

		if (item->txpower) {
			jsonitem = json_object_new_object();
			json_object_object_add(jsonitem, "CurrentTxPower", json_object_new_int((int)item->txpower->currenttxpower));
			json_object_object_add(jsonitems, "IEEE80211TxPower", jsonitem);
		}

		if (item->txpowerlevel) {
			struct json_object* jsontxpower;

			jsontxpower = json_object_new_array();
			for (i = 0; i < item->txpowerlevel->numlevels; i++) {
				json_object_array_add(jsontxpower, json_object_new_int((int)item->txpowerlevel->powerlevel[i]));
			}

			json_object_object_add(jsonitems, "IEEE80211TXPowerLevel", jsontxpower);
		}

		if (item->updatewlan) {
		}

		if (item->wtpqos) {
		}

		if (item->wtpradioconf) {
			char buffer[18];

			jsonitem = json_object_new_object();
			json_object_object_add(jsonitem, "ShortPreamble", json_object_new_int((int)item->wtpradioconf->shortpreamble));
			json_object_object_add(jsonitem, "NumBSSIDs", json_object_new_int((int)item->wtpradioconf->maxbssid));
			json_object_object_add(jsonitem, "DTIMPeriod", json_object_new_int((int)item->wtpradioconf->dtimperiod));
			json_object_object_add(jsonitem, "BSSID", json_object_new_string(capwap_printf_macaddress(buffer, (unsigned char*)item->wtpradioconf->bssid, MACADDRESS_EUI48_LENGTH)));
			json_object_object_add(jsonitem, "BeaconPeriod", json_object_new_int((int)item->wtpradioconf->beaconperiod));
			json_object_object_add(jsonitem, "CountryString", json_object_new_string((char*)item->wtpradioconf->country));
			json_object_object_add(jsonitems, "IEEE80211WTPRadioConfiguration", jsonitem);
		}

		if (item->wtpradiofailalarm) {
		}

		if (item->wtpradioinformation) {
			jsonitem = json_object_new_object();
			json_object_object_add(jsonitem, "Mode", json_object_new_int((int)item->wtpradioinformation->radiotype));
			json_object_object_add(jsonitems, "IEEE80211WTPRadioInformation", jsonitem);
		}

		/* */
		json_object_array_add(jsonarray, jsonitems);
	}

	return jsonarray;
}
