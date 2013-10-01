#include "ac.h"
#include "ac_json.h"

/* */
void ac_json_ieee80211_init(struct ac_json_ieee80211_wtpradio* wtpradio) {
	ASSERT(wtpradio != NULL);

	memset(wtpradio, 0, sizeof(struct ac_json_ieee80211_wtpradio));
}

/* */
void ac_json_ieee80211_free(struct ac_json_ieee80211_wtpradio* wtpradio) {
	int i, j;

	ASSERT(wtpradio != NULL);

	for (i = 0; i < RADIOID_MAX_COUNT; i++) {
		struct ac_json_ieee80211_item* item = &wtpradio->items[i];

		if (item->valid) {
			if (item->addwlan) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_ADD_WLAN)->free_message_element(item->addwlan);
			}

			if (item->antenna) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_ANTENNA)->free_message_element(item->antenna);
			}

			if (item->assignbssid) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_ASSIGN_BSSID)->free_message_element(item->assignbssid);
			}

			if (item->deletewlan) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_DELETE_WLAN)->free_message_element(item->deletewlan);
			}

			if (item->directsequencecontrol) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL)->free_message_element(item->directsequencecontrol);
			}

			if (item->iearray) {
				struct capwap_message_elements_ops* ieops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_IE);

				for (j = 0; j < item->iearray->count; j++) {
					ieops->free_message_element(*(struct capwap_80211_ie_element**)capwap_array_get_item_pointer(item->iearray, j));
				}

				capwap_array_free(item->iearray);
			}

			if (item->macoperation) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_MACOPERATION)->free_message_element(item->macoperation);
			}

			if (item->miccountermeasures) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES)->free_message_element(item->miccountermeasures);
			}

			if (item->multidomaincapability) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY)->free_message_element(item->multidomaincapability);
			}

			if (item->ofdmcontrol) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_OFDMCONTROL)->free_message_element(item->ofdmcontrol);
			}

			if (item->rateset) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_RATESET)->free_message_element(item->rateset);
			}

			if (item->rsnaerrorreport) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT)->free_message_element(item->rsnaerrorreport);
			}

			if (item->statistics) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_STATISTICS)->free_message_element(item->statistics);
			}

			if (item->supportedrates) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_SUPPORTEDRATES)->free_message_element(item->supportedrates);
			}

			if (item->txpower) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_TXPOWER)->free_message_element(item->txpower);
			}

			if (item->txpowerlevel) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_TXPOWERLEVEL)->free_message_element(item->txpowerlevel);
			}

			if (item->updatewlan) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_UPDATE_WLAN)->free_message_element(item->updatewlan);
			}

			if (item->wtpqos) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTP_QOS)->free_message_element(item->wtpqos);
			}

			if (item->wtpradioconf) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTP_RADIO_CONF)->free_message_element(item->wtpradioconf);
			}

			if (item->wtpradiofailalarm) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM)->free_message_element(item->wtpradiofailalarm);
			}

			if (item->wtpradioinformation) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION)->free_message_element(item->wtpradioinformation);
			}
		}
	}
}

/* */
int ac_json_ieee80211_addmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, uint16_t type, void* data, int overwrite) {
	ASSERT(wtpradio != NULL);
	ASSERT(IS_80211_MESSAGE_ELEMENTS(type));
	ASSERT(data != NULL);

	switch (type) {
		case CAPWAP_ELEMENT_80211_ADD_WLAN: {
			struct capwap_80211_addwlan_element* addwlan = (struct capwap_80211_addwlan_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[addwlan->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_ADD_WLAN);

			if (item->addwlan) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->addwlan);
			}

			item->valid = 1;
			item->addwlan = (struct capwap_80211_addwlan_element*)ops->clone_message_element(addwlan);
			break;
		}

		case CAPWAP_ELEMENT_80211_ANTENNA: {
			struct capwap_80211_antenna_element* antenna = (struct capwap_80211_antenna_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[antenna->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_ANTENNA);

			if (item->antenna) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->antenna);
			}

			item->valid = 1;
			item->antenna = (struct capwap_80211_antenna_element*)ops->clone_message_element(antenna);
			break;
		}

		case CAPWAP_ELEMENT_80211_ASSIGN_BSSID: {
			struct capwap_80211_assignbssid_element* assignbssid = (struct capwap_80211_assignbssid_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[assignbssid->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_ASSIGN_BSSID);

			if (item->assignbssid) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->assignbssid);
			}

			item->valid = 1;
			item->assignbssid = (struct capwap_80211_assignbssid_element*)ops->clone_message_element(assignbssid);
			break;
		}

		case CAPWAP_ELEMENT_80211_DELETE_WLAN: {
			struct capwap_80211_deletewlan_element* deletewlan = (struct capwap_80211_deletewlan_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[deletewlan->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_DELETE_WLAN);

			if (item->deletewlan) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->deletewlan);
			}

			item->valid = 1;
			item->deletewlan = (struct capwap_80211_deletewlan_element*)ops->clone_message_element(deletewlan);
			break;
		}

		case CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL: {
			struct capwap_80211_directsequencecontrol_element* directsequencecontrol = (struct capwap_80211_directsequencecontrol_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[directsequencecontrol->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL);

			if (item->directsequencecontrol) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->directsequencecontrol);
			}

			item->valid = 1;
			item->directsequencecontrol = (struct capwap_80211_directsequencecontrol_element*)ops->clone_message_element(directsequencecontrol);
			break;
		}

		case CAPWAP_ELEMENT_80211_IE: {
			struct capwap_80211_ie_element** ieclone;
			struct capwap_80211_ie_element* ie = (struct capwap_80211_ie_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[ie->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_IE);

			if (!item->iearray) {
				item->iearray = capwap_array_create(sizeof(struct capwap_80211_ie_element*), 0, 0);
			}

			item->valid = 1;
			ieclone = (struct capwap_80211_ie_element**)capwap_array_get_item_pointer(item->iearray, item->iearray->count);
			*ieclone = (struct capwap_80211_ie_element*)ops->clone_message_element(ie);

			break;
		}

		case CAPWAP_ELEMENT_80211_MACOPERATION: {
			struct capwap_80211_macoperation_element* macoperation = (struct capwap_80211_macoperation_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[macoperation->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_MACOPERATION);

			if (item->macoperation) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->macoperation);
			}

			item->valid = 1;
			item->macoperation = (struct capwap_80211_macoperation_element*)ops->clone_message_element(macoperation);
			break;
		}

		case CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES: {
			struct capwap_80211_miccountermeasures_element* miccountermeasures = (struct capwap_80211_miccountermeasures_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[miccountermeasures->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES);

			if (item->miccountermeasures) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->miccountermeasures);
			}

			item->valid = 1;
			item->miccountermeasures = (struct capwap_80211_miccountermeasures_element*)ops->clone_message_element(miccountermeasures);
			break;
		}

		case CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY: {
			struct capwap_80211_multidomaincapability_element* multidomaincapability = (struct capwap_80211_multidomaincapability_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[multidomaincapability->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY);

			if (item->multidomaincapability) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->multidomaincapability);
			}

			item->valid = 1;
			item->multidomaincapability = (struct capwap_80211_multidomaincapability_element*)ops->clone_message_element(multidomaincapability);
			break;
		}

		case CAPWAP_ELEMENT_80211_OFDMCONTROL: {
			struct capwap_80211_ofdmcontrol_element* ofdmcontrol = (struct capwap_80211_ofdmcontrol_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[ofdmcontrol->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_OFDMCONTROL);

			if (item->ofdmcontrol) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->ofdmcontrol);
			}

			item->valid = 1;
			item->ofdmcontrol = (struct capwap_80211_ofdmcontrol_element*)ops->clone_message_element(ofdmcontrol);
			break;
		}

		case CAPWAP_ELEMENT_80211_RATESET: {
			struct capwap_80211_rateset_element* rateset = (struct capwap_80211_rateset_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[rateset->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_RATESET);

			if (item->rateset) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->rateset);
			}

			item->valid = 1;
			item->rateset = (struct capwap_80211_rateset_element*)ops->clone_message_element(rateset);
			break;
		}

		case CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT: {
			struct capwap_80211_rsnaerrorreport_element* rsnaerrorreport = (struct capwap_80211_rsnaerrorreport_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[rsnaerrorreport->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT);

			if (item->rsnaerrorreport) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->rsnaerrorreport);
			}

			item->valid = 1;
			item->rsnaerrorreport = (struct capwap_80211_rsnaerrorreport_element*)ops->clone_message_element(rsnaerrorreport);
			break;
		}

		case CAPWAP_ELEMENT_80211_STATISTICS: {
			struct capwap_80211_statistics_element* statistics = (struct capwap_80211_statistics_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[statistics->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_STATISTICS);

			if (item->statistics) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->statistics);
			}

			item->valid = 1;
			item->statistics = (struct capwap_80211_statistics_element*)ops->clone_message_element(statistics);
			break;
		}

		case CAPWAP_ELEMENT_80211_SUPPORTEDRATES: {
			struct capwap_80211_supportedrates_element* supportedrates = (struct capwap_80211_supportedrates_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[supportedrates->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_SUPPORTEDRATES);

			if (item->supportedrates) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->supportedrates);
			}

			item->valid = 1;
			item->supportedrates = (struct capwap_80211_supportedrates_element*)ops->clone_message_element(supportedrates);
			break;
		}

		case CAPWAP_ELEMENT_80211_TXPOWER: {
			struct capwap_80211_txpower_element* txpower = (struct capwap_80211_txpower_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[txpower->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_TXPOWER);

			if (item->txpower) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->txpower);
			}

			item->valid = 1;
			item->txpower = (struct capwap_80211_txpower_element*)ops->clone_message_element(txpower);
			break;
		}

		case CAPWAP_ELEMENT_80211_TXPOWERLEVEL: {
			struct capwap_80211_txpowerlevel_element* txpowerlevel = (struct capwap_80211_txpowerlevel_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[txpowerlevel->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_TXPOWERLEVEL);

			if (item->txpowerlevel) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->txpowerlevel);
			}

			item->valid = 1;
			item->txpowerlevel = (struct capwap_80211_txpowerlevel_element*)ops->clone_message_element(txpowerlevel);
			break;
		}

		case CAPWAP_ELEMENT_80211_UPDATE_WLAN: {
			struct capwap_80211_updatewlan_element* updatewlan = (struct capwap_80211_updatewlan_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[updatewlan->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_UPDATE_WLAN);

			if (item->updatewlan) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->updatewlan);
			}

			item->valid = 1;
			item->updatewlan = (struct capwap_80211_updatewlan_element*)ops->clone_message_element(updatewlan);
			break;
		}

		case CAPWAP_ELEMENT_80211_WTP_QOS: {
			struct capwap_80211_wtpqos_element* wtpqos = (struct capwap_80211_wtpqos_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[wtpqos->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTP_QOS);

			if (item->wtpqos) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->wtpqos);
			}

			item->valid = 1;
			item->wtpqos = (struct capwap_80211_wtpqos_element*)ops->clone_message_element(wtpqos);
			break;
		}

		case CAPWAP_ELEMENT_80211_WTP_RADIO_CONF: {
			struct capwap_80211_wtpradioconf_element* wtpradioconf = (struct capwap_80211_wtpradioconf_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[wtpradioconf->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTP_RADIO_CONF);

			if (item->wtpradioconf) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->wtpradioconf);
			}

			item->valid = 1;
			item->wtpradioconf = (struct capwap_80211_wtpradioconf_element*)ops->clone_message_element(wtpradioconf);
			break;
		}

		case CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM: {
			struct capwap_80211_wtpradiofailalarm_element* wtpradiofailalarm = (struct capwap_80211_wtpradiofailalarm_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[wtpradiofailalarm->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM);

			if (item->wtpradiofailalarm) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->wtpradiofailalarm);
			}

			item->valid = 1;
			item->wtpradiofailalarm = (struct capwap_80211_wtpradiofailalarm_element*)ops->clone_message_element(wtpradiofailalarm);
			break;
		}

		case CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION: {
			struct capwap_80211_wtpradioinformation_element* wtpradioinformation = (struct capwap_80211_wtpradioinformation_element*)data;
			struct ac_json_ieee80211_item* item = &wtpradio->items[wtpradioinformation->radioid - 1];
			struct capwap_message_elements_ops* ops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION);

			if (item->wtpradioinformation) {
				if (!overwrite) {
					return 0;
				}

				ops->free_message_element(item->wtpradioinformation);
			}

			item->valid = 1;
			item->wtpradioinformation = (struct capwap_80211_wtpradioinformation_element*)ops->clone_message_element(wtpradioinformation);
			break;
		}

		default: {
			return 0;
		}
	}

	return 1;
}

/* */
int ac_json_ieee80211_parsingmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, struct capwap_message_element_itemlist* messageelement) {
	int i;

	ASSERT(wtpradio != NULL);
	ASSERT(messageelement != NULL);

	switch (messageelement->type) {
		case CAPWAP_ELEMENT_80211_ADD_WLAN: {
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE);

			if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_ADD_WLAN, messageelement->data, 0)) {
				return 0;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_ANTENNA: {
			struct capwap_array* antennaarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < antennaarray->count; i++) {
				if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_ANTENNA, *(struct capwap_80211_antenna_element**)capwap_array_get_item_pointer(antennaarray, i), 0)) {
					return 0;
				}
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_ASSIGN_BSSID: {
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE);

			if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_ASSIGN_BSSID, messageelement->data, 0)) {
				return 0;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_DELETE_WLAN: {
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE);

			if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_DELETE_WLAN, messageelement->data, 0)) {
				return 0;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL: {
			struct capwap_array* directsequencecontrolarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < directsequencecontrolarray->count; i++) {
				if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL, *(struct capwap_80211_directsequencecontrol_element**)capwap_array_get_item_pointer(directsequencecontrolarray, i), 0)) {
					return 0;
				}
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_IE: {
			struct capwap_array* iearray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < iearray->count; i++) {
				if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_IE, *(struct capwap_80211_ie_element**)capwap_array_get_item_pointer(iearray, i), 0)) {
					return 0;
				}
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_MACOPERATION: {
			struct capwap_array* macoperationarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < macoperationarray->count; i++) {
				if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_MACOPERATION, *(struct capwap_80211_macoperation_element**)capwap_array_get_item_pointer(macoperationarray, i), 0)) {
					return 0;
				}
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES: {
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE);

			if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES, messageelement->data, 0)) {
				return 0;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY: {
			struct capwap_array* multidomaincapabilityarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < multidomaincapabilityarray->count; i++) {
				if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY, *(struct capwap_80211_multidomaincapability_element**)capwap_array_get_item_pointer(multidomaincapabilityarray, i), 0)) {
					return 0;
				}
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_OFDMCONTROL: {
			struct capwap_array* ofdmcontrolarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < ofdmcontrolarray->count; i++) {
				if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_OFDMCONTROL, *(struct capwap_80211_ofdmcontrol_element**)capwap_array_get_item_pointer(ofdmcontrolarray, i), 0)) {
					return 0;
				}
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_RATESET: {
			struct capwap_array* ratesetarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < ratesetarray->count; i++) {
				if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_RATESET, *(struct capwap_80211_rateset_element**)capwap_array_get_item_pointer(ratesetarray, i), 0)) {
					return 0;
				}
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT: {
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE);

			if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT, messageelement->data, 0)) {
				return 0;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_STATISTICS: {
			struct capwap_array* statisticsarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < statisticsarray->count; i++) {
				if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_STATISTICS, *(struct capwap_80211_statistics_element**)capwap_array_get_item_pointer(statisticsarray, i), 0)) {
					return 0;
				}
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_SUPPORTEDRATES: {
			struct capwap_array* supportedratesarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < supportedratesarray->count; i++) {
				if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_SUPPORTEDRATES, *(struct capwap_80211_supportedrates_element**)capwap_array_get_item_pointer(supportedratesarray, i), 0)) {
					return 0;
				}
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_TXPOWER: {
			struct capwap_array* txpowerarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < txpowerarray->count; i++) {
				if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_TXPOWER, *(struct capwap_80211_txpower_element**)capwap_array_get_item_pointer(txpowerarray, i), 0)) {
					return 0;
				}
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_TXPOWERLEVEL: {
			struct capwap_array* txpowerlevelarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < txpowerlevelarray->count; i++) {
				if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_TXPOWERLEVEL, *(struct capwap_80211_txpowerlevel_element**)capwap_array_get_item_pointer(txpowerlevelarray, i), 0)) {
					return 0;
				}
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_UPDATE_WLAN: {
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE);

			if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_UPDATE_WLAN, messageelement->data, 0)) {
				return 0;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_WTP_QOS: {
			struct capwap_array* wtpqosarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < wtpqosarray->count; i++) {
				if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_WTP_QOS, *(struct capwap_80211_wtpqos_element**)capwap_array_get_item_pointer(wtpqosarray, i), 0)) {
					return 0;
				}
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_WTP_RADIO_CONF: {
			struct capwap_array* wtpradioconfarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < wtpradioconfarray->count; i++) {
				if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_WTP_RADIO_CONF, *(struct capwap_80211_wtpradioconf_element**)capwap_array_get_item_pointer(wtpradioconfarray, i), 0)) {
					return 0;
				}
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM: {
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_SINGLE);

			if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM, messageelement->data, 0)) {
				return 0;
			}

			break;
		}

		case CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION: {
			struct capwap_array* wtpradioinformationarray = (struct capwap_array*)messageelement->data;
			ASSERT(messageelement->category == CAPWAP_MESSAGE_ELEMENT_ARRAY);

			for (i = 0; i < wtpradioinformationarray->count; i++) {
				if (!ac_json_ieee80211_addmessageelement(wtpradio, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION, *(struct capwap_80211_wtpradioinformation_element**)capwap_array_get_item_pointer(wtpradioinformationarray, i), 0)) {
					return 0;
				}
			}

			break;
		}
	}

	return 1;
}

/* */
int ac_json_ieee80211_parsingjson(struct ac_json_ieee80211_wtpradio* wtpradio, struct json_object* jsonroot) {
	return 1;
}

/* */
struct json_object* ac_json_ieee80211_getjson(struct ac_json_ieee80211_wtpradio* wtpradio) {
	int i;
	struct json_object* jsonarray;
	struct json_object* jsonitems;
	struct json_object* jsonitem;

	ASSERT(wtpradio != NULL);

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
			/* TODO */
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
			/* TODO */
		}

		if (item->deletewlan) {
			/* TODO */
		}

		if (item->directsequencecontrol) {
			jsonitem = json_object_new_object();
			json_object_object_add(jsonitem, "CurrentChan", json_object_new_int((int)item->directsequencecontrol->currentchannel));
			json_object_object_add(jsonitem, "CurrentCCA", json_object_new_int((int)item->directsequencecontrol->currentcca));
			json_object_object_add(jsonitem, "EnergyDetectThreshold", json_object_new_int((int)item->directsequencecontrol->enerydetectthreshold));
			json_object_object_add(jsonitems, "IEEE80211DirectSequenceControl", jsonitem);
		}

		if (item->iearray) {
			/* TODO */
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
			/* TODO */
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
			struct json_object* jsonrates;

			jsonrates = json_object_new_array();
			for (i = 0; i < item->rateset->ratesetcount; i++) {
				json_object_array_add(jsonrates, json_object_new_int((int)item->rateset->rateset[i]));
			}

			json_object_object_add(jsonitems, "IEEE80211Rateset", jsonrates);
		}

		if (item->rsnaerrorreport) {
			/* TODO */
		}

		if (item->statistics) {
			/* TODO */
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
			/* TODO */
		}

		if (item->wtpqos) {
			/* TODO */
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
			/* TODO */
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

/* */
void ac_json_ieee80211_buildpacket(struct ac_json_ieee80211_wtpradio* wtpradio, struct capwap_packet_txmng* txmngpacket) {
	int i, j;

	ASSERT(wtpradio != NULL);
	ASSERT(txmngpacket != NULL);

	for (i = 0; i < RADIOID_MAX_COUNT; i++) {
		struct ac_json_ieee80211_item* item = &wtpradio->items[i];

		if (item->valid) {
			if (item->addwlan) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_ADD_WLAN, item->addwlan);
			}

			if (item->antenna) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_ANTENNA, item->antenna);
			}

			if (item->assignbssid) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_ASSIGN_BSSID, item->assignbssid);
			}

			if (item->deletewlan) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_DELETE_WLAN, item->deletewlan);
			}

			if (item->directsequencecontrol) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL, item->directsequencecontrol);
			}

			if (item->iearray) {
				for (j = 0; j < item->iearray->count; j++) {
					capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_IE, *(struct capwap_80211_ie_element**)capwap_array_get_item_pointer(item->iearray, j));
				}
			}

			if (item->macoperation) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_MACOPERATION, item->macoperation);
			}

			if (item->miccountermeasures) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES, item->miccountermeasures);
			}

			if (item->multidomaincapability) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY, item->multidomaincapability);
			}

			if (item->ofdmcontrol) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_OFDMCONTROL, item->ofdmcontrol);
			}

			if (item->rateset) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_RATESET, item->rateset);
			}

			if (item->rsnaerrorreport) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT, item->rsnaerrorreport);
			}

			if (item->statistics) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_STATISTICS, item->statistics);
			}

			if (item->supportedrates) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_SUPPORTEDRATES, item->supportedrates);
			}

			if (item->txpower) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_TXPOWER, item->txpower);
			}

			if (item->txpowerlevel) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_TXPOWERLEVEL, item->txpowerlevel);
			}

			if (item->updatewlan) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_UPDATE_WLAN, item->updatewlan);
			}

			if (item->wtpqos) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_WTP_QOS, item->wtpqos);
			}

			if (item->wtpradioconf) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_WTP_RADIO_CONF, item->wtpradioconf);
			}

			if (item->wtpradiofailalarm) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM, item->wtpradiofailalarm);
			}

			if (item->wtpradioinformation) {
				capwap_packet_txmng_add_message_element(txmngpacket, CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION, item->wtpradioinformation);
			}
		}
	}
}
