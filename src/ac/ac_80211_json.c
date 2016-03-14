#include "ac.h"
#include "ac_json.h"

/* */
static struct ac_json_ieee80211_ops* ac_json_80211_message_elements[] = {
	/* CAPWAP_ELEMENT_80211_ADD_WLAN */ &ac_json_80211_addwlan_ops,
	/* CAPWAP_ELEMENT_80211_ANTENNA */ &ac_json_80211_antenna_ops,
	/* CAPWAP_ELEMENT_80211_ASSIGN_BSSID */ &ac_json_80211_assignbssid_ops,
	/* CAPWAP_ELEMENT_80211_DELETE_WLAN */ &ac_json_80211_deletewlan_ops,
	/* CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL */ &ac_json_80211_directsequencecontrol_ops,
	/* CAPWAP_ELEMENT_80211_IE */ &ac_json_80211_ie_ops,
	/* CAPWAP_ELEMENT_80211_MACOPERATION */ &ac_json_80211_macoperation_ops,
	/* CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES */ &ac_json_80211_miccountermeasures_ops,
	/* CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY */ &ac_json_80211_multidomaincapability_ops,
	/* CAPWAP_ELEMENT_80211_OFDMCONTROL */ &ac_json_80211_ofdmcontrol_ops,
	/* CAPWAP_ELEMENT_80211_RATESET */ &ac_json_80211_rateset_ops,
	/* CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT */ &ac_json_80211_rsnaerrorreport_ops,
	/* CAPWAP_ELEMENT_80211_STATION */ NULL,
	/* CAPWAP_ELEMENT_80211_STATION_QOS_PROFILE */ NULL,
	/* CAPWAP_ELEMENT_80211_STATION_SESSION_KEY_PROFILE */ NULL,
	/* CAPWAP_ELEMENT_80211_STATISTICS */ &ac_json_80211_statistics_ops,
	/* CAPWAP_ELEMENT_80211_SUPPORTEDRATES */ &ac_json_80211_supportedrates_ops,
	/* CAPWAP_ELEMENT_80211_TXPOWER */ &ac_json_80211_txpower_ops,
	/* CAPWAP_ELEMENT_80211_TXPOWERLEVEL */ &ac_json_80211_txpowerlevel_ops,
	/* CAPWAP_ELEMENT_80211_UPDATE_STATION_QOS */ NULL,
	/* CAPWAP_ELEMENT_80211_UPDATE_WLAN */ &ac_json_80211_updatewlan_ops,
	/* CAPWAP_ELEMENT_80211_WTP_QOS */ &ac_json_80211_wtpqos_ops,
	/* CAPWAP_ELEMENT_80211_WTP_RADIO_CONF */ &ac_json_80211_wtpradioconf_ops,
	/* CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM */ &ac_json_80211_wtpradiofailalarm_ops,
	/* CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION */ &ac_json_80211_wtpradioinformation_ops
};

/* */
static struct ac_json_ieee80211_ops *
ac_json_80211_getops_by_capwaptype(const struct capwap_message_element_id type)
{
	int i;

	for (i = 0; i < CAPWAP_80211_MESSAGE_ELEMENTS_COUNT; i++) {
		if (ac_json_80211_message_elements[i] &&
		    memcmp(&ac_json_80211_message_elements[i]->type, &type, sizeof(type)) == 0)
			return ac_json_80211_message_elements[i];
	}

	return NULL;
}

/* */
static struct ac_json_ieee80211_ops* ac_json_80211_getops_by_jsontype(char* type)
{
	int i;

	for (i = 0; i < CAPWAP_80211_MESSAGE_ELEMENTS_COUNT; i++) {
		if (ac_json_80211_message_elements[i] &&
		    strcmp(ac_json_80211_message_elements[i]->json_type, type) == 0)
			return ac_json_80211_message_elements[i];
	}

	return NULL;
}

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
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_ADD_WLAN)->free(item->addwlan);
			}

			if (item->antenna) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_ANTENNA)->free(item->antenna);
			}

			if (item->assignbssid) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_ASSIGN_BSSID)->free(item->assignbssid);
			}

			if (item->deletewlan) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_DELETE_WLAN)->free(item->deletewlan);
			}

			if (item->directsequencecontrol) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL)->free(item->directsequencecontrol);
			}

			if (item->iearray) {
				const struct capwap_message_elements_ops* ieops = capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_IE);

				for (j = 0; j < item->iearray->count; j++) {
					ieops->free(*(struct capwap_80211_ie_element**)capwap_array_get_item_pointer(item->iearray, j));
				}

				capwap_array_free(item->iearray);
			}

			if (item->macoperation) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_MACOPERATION)->free(item->macoperation);
			}

			if (item->miccountermeasures) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES)->free(item->miccountermeasures);
			}

			if (item->multidomaincapability) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY)->free(item->multidomaincapability);
			}

			if (item->ofdmcontrol) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_OFDMCONTROL)->free(item->ofdmcontrol);
			}

			if (item->rateset) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_RATESET)->free(item->rateset);
			}

			if (item->rsnaerrorreport) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT)->free(item->rsnaerrorreport);
			}

			if (item->statistics) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_STATISTICS)->free(item->statistics);
			}

			if (item->supportedrates) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_SUPPORTEDRATES)->free(item->supportedrates);
			}

			if (item->txpower) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_TXPOWER)->free(item->txpower);
			}

			if (item->txpowerlevel) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_TXPOWERLEVEL)->free(item->txpowerlevel);
			}

			if (item->updatewlan) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_UPDATE_WLAN)->free(item->updatewlan);
			}

			if (item->wtpqos) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTP_QOS)->free(item->wtpqos);
			}

			if (item->wtpradioconf) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTP_RADIO_CONF)->free(item->wtpradioconf);
			}

			if (item->wtpradiofailalarm) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM)->free(item->wtpradiofailalarm);
			}

			if (item->wtpradioinformation) {
				capwap_get_message_element_ops(CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION)->free(item->wtpradioinformation);
			}
		}
	}
}

/* */
int ac_json_ieee80211_addmessageelement(struct ac_json_ieee80211_wtpradio *wtpradio,
					const struct capwap_message_element_id id,
					void *data, int overwrite)
{
	struct ac_json_ieee80211_ops* ops;

	ASSERT(wtpradio != NULL);
	ASSERT(IS_80211_MESSAGE_ELEMENTS(id));
	ASSERT(data != NULL);

	/* */
 	ops = ac_json_80211_getops_by_capwaptype(id);
 	if (!ops)
 		return 0;

	return ops->add_message_element(wtpradio, data, overwrite);
}

/* */
int ac_json_ieee80211_parsingmessageelement(struct ac_json_ieee80211_wtpradio* wtpradio, struct capwap_message_element_itemlist* messageelement) {
	int i;

	ASSERT(wtpradio != NULL);
	ASSERT(messageelement != NULL);
	ASSERT(IS_80211_MESSAGE_ELEMENTS(messageelement->id));

	switch (messageelement->category) {
	case CAPWAP_MESSAGE_ELEMENT_SINGLE:
		if (!ac_json_ieee80211_addmessageelement(wtpradio, messageelement->id,
							 messageelement->data, 0))
			return 0;
		break;

	case CAPWAP_MESSAGE_ELEMENT_ARRAY: {
		struct capwap_array* items =
			(struct capwap_array*)messageelement->data;

		for (i = 0; i < items->count; i++)
			if (!ac_json_ieee80211_addmessageelement(wtpradio, messageelement->id,
								 *(void**)capwap_array_get_item_pointer(items, i), 0))
				return 0;
		break;
	}

	default:
		return 0;
	}

	return 1;
}

/* */
int ac_json_ieee80211_parsingjson(struct ac_json_ieee80211_wtpradio* wtpradio, struct json_object* jsonroot) {
	int i;
	int length;

	ASSERT(wtpradio != NULL);
	ASSERT(jsonroot != NULL);

	if (json_object_get_type(jsonroot) != json_type_array) {
		return 0;
	}

	/* */
	length = json_object_array_length(jsonroot);
	for (i = 0; i < length; i++) {
		struct json_object* jsonitem;
		struct json_object* jsonradio = json_object_array_get_idx(jsonroot, i);

		/* Get RadioID */
		jsonitem = compat_json_object_object_get(jsonradio, "RadioID");
		if (jsonitem && (json_object_get_type(jsonitem) == json_type_int)) {
			int radioid = json_object_get_int(jsonitem);
			if (IS_VALID_RADIOID(radioid)) {
				struct lh_entry* entry;

				/* Parsing every entry */
				for(entry = json_object_get_object(jsonradio)->head; entry != NULL; entry = entry->next) {
					struct ac_json_ieee80211_ops* ops = ac_json_80211_getops_by_jsontype((char*)entry->k);		/* Retrieve JSON handler */
					if (ops) {
						void* data = ops->create((struct json_object*)entry->v, radioid);
						if (data) {
							/* Message element complete */
							ac_json_ieee80211_addmessageelement(wtpradio, ops->type, data, 1);

							/* Free resource */
							capwap_get_message_element_ops(ops->type)->free(data);
						}
					}
				}
			}
		}
	}

	return 1;
}

/* */
struct json_object* ac_json_ieee80211_getjson(struct ac_json_ieee80211_wtpradio* wtpradio) {
	int i;
	struct json_object* jsonarray;
	struct json_object* jsonitems;

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
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_ADD_WLAN)->create_json(jsonitems, item->addwlan);
		}

		if (item->antenna) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_ANTENNA)->create_json(jsonitems, item->antenna);
		}

		if (item->assignbssid) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_ASSIGN_BSSID)->create_json(jsonitems, item->assignbssid);
		}

		if (item->deletewlan) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_DELETE_WLAN)->create_json(jsonitems, item->deletewlan);
		}

		if (item->directsequencecontrol) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL)->create_json(jsonitems, item->directsequencecontrol);
		}

		if (item->iearray) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_IE)->create_json(jsonitems, item->iearray);
		}

		if (item->macoperation) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_MACOPERATION)->create_json(jsonitems, item->macoperation);
		}

		if (item->miccountermeasures) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES)->create_json(jsonitems, item->miccountermeasures);
		}

		if (item->multidomaincapability) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY)->create_json(jsonitems, item->multidomaincapability);
		}

		if (item->ofdmcontrol) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_OFDMCONTROL)->create_json(jsonitems, item->ofdmcontrol);
		}

		if (item->rateset) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_RATESET)->create_json(jsonitems, item->rateset);
		}

		if (item->rsnaerrorreport) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_RSNA_ERROR_REPORT)->create_json(jsonitems, item->rsnaerrorreport);
		}

		if (item->statistics) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_STATISTICS)->create_json(jsonitems, item->statistics);
		}

		if (item->supportedrates) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_SUPPORTEDRATES)->create_json(jsonitems, item->supportedrates);
		}

		if (item->txpower) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_TXPOWER)->create_json(jsonitems, item->txpower);
		}

		if (item->txpowerlevel) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_TXPOWERLEVEL)->create_json(jsonitems, item->txpowerlevel);
		}

		if (item->updatewlan) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_UPDATE_WLAN)->create_json(jsonitems, item->updatewlan);
		}

		if (item->wtpqos) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_WTP_QOS)->create_json(jsonitems, item->wtpqos);
		}

		if (item->wtpradioconf) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_WTP_RADIO_CONF)->create_json(jsonitems, item->wtpradioconf);
		}

		if (item->wtpradiofailalarm) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_WTP_RADIO_FAIL_ALARM)->create_json(jsonitems, item->wtpradiofailalarm);
		}

		if (item->wtpradioinformation) {
			ac_json_80211_getops_by_capwaptype(CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION)->create_json(jsonitems, item->wtpradioinformation);
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
