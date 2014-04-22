#include "wtp.h"
#include "capwap_hash.h"
#include "capwap_list.h"
#include "wtp_radio.h"
#include "wtp_dfa.h"

/* */
#define WTP_UPDATE_FREQUENCY_DSSS				1
#define WTP_UPDATE_FREQUENCY_OFDM				2
#define WTP_UPDATE_RATES						3
#define WTP_UPDATE_CONFIGURATION				4

struct wtp_update_configuration_item {
	int type;
	struct wtp_radio* radio;
};

/* */
static int wtp_radio_configure_phy(struct wtp_radio* radio) {
	/* Default rate set is all supported rate */
	if (radio->radioid != radio->rateset.radioid) {
		if (radio->radioid != radio->supportedrates.radioid) {
			return -1;			/* Supported rate not set */
		}

		/* */
		radio->rateset.radioid = radio->radioid;
		radio->rateset.ratesetcount = radio->supportedrates.supportedratescount;
		memcpy(radio->rateset.rateset, radio->supportedrates.supportedrates, CAPWAP_RATESET_MAXLENGTH);

		/* Update rates */
		if (wifi_device_updaterates(radio->devicehandle, radio->rateset.rateset, radio->rateset.ratesetcount)) {
			return -1;
		}
	}

	/* Check channel radio */
	if (radio->radioid != radio->radioinformation.radioid) {
		return -1;
	} else if (radio->radioid != radio->radioconfig.radioid) {
		return -1;
	} else if ((!radio->directsequencecontrol.radioid && !radio->ofdmcontrol.radioid) || ((radio->directsequencecontrol.radioid == radio->radioid) && (radio->ofdmcontrol.radioid == radio->radioid))) {
		return -1;		/* Only one from DSSS and OFDM can select */
	} else if ((radio->radioid == radio->directsequencecontrol.radioid) && !(radio->radioinformation.radiotype & (CAPWAP_RADIO_TYPE_80211B | CAPWAP_RADIO_TYPE_80211G))) {
		return -1;
	} else if ((radio->radioid == radio->ofdmcontrol.radioid) && !(radio->radioinformation.radiotype & CAPWAP_RADIO_TYPE_80211A)) {
		return -1;
	}

	return 0;
}

/* */
static void wtp_radio_send_frame_to_ac(void* param, const struct ieee80211_header_mgmt* mgmt, int mgmtlength) {
	struct wtp_radio_wlan* wlan = (struct wtp_radio_wlan*)param;

	ASSERT(param != NULL);
	ASSERT(mgmt != NULL);
	ASSERT(mgmtlength >= sizeof(struct ieee80211_header));

	/* Send packet */
	wtp_send_data_packet(wlan->radio->radioid, wlan->wlanid, (const uint8_t*)mgmt, mgmtlength, 1);
}

/* */
static unsigned long wtp_radio_acl_item_gethash(const void* key, unsigned long keysize, unsigned long hashsize) {
	uint8_t* macaddress = (uint8_t*)key;

	ASSERT(keysize == ETH_ALEN);

	return (((unsigned long)macaddress[3] ^ (unsigned long)macaddress[4] ^ (unsigned long)macaddress[5]) >> 2);
}

/* */
void wtp_radio_init(void) {
	g_wtp.radios = capwap_array_create(sizeof(struct wtp_radio), 0, 1);

	g_wtp.defaultaclstations = WTP_RADIO_ACL_STATION_ALLOW;
	g_wtp.aclstations = capwap_hash_create(WTP_RADIO_ACL_HASH_SIZE, WTP_RADIO_ACL_KEY_SIZE, wtp_radio_acl_item_gethash, NULL, NULL);
}

/* */
void wtp_radio_close(void) {
	int i;
	struct capwap_list_item* itemwlan;

	ASSERT(g_wtp.radios != NULL);

	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio* radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);

		if (radio->antenna.selections) {
			capwap_array_free(radio->antenna.selections);
		}

		if (radio->wlan) {
			for (itemwlan = radio->wlan->first; itemwlan != NULL; itemwlan = itemwlan->next) {
				struct wtp_radio_wlan* wlan = (struct wtp_radio_wlan*)itemwlan->item;

				/* Destroy BSS interface */
				if (wlan->wlanhandle) {
					wifi_wlan_destroy(wlan->wlanhandle);
				}
			}

			capwap_list_free(radio->wlan);
		}

		if (radio->wlanpool) {
			for (itemwlan = radio->wlanpool->first; itemwlan != NULL; itemwlan = itemwlan->next) {
				struct wtp_radio_wlanpool* wlanpool = (struct wtp_radio_wlanpool*)itemwlan->item;

				/* Destroy BSS interface */
				if (wlanpool->wlanhandle) {
					wifi_wlan_destroy(wlanpool->wlanhandle);
				}
			}

			capwap_list_free(radio->wlanpool);
		}
	}

	capwap_array_resize(g_wtp.radios, 0);
}

/* */
void wtp_radio_free(void) {
	ASSERT(g_wtp.radios != NULL);

	if (g_wtp.radios->count > 0) {
		wtp_radio_close();
	}

	capwap_array_free(g_wtp.radios);
	capwap_hash_free(g_wtp.aclstations);
}

/* */
int wtp_radio_setconfiguration(struct capwap_parsed_packet* packet) {
	int i;
	int result = 0;
	unsigned short binding;
	struct capwap_array* messageelements;
	struct capwap_array* updateitems;
	struct wtp_update_configuration_item* item;

	ASSERT(packet != NULL);

	/* */
	updateitems = capwap_array_create(sizeof(struct wtp_update_configuration_item), 0, 1);

	/* */
	binding = GET_WBID_HEADER(packet->rxmngpacket->header);
	if (binding == CAPWAP_WIRELESS_BINDING_IEEE80211) {
		struct wtp_radio* radio;
		struct capwap_list_item* search;

		/* Set radio configuration and invalidate the old values */
		search = packet->messages->first;
		while (search) {
			struct capwap_message_element_itemlist* messageelement = (struct capwap_message_element_itemlist*)search->item;

			/* Parsing only IEEE 802.11 message element */
			if (IS_80211_MESSAGE_ELEMENTS(messageelement->type)) {
				switch (messageelement->type) {
					case CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL: {
						messageelements = (struct capwap_array*)messageelement->data;
						if (messageelements && (messageelements->count > 0)) {
							struct capwap_80211_directsequencecontrol_element* directsequencecontrol;

							for (i = 0; i < messageelements->count; i++) {
								directsequencecontrol = *(struct capwap_80211_directsequencecontrol_element**)capwap_array_get_item_pointer(messageelements, i);
								radio = wtp_radio_get_phy(directsequencecontrol->radioid);
								if (radio) {
									memset(&radio->directsequencecontrol, 0, sizeof(struct capwap_80211_directsequencecontrol_element));
									memset(&radio->ofdmcontrol, 0, sizeof(struct capwap_80211_ofdmcontrol_element));
								}
							}
						}

						break;
					}

					case CAPWAP_ELEMENT_80211_OFDMCONTROL: {
						messageelements = (struct capwap_array*)messageelement->data;
						if (messageelements && (messageelements->count > 0)) {
							struct capwap_80211_ofdmcontrol_element* ofdmcontrol;

							for (i = 0; i < messageelements->count; i++) {
								ofdmcontrol = *(struct capwap_80211_ofdmcontrol_element**)capwap_array_get_item_pointer(messageelements, i);
								radio = wtp_radio_get_phy(ofdmcontrol->radioid);
								if (radio) {
									memset(&radio->directsequencecontrol, 0, sizeof(struct capwap_80211_directsequencecontrol_element));
									memset(&radio->ofdmcontrol, 0, sizeof(struct capwap_80211_ofdmcontrol_element));
								}
							}
						}

						break;
					}

					case CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION: {
						messageelements = (struct capwap_array*)messageelement->data;
						if (messageelements && (messageelements->count > 0)) {
							struct capwap_80211_wtpradioinformation_element* radioinformation;

							for (i = 0; i < messageelements->count; i++) {
								radioinformation = *(struct capwap_80211_wtpradioinformation_element**)capwap_array_get_item_pointer(messageelements, i);
								radio = wtp_radio_get_phy(radioinformation->radioid);
								if (radio && (radio->radioid == radioinformation->radioid)) {
									memcpy(&radio->radioinformation, radioinformation, sizeof(struct capwap_80211_wtpradioinformation_element));
								}
							}
						}

						break;
					}
				}
			}

			/* Next */
			search = search->next;
		}

		/* Update new values */
		search = packet->messages->first;
		while (search) {
			struct capwap_message_element_itemlist* messageelement = (struct capwap_message_element_itemlist*)search->item;

			/* Parsing only IEEE 802.11 message element */
			if (IS_80211_MESSAGE_ELEMENTS(messageelement->type)) {
				switch (messageelement->type) {
					case CAPWAP_ELEMENT_80211_ANTENNA: {
						messageelements = (struct capwap_array*)messageelement->data;
						if (messageelements && (messageelements->count > 0)) {
							struct capwap_80211_antenna_element* antenna;

							for (i = 0; i < messageelements->count; i++) {
								antenna = *(struct capwap_80211_antenna_element**)capwap_array_get_item_pointer(messageelements, i);
								radio = wtp_radio_get_phy(antenna->radioid);
								if (radio && (radio->radioid == antenna->radioid)) {
									capwap_element_80211_antenna_copy(&radio->antenna, antenna);
								}
							}
						}

						break;
					}

					case CAPWAP_ELEMENT_80211_MACOPERATION: {
						messageelements = (struct capwap_array*)messageelement->data;
						if (messageelements && (messageelements->count > 0)) {
							struct capwap_80211_macoperation_element* macoperation;

							for (i = 0; i < messageelements->count; i++) {
								macoperation = *(struct capwap_80211_macoperation_element**)capwap_array_get_item_pointer(messageelements, i);
								radio = wtp_radio_get_phy(macoperation->radioid);
								if (radio && (radio->radioid == macoperation->radioid)) {
									memcpy(&radio->macoperation, macoperation, sizeof(struct capwap_80211_macoperation_element));
								}
							}
						}

						break;
					}

					case CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY: {
						messageelements = (struct capwap_array*)messageelement->data;
						if (messageelements && (messageelements->count > 0)) {
							struct capwap_80211_multidomaincapability_element* multidomaincapability;

							for (i = 0; i < messageelements->count; i++) {
								multidomaincapability = *(struct capwap_80211_multidomaincapability_element**)capwap_array_get_item_pointer(messageelements, i);
								radio = wtp_radio_get_phy(multidomaincapability->radioid);
								if (radio && (radio->radioid == multidomaincapability->radioid)) {
									memcpy(&radio->multidomaincapability, multidomaincapability, sizeof(struct capwap_80211_multidomaincapability_element));
								}
							}
						}

						break;
					}

					case CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL: {
						messageelements = (struct capwap_array*)messageelement->data;
						if (messageelements && (messageelements->count > 0)) {
							struct capwap_80211_directsequencecontrol_element* directsequencecontrol;

							for (i = 0; i < messageelements->count; i++) {
								directsequencecontrol = *(struct capwap_80211_directsequencecontrol_element**)capwap_array_get_item_pointer(messageelements, i);
								radio = wtp_radio_get_phy(directsequencecontrol->radioid);
								if (radio && (radio->radioid == directsequencecontrol->radioid)) {
									if (radio->radioinformation.radiotype & (CAPWAP_RADIO_TYPE_80211B | CAPWAP_RADIO_TYPE_80211G)) {
										memcpy(&radio->directsequencecontrol, directsequencecontrol, sizeof(struct capwap_80211_directsequencecontrol_element));

										/* Pending change radio channel */
										item = (struct wtp_update_configuration_item*)capwap_array_get_item_pointer(updateitems, updateitems->count);
										item->type = WTP_UPDATE_FREQUENCY_DSSS;
										item->radio = radio;
									}
								}
							}
						}

						break;
					}

					case CAPWAP_ELEMENT_80211_OFDMCONTROL: {
						messageelements = (struct capwap_array*)messageelement->data;
						if (messageelements && (messageelements->count > 0)) {
							struct capwap_80211_ofdmcontrol_element* ofdmcontrol;

							for (i = 0; i < messageelements->count; i++) {
								ofdmcontrol = *(struct capwap_80211_ofdmcontrol_element**)capwap_array_get_item_pointer(messageelements, i);
								radio = wtp_radio_get_phy(ofdmcontrol->radioid);
								if (radio && (radio->radioid == ofdmcontrol->radioid)) {
									if (radio->radioinformation.radiotype & CAPWAP_RADIO_TYPE_80211A) {
										memcpy(&radio->ofdmcontrol, ofdmcontrol, sizeof(struct capwap_80211_ofdmcontrol_element));

										/* Pending change radio channel */
										item = (struct wtp_update_configuration_item*)capwap_array_get_item_pointer(updateitems, updateitems->count);
										item->type = WTP_UPDATE_FREQUENCY_OFDM;
										item->radio = radio;
									}
								}
							}
						}

						break;
					}

					case CAPWAP_ELEMENT_80211_RATESET: {
						messageelements = (struct capwap_array*)messageelement->data;
						if (messageelements && (messageelements->count > 0)) {
							struct capwap_80211_rateset_element* rateset;

							for (i = 0; i < messageelements->count; i++) {
								rateset = *(struct capwap_80211_rateset_element**)capwap_array_get_item_pointer(messageelements, i);
								radio = wtp_radio_get_phy(rateset->radioid);
								if (radio && (radio->radioid == rateset->radioid)) {
									memcpy(&radio->rateset, rateset, sizeof(struct capwap_80211_rateset_element));

									/* Pending change radio rates */
									item = (struct wtp_update_configuration_item*)capwap_array_get_item_pointer(updateitems, updateitems->count);
									item->type = WTP_UPDATE_RATES;
									item->radio = radio;
								}
							}
						}

						break;
					}

					case CAPWAP_ELEMENT_80211_SUPPORTEDRATES: {
						messageelements = (struct capwap_array*)messageelement->data;
						if (messageelements && (messageelements->count > 0)) {
							struct capwap_80211_supportedrates_element* supportedrates;

							for (i = 0; i < messageelements->count; i++) {
								supportedrates = *(struct capwap_80211_supportedrates_element**)capwap_array_get_item_pointer(messageelements, i);
								radio = wtp_radio_get_phy(supportedrates->radioid);
								if (radio && (radio->radioid == supportedrates->radioid)) {
									memcpy(&radio->supportedrates, supportedrates, sizeof(struct capwap_80211_supportedrates_element));
								}
							}
						}

						break;
					}

					case CAPWAP_ELEMENT_80211_TXPOWER: {
						messageelements = (struct capwap_array*)messageelement->data;
						if (messageelements && (messageelements->count > 0)) {
							struct capwap_80211_txpower_element* txpower;

							for (i = 0; i < messageelements->count; i++) {
								txpower = *(struct capwap_80211_txpower_element**)capwap_array_get_item_pointer(messageelements, i);
								radio = wtp_radio_get_phy(txpower->radioid);
								if (radio && (radio->radioid == txpower->radioid)) {
									memcpy(&radio->txpower, txpower, sizeof(struct capwap_80211_txpower_element));
								}
							}
						}

						break;
					}

					case CAPWAP_ELEMENT_80211_WTP_QOS: {
						messageelements = (struct capwap_array*)messageelement->data;
						if (messageelements && (messageelements->count > 0)) {
							struct capwap_80211_wtpqos_element* qos;

							for (i = 0; i < messageelements->count; i++) {
								qos = *(struct capwap_80211_wtpqos_element**)capwap_array_get_item_pointer(messageelements, i);
								radio = wtp_radio_get_phy(qos->radioid);
								if (radio && (radio->radioid == qos->radioid)) {
									memcpy(&radio->qos, qos, sizeof(struct capwap_80211_wtpqos_element));
								}
							}
						}

						break;
					}

					case CAPWAP_ELEMENT_80211_WTP_RADIO_CONF: {
						messageelements = (struct capwap_array*)messageelement->data;
						if (messageelements && (messageelements->count > 0)) {
							struct capwap_80211_wtpradioconf_element* radioconfig;

							for (i = 0; i < messageelements->count; i++) {
								radioconfig = *(struct capwap_80211_wtpradioconf_element**)capwap_array_get_item_pointer(messageelements, i);
								radio = wtp_radio_get_phy(radioconfig->radioid);
								if (radio && (radio->radioid == radioconfig->radioid)) {
									memcpy(&radio->radioconfig, radioconfig, sizeof(struct capwap_80211_wtpradioconf_element));

									/* Pending change radio configuration */
									item = (struct wtp_update_configuration_item*)capwap_array_get_item_pointer(updateitems, updateitems->count);
									item->type = WTP_UPDATE_CONFIGURATION;
									item->radio = radio;
								}
							}
						}

						break;
					}
				}
			}

			/* Next */
			search = search->next;
		}
	}

	/* Update radio frequency */
	for (i = 0; (i < updateitems->count) && !result; i++) {
		struct wtp_update_configuration_item* item = (struct wtp_update_configuration_item*)capwap_array_get_item_pointer(updateitems, i);

		switch (item->type) {
			case WTP_UPDATE_FREQUENCY_DSSS: {
				result = wifi_device_setfrequency(item->radio->devicehandle, WIFI_BAND_2GHZ, item->radio->radioinformation.radiotype, item->radio->directsequencecontrol.currentchannel);
				break;
			}

			case WTP_UPDATE_FREQUENCY_OFDM: {
				result = wifi_device_setfrequency(item->radio->devicehandle, WIFI_BAND_5GHZ, item->radio->radioinformation.radiotype, item->radio->ofdmcontrol.currentchannel);
				break;
			}
		}
	}

	/* Update radio configuration */
	for (i = 0; (i < updateitems->count) && !result; i++) {
		struct wtp_update_configuration_item* item = (struct wtp_update_configuration_item*)capwap_array_get_item_pointer(updateitems, i);

		switch (item->type) {
			case WTP_UPDATE_RATES: {
				result = wifi_device_updaterates(item->radio->devicehandle, item->radio->rateset.rateset, item->radio->rateset.ratesetcount);
				break;
			}

			case WTP_UPDATE_CONFIGURATION: {
				struct device_setconfiguration_params params;

				memset(&params, 0, sizeof(struct device_setconfiguration_params));
				params.shortpreamble = ((item->radio->radioconfig.shortpreamble == CAPWAP_WTP_RADIO_CONF_SHORTPREAMBLE_ENABLE) ? 1 : 0);
				params.maxbssid = item->radio->radioconfig.maxbssid;
				params.dtimperiod = item->radio->radioconfig.dtimperiod;
				memcpy(params.bssid, item->radio->radioconfig.bssid, ETH_ALEN);
				params.beaconperiod = item->radio->radioconfig.beaconperiod;
				memcpy(params.country, item->radio->radioconfig.country, WIFI_COUNTRY_LENGTH);
				result = wifi_device_setconfiguration(item->radio->devicehandle, &params);
				break;
			}
		}
	}

	/* */
	capwap_array_free(updateitems);
	return result;
}

/* */
struct wtp_radio* wtp_radio_create_phy(void) {
	struct wtp_radio* radio;

	/* Create disabled radio */
	radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, g_wtp.radios->count);
	radio->radioid = (uint8_t)g_wtp.radios->count;
	radio->status = WTP_RADIO_DISABLED;

	/* Init configuration radio */
	radio->wlan = capwap_list_create();
	radio->wlanpool = capwap_list_create();
	radio->antenna.selections = capwap_array_create(sizeof(uint8_t), 0, 1);
	return radio;
}

/* */
struct wtp_radio* wtp_radio_get_phy(uint8_t radioid) {
	int i;

	/* Check */
	if (!IS_VALID_RADIOID(radioid)) {
		return NULL;
	}

	/* Retrieve radio */
	for (i = 0; i < g_wtp.radios->count; i++) {
		struct wtp_radio* radio = (struct wtp_radio*)capwap_array_get_item_pointer(g_wtp.radios, i);
		if (radioid == radio->radioid) {
			return radio;
		}
	}

	return NULL;
}

/* */
struct wtp_radio_wlan* wtp_radio_get_wlan(struct wtp_radio* radio, uint8_t wlanid) {
	struct capwap_list_item* itemwlan;

	ASSERT(radio != NULL);

	/* Check */
	if (!IS_VALID_WLANID(wlanid)) {
		return NULL;
	}

	/* Retrieve BSS */
	for (itemwlan = radio->wlan->first; itemwlan != NULL; itemwlan = itemwlan->next) {
		struct wtp_radio_wlan* wlan = (struct wtp_radio_wlan*)itemwlan->item;
		if (wlanid == wlan->wlanid) {
			return wlan;
		}
	}

	return NULL;
}

/* */
struct wtp_radio_wlan* wtp_radio_search_wlan(struct wtp_radio* radio, const uint8_t* bssid) {
	struct capwap_list_item* itemwlan;

	ASSERT(radio != NULL);
	ASSERT(bssid != NULL);

	/* Retrieve BSS */
	for (itemwlan = radio->wlan->first; itemwlan != NULL; itemwlan = itemwlan->next) {
		struct wtp_radio_wlan* wlan = (struct wtp_radio_wlan*)itemwlan->item;
		if (!memcmp(bssid, wlan->wlanhandle->address, MACADDRESS_EUI48_LENGTH)) {
			return wlan;
		}
	}

	return NULL;
}

/* */
void wtp_radio_update_fdevent(struct wtp_fds* fds) {
	int count;
	struct pollfd* fdsbuffer;

	ASSERT(fds != NULL);

	/* Retrieve number of File Descriptor Event */
	count = wifi_event_getfd(NULL, NULL, 0);
	if (count < 0) {
		return;
	}

	/* Resize poll */
	if (fds->eventscount != count) {
		fdsbuffer = (struct pollfd*)capwap_alloc(sizeof(struct pollfd) * (fds->fdsnetworkcount + count));
		if (fds->fdspoll && (fds->fdsnetworkcount > 0)) {
			memcpy(fdsbuffer, fds->fdspoll, sizeof(struct pollfd) * fds->fdsnetworkcount);
			capwap_free(fds->fdspoll);
		}

		fds->fdspoll = fdsbuffer;

		/* Events Callback */
		if (fds->events) {
			capwap_free(fds->events);
		}

		fds->events = (struct wifi_event*)((count > 0) ? capwap_alloc(sizeof(struct wifi_event) * count) : NULL);

		/* */
		fds->eventscount = count;
		fds->fdstotalcount = fds->fdsnetworkcount + count;
	}

	/* Retrieve File Descriptor Event */
	if (count > 0) {
		ASSERT(fds->fdspoll != NULL);
		wifi_event_getfd(&fds->fdspoll[fds->fdsnetworkcount], fds->events, fds->eventscount);
	}
}

/* */
void wtp_radio_receive_data_packet(uint8_t radioid, unsigned short binding, const uint8_t* frame, int length) {
	struct wtp_radio* radio;
	struct wtp_radio_wlan* wlan;

	ASSERT(frame != NULL);
	ASSERT(length > 0);

	/* Get radio */
	radio = wtp_radio_get_phy(radioid);
	if (!radio) {
		return;
	}

	if ((binding == CAPWAP_WIRELESS_BINDING_IEEE80211) && (length >= sizeof(struct ieee80211_header))) {
		const struct ieee80211_header* header = (const struct ieee80211_header*)frame;
		const uint8_t* bssid = ieee80211_get_bssid_addr(header);

		if (bssid) {
			wlan = wtp_radio_search_wlan(radio, bssid);
			if (wlan) {
				wifi_wlan_receive_ac_frame(wlan->wlanhandle, header, length);
			}
		}
	}

}

/* */
uint32_t wtp_radio_create_wlan(struct capwap_parsed_packet* packet, struct capwap_80211_assignbssid_element* bssid) {
	struct wtp_radio* radio;
	struct wtp_radio_wlan* wlan;
	struct wtp_radio_wlanpool* wlanpool;
	struct capwap_list_item* itemwlan;
	struct capwap_list_item* itemwlanpool;
	struct wlan_startap_params params;
	struct capwap_80211_addwlan_element* addwlan;

	ASSERT(packet != NULL);

	/* Get message elements */
	addwlan = (struct capwap_80211_addwlan_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_ADD_WLAN);
	if (!addwlan) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Get physical radio */
	radio = wtp_radio_get_phy(addwlan->radioid);
	if (!radio) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Check if virtual interface is already exist */
	wlan = wtp_radio_get_wlan(radio, addwlan->wlanid);
	if (wlan) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Verify exist interface into pool */
	if (!radio->wlanpool->first) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Prepare physical interface for create wlan */
	if (!radio->wlan->count) {
		if (wtp_radio_configure_phy(radio)) {
			return CAPWAP_RESULTCODE_FAILURE;
		}
	}

	/* Get interface from pool */
	itemwlanpool = capwap_itemlist_remove_head(radio->wlanpool);
	wlanpool = (struct wtp_radio_wlanpool*)itemwlanpool->item;

	/* Create interface used */
	itemwlan = capwap_itemlist_create(sizeof(struct wtp_radio_wlan));
	wlan = (struct wtp_radio_wlan*)itemwlan->item;
	wlan->wlanid = addwlan->wlanid;
	wlan->wlanhandle = wlanpool->wlanhandle;
	wlan->radio = wlanpool->radio;

	/* Wlan configuration */
	memset(&params, 0, sizeof(struct wlan_startap_params));
	params.send_frame = wtp_radio_send_frame_to_ac;
	params.send_frame_to_ac_cbparam = (void*)wlan;
	params.ssid = (const char*)addwlan->ssid;
	params.ssid_hidden = addwlan->suppressssid;
	params.capability = addwlan->capability;
	params.qos = addwlan->qos;
	params.authmode = addwlan->authmode;
	params.macmode = addwlan->macmode;
	params.tunnelmode = addwlan->tunnelmode;
	/* TODO (struct capwap_array*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_IE) */

	/* Start AP */
	if (wifi_wlan_startap(wlanpool->wlanhandle, &params)) {
		/* Set interface to pool */
		capwap_itemlist_free(itemwlan);
		capwap_itemlist_insert_before(radio->wlanpool, NULL, itemwlanpool);
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Move interface from pool to used */
	capwap_itemlist_free(itemwlanpool);
	capwap_itemlist_insert_after(radio->wlan, NULL, itemwlan);

	/* Update Event File Descriptor */
	wtp_radio_update_fdevent(&g_wtp.fds);

	/* Retrieve macaddress of new device */
	bssid->radioid = addwlan->radioid;
	bssid->wlanid = addwlan->wlanid;
	wifi_wlan_getbssid(wlan->wlanhandle, bssid->bssid);

	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
uint32_t wtp_radio_update_wlan(struct capwap_parsed_packet* packet) {
	/* TODO */
	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
uint32_t wtp_radio_delete_wlan(struct capwap_parsed_packet* packet) {
	/* TODO */
	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
uint32_t wtp_radio_add_station(struct capwap_parsed_packet* packet) {
	struct capwap_addstation_element* addstation;
	struct capwap_80211_station_element* station80211;
	struct wtp_radio* radio;
	struct wtp_radio_wlan* wlan;
	struct station_add_params stationparams;

	/* Get message elements */
	addstation = (struct capwap_addstation_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_ADDSTATION);
	station80211 = (struct capwap_80211_station_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_80211_STATION);
	if (!station80211 || (addstation->radioid != station80211->radioid)) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Get physical radio */
	radio = wtp_radio_get_phy(addstation->radioid);
	if (!radio) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Get virtual interface */
	wlan = wtp_radio_get_wlan(radio, station80211->wlanid);
	if (!wlan) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Authorize station */
	memset(&stationparams, 0, sizeof(struct station_add_params));
	stationparams.address = station80211->address;

	if (wifi_station_authorize(wlan->wlanhandle, &stationparams)) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
uint32_t wtp_radio_delete_station(struct capwap_parsed_packet* packet) {
	struct wtp_radio* radio;
	struct station_delete_params stationparams;
	struct capwap_deletestation_element* deletestation;

	/* Get message elements */
	deletestation = (struct capwap_deletestation_element*)capwap_get_message_element_data(packet, CAPWAP_ELEMENT_DELETESTATION);

	/* Get physical radio */
	radio = wtp_radio_get_phy(deletestation->radioid);
	if (!radio) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	/* Authorize station */
	memset(&stationparams, 0, sizeof(struct station_delete_params));
	stationparams.address = deletestation->address;

	if (wifi_station_deauthorize(radio->devicehandle, &stationparams)) {
		return CAPWAP_RESULTCODE_FAILURE;
	}

	return CAPWAP_RESULTCODE_SUCCESS;
}

/* */
int wtp_radio_acl_station(const uint8_t* macaddress) {
	ASSERT(macaddress != NULL);

	/* Check if exist ACL for station */
	if (capwap_hash_hasitem(g_wtp.aclstations, macaddress)) {
		return ((g_wtp.defaultaclstations == WTP_RADIO_ACL_STATION_ALLOW) ? WTP_RADIO_ACL_STATION_DENY : WTP_RADIO_ACL_STATION_ALLOW);
	}

	/* Default ACL station */
	return g_wtp.defaultaclstations;
}

/* */
void wtp_radio_acl_addstation(const uint8_t* macaddress) {
	ASSERT(macaddress != NULL);

	capwap_hash_add(g_wtp.aclstations, macaddress, NULL);
}

void wtp_radio_acl_deletestation(const uint8_t* macaddress) {
	ASSERT(macaddress != NULL);

	capwap_hash_delete(g_wtp.aclstations, macaddress);
}
