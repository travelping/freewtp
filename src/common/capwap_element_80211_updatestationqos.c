#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Radio ID    |                  MAC Address                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          MAC Address          |       QoS Sub-Element...      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Reserved|8021p|RSV| DSCP Tag  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1043 for IEEE 802.11 Update Station QoS

Length:   14

********************************************************************/

/* */
static void capwap_80211_updatestationqos_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	int i;
	struct capwap_80211_updatestationqos_element* element = (struct capwap_80211_updatestationqos_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	func->write_block(handle, element->address, CAPWAP_UPDATE_STATION_QOS_ADDRESS_LENGTH);
	for (i = 0; i < CAPWAP_UPDATE_STATION_QOS_SUBELEMENTS; i++) {
		func->write_u8(handle, element->qos[i].priority8021p & CAPWAP_UPDATE_STATION_QOS_PRIORIY_MASK);
		func->write_u8(handle, element->qos[i].dscp & CAPWAP_UPDATE_STATION_QOS_DSCP_MASK);
	}
}

/* */
static void* capwap_80211_updatestationqos_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	int i;
	struct capwap_80211_updatestationqos_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 14) {
		capwap_logging_debug("Invalid IEEE 802.11 Update Station QoS element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_updatestationqos_element*)capwap_alloc(sizeof(struct capwap_80211_updatestationqos_element));
	memset(data, 0, sizeof(struct capwap_80211_updatestationqos_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_block(handle, data->address, MACADDRESS_EUI48_LENGTH);
	for (i = 0; i < CAPWAP_UPDATE_STATION_QOS_SUBELEMENTS; i++) {
		func->read_u8(handle, &data->qos[i].priority8021p);
		data->qos[i].priority8021p &= CAPWAP_UPDATE_STATION_QOS_PRIORIY_MASK;
		func->read_u8(handle, &data->qos[i].dscp);
		data->qos[i].dscp &= CAPWAP_UPDATE_STATION_QOS_DSCP_MASK;
	}

	return data;
}

/* */
static void* capwap_80211_updatestationqos_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211_updatestationqos_element));
}

/* */
static void capwap_80211_updatestationqos_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_updatestationqos_ops = {
	.create_message_element = capwap_80211_updatestationqos_element_create,
	.parsing_message_element = capwap_80211_updatestationqos_element_parsing,
	.clone_message_element = capwap_80211_updatestationqos_element_clone,
	.free_message_element = capwap_80211_updatestationqos_element_free
};
