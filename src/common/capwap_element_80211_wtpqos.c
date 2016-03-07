#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Radio ID    |Tagging Policy |       QoS Sub-Element ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Queue Depth  |             CWMin             |     CWMax     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     CWMax     |     AIFS      | Reserved|8021p|RSV| DSCP Tag  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   1045 for IEEE 802.11 WTP Quality of Service

Length:   34

********************************************************************/

/* */
static void capwap_80211_wtpqos_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	int i;
	struct capwap_80211_wtpqos_element* element = (struct capwap_80211_wtpqos_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->taggingpolicy);
	for (i = 0; i < CAPWAP_UPDATE_STATION_QOS_SUBELEMENTS; i++) {
		func->write_u8(handle, element->qos[i].queuedepth);
		func->write_u16(handle, element->qos[i].cwmin);
		func->write_u16(handle, element->qos[i].cwmax);
		func->write_u8(handle, element->qos[i].aifs);
		func->write_u8(handle, element->qos[i].priority8021p & CAPWAP_WTP_QOS_PRIORIY_MASK);
		func->write_u8(handle, element->qos[i].dscp & CAPWAP_WTP_QOS_DSCP_MASK);
	}
}

/* */
static void* capwap_80211_wtpqos_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	int i;
	struct capwap_80211_wtpqos_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 34) {
		capwap_logging_debug("Invalid IEEE 802.11 WTP QoS element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_wtpqos_element*)capwap_alloc(sizeof(struct capwap_80211_wtpqos_element));
	memset(data, 0, sizeof(struct capwap_80211_wtpqos_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->taggingpolicy);
	for (i = 0; i < CAPWAP_UPDATE_STATION_QOS_SUBELEMENTS; i++) {
		func->read_u8(handle, &data->qos[i].queuedepth);
		func->read_u16(handle, &data->qos[i].cwmin);
		func->read_u16(handle, &data->qos[i].cwmax);
		func->read_u8(handle, &data->qos[i].aifs);
		func->read_u8(handle, &data->qos[i].priority8021p);
		data->qos[i].priority8021p &= CAPWAP_UPDATE_STATION_QOS_PRIORIY_MASK;
		func->read_u8(handle, &data->qos[i].dscp);
		data->qos[i].dscp &= CAPWAP_UPDATE_STATION_QOS_DSCP_MASK;
	}

	return data;
}

/* */
static void* capwap_80211_wtpqos_element_clone(void* data) {
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211_wtpqos_element));
}

/* */
static void capwap_80211_wtpqos_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}

/* */
struct capwap_message_elements_ops capwap_element_80211_wtpqos_ops = {
	.create = capwap_80211_wtpqos_element_create,
	.parse = capwap_80211_wtpqos_element_parsing,
	.clone = capwap_80211_wtpqos_element_clone,
	.free = capwap_80211_wtpqos_element_free
};
