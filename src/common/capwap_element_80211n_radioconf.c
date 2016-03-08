#include "capwap.h"
#include "capwap_element.h"

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Radio ID   |S|P|N|G|B|     |    MaxSup MCS | Max MandMCS   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    TxAntenna  |    RxAntenna  |         Reserved              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Type:   TBD1 for IEEE 802.11n WLAN Radio Configuration
 *
 */

/* */
static void
capwap_80211n_radioconf_element_create(void *data,
				       capwap_message_elements_handle handle,
				       struct capwap_write_message_elements_ops *func)
{
	struct capwap_80211n_radioconf_element *element = (struct capwap_80211n_radioconf_element *)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	func->write_u8(handle, element->flags & CAPWAP_80211N_RADIO_CONF_MASK);
	func->write_u8(handle, element->maxsupmcs);
	func->write_u8(handle, element->maxmandmcs);
	func->write_u8(handle, element->txant);
	func->write_u8(handle, element->rxant);
	func->write_u16(handle, 0);
}

/* */
static void *
capwap_80211n_radioconf_element_parsing(capwap_message_elements_handle handle,
					struct capwap_read_message_elements_ops *func)
{
	struct capwap_80211n_radioconf_element *data;
	uint16_t reserved;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 8) {
		capwap_logging_debug("Invalid IEEE 802.11n Radio Configuration element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211n_radioconf_element*)capwap_alloc(sizeof(struct capwap_80211n_radioconf_element));
	memset(data, 0, sizeof(struct capwap_80211n_radioconf_element));

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	func->read_u8(handle, &data->flags);
	func->read_u8(handle, &data->maxsupmcs);
	func->read_u8(handle, &data->maxmandmcs);
	func->read_u8(handle, &data->txant);
	func->read_u8(handle, &data->rxant);
	func->read_u16(handle, &reserved);

	return data;
}

/* */
static void *
capwap_80211n_radioconf_element_clone(void *data)
{
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211n_radioconf_element));
}

/* */
static void
capwap_80211n_radioconf_element_free(void* data)
{
	ASSERT(data != NULL);

	capwap_free(data);
}

/* */
const struct capwap_message_elements_ops capwap_element_80211n_radioconf_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_80211n_radioconf_element_create,
	.parse = capwap_80211n_radioconf_element_parsing,
	.clone = capwap_80211n_radioconf_element_clone,
	.free = capwap_80211n_radioconf_element_free
};
