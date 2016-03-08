#include "capwap.h"
#include "capwap_element.h"

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                          MAC Address                          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |            MAC Address        |S| P |T|F|H|M| |  Max RxFactor |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Min StaSpacing|       HiSuppDataRate          | AMPDUBufSize  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | AMPDUBufSize  |    HtcSupp    |           MCS Set             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   MCS Set                                                     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   MCS Set                                                     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Type:   TBD2 for IEEE 802.11n Station Information
 *
 */

/* */
static void
capwap_80211n_station_info_element_create(void *data,
				       capwap_message_elements_handle handle,
				       struct capwap_write_message_elements_ops *func)
{
	struct capwap_80211n_station_info_element *element = (struct capwap_80211n_station_info_element *)data;

	ASSERT(data != NULL);

	func->write_block(handle, element->address, MACADDRESS_EUI48_LENGTH);
        func->write_u8(handle, element->flags);
	func->write_u8(handle, element->maxrxfactor);
	func->write_u8(handle, element->minstaspaceing);
	func->write_u16(handle, element->hisuppdatarate);
	func->write_u16(handle, element->ampdubufsize);
	func->write_u8(handle, element->htcsupp);
	func->write_block(handle, element->mcsset, MCS_SET_LENGTH);
}

/* */
static void *
capwap_80211n_station_info_element_parsing(capwap_message_elements_handle handle,
					struct capwap_read_message_elements_ops *func)
{
	struct capwap_80211n_station_info_element *data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 24) {
		capwap_logging_debug("Invalid IEEE 802.11n Station Information");
		return NULL;
	}

	/* */
	data = (struct capwap_80211n_station_info_element*)capwap_alloc(sizeof(struct capwap_80211n_station_info_element));
	memset(data, 0, sizeof(struct capwap_80211n_station_info_element));

	/* Retrieve data */
	func->read_block(handle, data->address, MACADDRESS_EUI48_LENGTH);
        func->read_u8(handle, &data->flags);
	func->read_u8(handle, &data->maxrxfactor);
	func->read_u8(handle, &data->minstaspaceing);
	func->read_u16(handle, &data->hisuppdatarate);
	func->read_u16(handle, &data->ampdubufsize);
	func->read_u8(handle, &data->htcsupp);
	func->read_block(handle, data->mcsset, MCS_SET_LENGTH);

	return data;
}

/* */
static void *
capwap_80211n_station_info_element_clone(void *data)
{
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211n_station_info_element));
}

/* */
static void
capwap_80211n_station_info_element_free(void* data)
{
	ASSERT(data != NULL);

	capwap_free(data);
}

/* */
const struct capwap_message_elements_ops capwap_element_80211n_station_info_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_80211n_station_info_element_create,
	.parse = capwap_80211n_station_info_element_parsing,
	.clone = capwap_80211n_station_info_element_clone,
	.free = capwap_80211n_station_info_element_free
};
