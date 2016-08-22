#include "capwap.h"
#include "element.h"

/*
 * The IEEE 802.11 Encryption Capability message element is used by
 * the WTP to inform the AC of the support cipher suites. It contains
 * a list of suites as defined by IEEE 802.11 Sect. 8.4.2.27.2.
 * The message element contains the following fields.
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Radio ID   |            Cipher Suites...                   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * IEEE 802.11 Encryption Capability
 *
 * Vendor Id:  18681 (Travelping GmbH)
 * Type:       18
 *
 */

/* */
static void
capwap_vendor_travelping_80211_encryption_capability_element_create(void *data,
								    capwap_message_elements_handle handle,
								    struct capwap_write_message_elements_ops *func)
{
	int i;
	struct capwap_vendor_travelping_80211_encryption_capability_element *element =
		(struct capwap_vendor_travelping_80211_encryption_capability_element *)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->radioid);
	for (i = 0; i < element->suites_count; i++)
		func->write_u32(handle, element->suites[i]);
}

/* */
static void *
capwap_vendor_travelping_80211_encryption_capability_element_parsing(capwap_message_elements_handle handle,
								     struct capwap_read_message_elements_ops *func)
{
	struct capwap_vendor_travelping_80211_encryption_capability_element *data;
	int suites_length, i;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) < 1) {
		log_printf(LOG_DEBUG, "Invalid Vendor Travelping WTP 802.11 Encryption Capability element");
		return NULL;
	}

	suites_length = func->read_ready(handle) - 1;
	if ((suites_length % sizeof(uint32_t)) != 0) {
		log_printf(LOG_DEBUG, "Invalid Vendor Travelping WTP 802.11 Encryption Capability element");
		return NULL;
	}

	/* */
	data = (struct capwap_vendor_travelping_80211_encryption_capability_element *)
		capwap_alloc(sizeof(struct capwap_vendor_travelping_80211_encryption_capability_element) + suites_length);

	/* Retrieve data */
	func->read_u8(handle, &data->radioid);
	data->suites_count = suites_length / sizeof(uint32_t);
	for (i = 0; i < data->suites_count; i++)
		func->read_u32(handle, &data->suites[i]);
	return data;
}

/* */
static void *
capwap_vendor_travelping_80211_encryption_capability_element_clone(void *data)
{
	struct capwap_vendor_travelping_80211_encryption_capability_element *element =
		(struct capwap_vendor_travelping_80211_encryption_capability_element *)data;

	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_vendor_travelping_80211_encryption_capability_element)
			    + element->suites_count * sizeof(uint32_t));
}

/* */
static void
capwap_vendor_travelping_80211_encryption_capability_element_free(void* data)
{
	ASSERT(data != NULL);

	capwap_free(data);
}

/* */
const struct capwap_message_elements_ops capwap_element_vendor_travelping_80211_encryption_capability_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_ARRAY,
	.create = capwap_vendor_travelping_80211_encryption_capability_element_create,
	.parse = capwap_vendor_travelping_80211_encryption_capability_element_parsing,
	.clone = capwap_vendor_travelping_80211_encryption_capability_element_clone,
	.free = capwap_vendor_travelping_80211_encryption_capability_element_free
};
