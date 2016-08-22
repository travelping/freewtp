#include "capwap.h"
#include "element.h"

/*
 *  The IEEE 802.11 Supported MAC Profile message element allows the WTP
 *  to communicate the profiles it supports.  The Discovery Request
 *  message, Primary Discovery Request message, and Join Request message
 *  may include one such message element.
 *
 *          0               1               2               3
 *          0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0
 *         +=+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 *         | Num_Profiles  |  Profile_1    |   Profile_[2..N]..
 *         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 *
 *  o  Type: 1060 for IEEE 802.11 Supported MAC Profiles
 *
 *  o  Num_Profiles >=1: This refers to the number of profiles present in
 *     this message element.  There must be at least one profile.
 *
 *  o  Profile: Each profile is identified by a value specified in
 *     Section 3.2.
 */

/* */
static void
capwap_80211_supported_mac_profiles_element_create(void *data, capwap_message_elements_handle handle,
						   struct capwap_write_message_elements_ops *func)
{
	struct capwap_80211_supported_mac_profiles_element *element =
		(struct capwap_80211_supported_mac_profiles_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->supported_mac_profilescount);
	func->write_block(handle, element->supported_mac_profiles, element->supported_mac_profilescount);
}

/* */
static void *
capwap_80211_supported_mac_profiles_element_parsing(capwap_message_elements_handle handle,
						    struct capwap_read_message_elements_ops *func)
{
	unsigned short length;
	struct capwap_80211_supported_mac_profiles_element *data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length < 1 || length > 255) {
		log_printf(LOG_DEBUG, "Invalid IEEE 802.11 Supported MAC Profiles element");
		return NULL;
	}

	length -= 1;

	/* */
	data = (struct capwap_80211_supported_mac_profiles_element *)
		capwap_alloc(sizeof(struct capwap_80211_supported_mac_profiles_element) + length);
	memset(data, 0, sizeof(struct capwap_80211_supported_mac_profiles_element) + length);

	/* Retrieve data */
	func->read_u8(handle, &data->supported_mac_profilescount);
	if (data->supported_mac_profilescount != length) {
		log_printf(LOG_DEBUG, "Invalid IEEE 802.11 Supported MAC Profiles element");
		capwap_free(data);
		return NULL;
	}
	func->read_block(handle, data->supported_mac_profiles, length);

	return data;
}

/* */
static void *capwap_80211_supported_mac_profiles_element_clone(void *data)
{
	struct capwap_80211_supported_mac_profiles_element *element =
		(struct capwap_80211_supported_mac_profiles_element*)data;

	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211_supported_mac_profiles_element)
		+ element->supported_mac_profilescount);
}

/* */
static void capwap_80211_supported_mac_profiles_element_free(void *data)
{
	ASSERT(data != NULL);

	capwap_free(data);
}

/* */
const struct capwap_message_elements_ops capwap_element_80211_supported_mac_profiles_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_80211_supported_mac_profiles_element_create,
	.parse = capwap_80211_supported_mac_profiles_element_parsing,
	.clone = capwap_80211_supported_mac_profiles_element_clone,
	.free = capwap_80211_supported_mac_profiles_element_free
};
