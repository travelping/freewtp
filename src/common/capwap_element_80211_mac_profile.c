#include "capwap.h"
#include "capwap_element.h"

/*
 *  The IEEE 802.11 MAC Profile message element allows the AC to select a
 *  profile.  This message element may be provided along with the IEEE
 *  802.11 ADD WLAN message element while configuring a WLAN on the WTP.
 *
 *          0 1 2 3 4 5 6 7
 *         +=+-+-+-+-+-+-+-+
 *         |  Profile      |
 *         +-+-+-+-+-+-+-+-+
 *
 *  o  Type: 1061 for IEEE 802.11 MAC Profile
 *
 *  o  Profile: The profile is identified by a value as given below
 *
 *     *  0: This refers to the IEEE 802.11 Split MAC Profile with WTP
 *        encryption
 *
 *     *  1: This refers to the IEEE 802.11 Split MAC Profile with AC
 *        encryption
 */

/* */
static void
capwap_80211_mac_profile_element_create(void *data, capwap_message_elements_handle handle,
						   struct capwap_write_message_elements_ops *func)
{
	struct capwap_80211_mac_profile_element *element =
		(struct capwap_80211_mac_profile_element*)data;

	ASSERT(data != NULL);

	func->write_u8(handle, element->mac_profile);
}

/* */
static void *
capwap_80211_mac_profile_element_parsing(capwap_message_elements_handle handle,
						    struct capwap_read_message_elements_ops *func)
{
	unsigned short length;
	struct capwap_80211_mac_profile_element *data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	length = func->read_ready(handle);
	if (length != 1) {
		log_printf(LOG_DEBUG, "Invalid IEEE 802.11 Supported MAC Profiles element");
		return NULL;
	}

	/* */
	data = (struct capwap_80211_mac_profile_element *)
		capwap_alloc(sizeof(struct capwap_80211_mac_profile_element));
	memset(data, 0, sizeof(struct capwap_80211_mac_profile_element));

	/* Retrieve data */
	func->read_u8(handle, &data->mac_profile);

	return data;
}

/* */
static void *capwap_80211_mac_profile_element_clone(void *data)
{
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_80211_mac_profile_element));
}

/* */
static void capwap_80211_mac_profile_element_free(void *data)
{
	ASSERT(data != NULL);

	capwap_free(data);
}

/* */
const struct capwap_message_elements_ops capwap_element_80211_mac_profile_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_80211_mac_profile_element_create,
	.parse = capwap_80211_mac_profile_element_parsing,
	.clone = capwap_80211_mac_profile_element_clone,
	.free = capwap_80211_mac_profile_element_free
};
