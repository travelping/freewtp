#include "capwap.h"
#include "capwap_element.h"

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                           Second                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                           Fraction                            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * WTP Timestamp
 *
 * Vendor Id:  18681 (Travelping GmbH)
 * Type:       2
 *
 */

struct ntp_time_t {
        uint32_t   second;
        uint32_t   fraction;
};

static inline void convert_ntp_time_into_unix_time(struct ntp_time_t *ntp, struct timeval *tv)
{
    tv->tv_sec = ntp->second - 0x83AA7E80; // the seconds from Jan 1, 1900 to Jan 1, 1970
    tv->tv_usec = (uint32_t)( (double)ntp->fraction * 1.0e6 / (double)(1LL<<32) );
}

static inline void convert_unix_time_into_ntp_time(struct timeval *tv, struct ntp_time_t *ntp)
{
    ntp->second = tv->tv_sec + 0x83AA7E80;
    ntp->fraction = (uint32_t)( (double)(tv->tv_usec+1) * (double)(1LL<<32) * 1.0e-6 );
}

/* */
static void
capwap_vendor_travelping_wtp_timestamp_element_create(void *data,
						      capwap_message_elements_handle handle,
						      struct capwap_write_message_elements_ops *func)
{
	struct capwap_vendor_travelping_wtp_timestamp_element *element =
		(struct capwap_vendor_travelping_wtp_timestamp_element *)data;
	struct ntp_time_t ntp;

	ASSERT(data != NULL);

	convert_unix_time_into_ntp_time(&element->tv, &ntp);

	func->write_u32(handle, ntp.second);
	func->write_u32(handle, ntp.fraction);
}

/* */
static void *
capwap_vendor_travelping_wtp_timestamp_element_parsing(capwap_message_elements_handle handle,
						       struct capwap_read_message_elements_ops *func)
{
	struct capwap_vendor_travelping_wtp_timestamp_element *data;
	struct ntp_time_t ntp;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 8) {
		log_printf(LOG_DEBUG, "Invalid Vendor Travelping WTP Timestamp element");
		return NULL;
	}

	/* */
	data = (struct capwap_vendor_travelping_wtp_timestamp_element *)
		capwap_alloc(sizeof(struct capwap_vendor_travelping_wtp_timestamp_element));

	/* Retrieve data */
	func->read_u32(handle, &ntp.second);
	func->read_u32(handle, &ntp.fraction);

	convert_ntp_time_into_unix_time(&ntp, &data->tv);

	return data;
}

/* */
static void *
capwap_vendor_travelping_wtp_timestamp_element_clone(void *data)
{
	ASSERT(data != NULL);

	return capwap_clone(data, sizeof(struct capwap_vendor_travelping_wtp_timestamp_element));
}

/* */
static void
capwap_vendor_travelping_wtp_timestamp_element_free(void* data)
{
	ASSERT(data != NULL);

	capwap_free(data);
}

/* */
const struct capwap_message_elements_ops capwap_element_vendor_travelping_wtp_timestamp_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_vendor_travelping_wtp_timestamp_element_create,
	.parse = capwap_vendor_travelping_wtp_timestamp_element_parsing,
	.clone = capwap_vendor_travelping_wtp_timestamp_element_clone,
	.free = capwap_vendor_travelping_wtp_timestamp_element_free
};
