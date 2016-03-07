#ifndef __CAPWAP_ELEMENT_VENDORPAYLOAD_HEADER__
#define __CAPWAP_ELEMENT_VENDORPAYLOAD_HEADER__

#define VENDOR_TRAVELPING					18681
#define VENDOR_TRAVELPING_ELEMENT_80211N_RADIO_CONF		123
#define VENDOR_TRAVELPING_ELEMENT_80211N_STATION_INFO		124

#define CAPWAP_ELEMENT_VENDORPAYLOAD		37

#define CAPWAP_VENDORPAYLOAD_MAXLENGTH		2048

struct capwap_vendorpayload_element {
	uint32_t vendorid;
	uint16_t elementid;
	uint16_t datalength;
	uint8_t* data;
};

extern struct capwap_message_elements_ops capwap_element_vendorpayload_ops;

#endif /* __CAPWAP_ELEMENT_VENDORPAYLOAD_HEADER__ */
