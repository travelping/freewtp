#ifndef __CAPWAP_ELEMENT_VENDORPAYLOAD_HEADER__
#define __CAPWAP_ELEMENT_VENDORPAYLOAD_HEADER__

#define CAPWAP_ELEMENT_VENDORPAYLOAD_VENDOR		0
#define CAPWAP_ELEMENT_VENDORPAYLOAD_TYPE		37
#define CAPWAP_ELEMENT_VENDORPAYLOAD			(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_VENDORPAYLOAD_VENDOR, .type = CAPWAP_ELEMENT_VENDORPAYLOAD_TYPE }


#define CAPWAP_VENDORPAYLOAD_MAXLENGTH		2048

struct capwap_vendorpayload_element {
	uint32_t vendorid;
	uint16_t elementid;
	uint16_t datalength;
	uint8_t data[];
};

void *
capwap_unknown_vendorpayload_element_parsing(capwap_message_elements_handle handle,
					     struct capwap_read_message_elements_ops *func,
					     unsigned short length,
					     const struct capwap_message_element_id vendor_id);

extern const struct capwap_message_elements_ops capwap_element_vendorpayload_ops;

#endif /* __CAPWAP_ELEMENT_VENDORPAYLOAD_HEADER__ */
