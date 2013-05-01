#ifndef __CAPWAP_ELEMENT_VENDORPAYLOAD_HEADER__
#define __CAPWAP_ELEMENT_VENDORPAYLOAD_HEADER__

#define CAPWAP_ELEMENT_VENDORPAYLOAD		37

#define CAPWAP_VENDORPAYLOAD_MAXLENGTH		2048

struct capwap_vendorpayload_element {
	unsigned long vendorid;
	unsigned short elementid;
	unsigned short datalength;
	char data[CAPWAP_VENDORPAYLOAD_MAXLENGTH];
};

struct capwap_message_element* capwap_vendorpayload_element_create(void* data, unsigned long datalength);
int capwap_vendorpayload_element_validate(struct capwap_message_element* element);
void* capwap_vendorpayload_element_parsing(struct capwap_message_element* element);
void capwap_vendorpayload_element_free(void* data);


/* Helper */
#define CAPWAP_CREATE_VENDORPAYLOAD_ELEMENT(x)			({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_VENDORPAYLOAD_MAXLENGTH);	\
															f->create(x, sizeof(struct capwap_vendorpayload_element));	\
														})

#endif /* __CAPWAP_ELEMENT_VENDORPAYLOAD_HEADER__ */
