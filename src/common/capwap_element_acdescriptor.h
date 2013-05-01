#ifndef __CAPWAP_ELEMENT_ACDESCRIPTOR_HEADER__
#define __CAPWAP_ELEMENT_ACDESCRIPTOR_HEADER__

#define CAPWAP_ELEMENT_ACDESCRIPTION				1

#define CAPWAP_ACDESC_SECURITY_PRESHARED_KEY		0x04
#define CAPWAP_ACDESC_SECURITY_X509_CERT			0x02

#define CAPWAP_ACDESC_RMACFIELD_SUPPORTED			1
#define CAPWAP_ACDESC_RMACFIELD_NOTSUPPORTED		2

#define CAPWAP_ACDESC_DTLS_DATA_CHANNEL_ENABLED		0x04
#define CAPWAP_ACDESC_CLEAR_DATA_CHANNEL_ENABLED	0x02

struct capwap_acdescriptor_element {
	unsigned short station;
	unsigned short stationlimit;
	unsigned short wtp;
	unsigned short wtplimit;
	unsigned char security;
	unsigned char rmacfield;
	unsigned char dtlspolicy;
	struct capwap_array* descsubelement;
};

#define CAPWAP_ACDESC_SUBELEMENT_HARDWAREVERSION			4
#define CAPWAP_ACDESC_SUBELEMENT_SOFTWAREVERSION			5
#define CAPWAP_ACDESC_SUBELEMENT_MAXDATA					1024

struct capwap_acdescriptor_desc_subelement {
	unsigned long vendor;
	unsigned short type;
	unsigned short length;
	char data[CAPWAP_ACDESC_SUBELEMENT_MAXDATA];
};

struct capwap_message_element* capwap_acdescriptor_element_create(void* data, unsigned long length);
int capwap_acdescriptor_element_validate(struct capwap_message_element* element);
void* capwap_acdescriptor_element_parsing(struct capwap_message_element* element);
void capwap_acdescriptor_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_ACDESCRIPTOR_ELEMENT(x)			({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_ACDESCRIPTION);	\
															f->create(x, sizeof(struct capwap_acdescriptor_element));	\
														})

#endif /* __CAPWAP_ELEMENT_ACDESCRIPTOR_HEADER__ */
