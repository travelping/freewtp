#ifndef __CAPWAP_ELEMENT_ACIPV6LIST_HEADER__
#define __CAPWAP_ELEMENT_ACIPV6LIST_HEADER__

#define CAPWAP_ELEMENT_ACIPV6LIST							3

#define CAPWAP_ACIPV6LIST_MAX_ELEMENTS						1024

typedef struct capwap_array capwap_acipv6list_element_array;
struct capwap_acipv6list_element {
	struct in6_addr address;
};

struct capwap_message_element* capwap_acipv6list_element_create(void* data, unsigned long datalength);
int capwap_acipv6list_element_validate(struct capwap_message_element* element);
void* capwap_acipv6list_element_parsing(struct capwap_message_element* element);
void capwap_acipv6list_element_free(void* data);


/* Helper */
#define CAPWAP_CREATE_ACIPV6LIST_ELEMENT(x)				({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_ACIPV6LIST);	\
															f->create(x, sizeof(capwap_acipv6list_element_array));	\
														})

#endif /* __CAPWAP_ELEMENT_ACIPV6LIST_HEADER__ */
