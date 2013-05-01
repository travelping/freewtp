#ifndef __CAPWAP_ELEMENT_ACIPV4LIST_HEADER__
#define __CAPWAP_ELEMENT_ACIPV4LIST_HEADER__

#define CAPWAP_ELEMENT_ACIPV4LIST							2

#define CAPWAP_ACIPV4LIST_MAX_ELEMENTS						1024

typedef struct capwap_array capwap_acipv4list_element_array;
struct capwap_acipv4list_element {
	struct in_addr address;
};

struct capwap_message_element* capwap_acipv4list_element_create(void* data, unsigned long datalength);
int capwap_acipv4list_element_validate(struct capwap_message_element* element);
void* capwap_acipv4list_element_parsing(struct capwap_message_element* element);
void capwap_acipv4list_element_free(void* data);


/* Helper */
#define CAPWAP_CREATE_ACIPV4LIST_ELEMENT(x)				({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_ACIPV4LIST);	\
															f->create(x, sizeof(capwap_acipv4list_element_array));	\
														})

#endif /* __CAPWAP_ELEMENT_ACIPV4LIST_HEADER__ */
