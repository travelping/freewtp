#ifndef __CAPWAP_ARRAY_HEADER__
#define __CAPWAP_ARRAY_HEADER__

struct capwap_array {
	void* buffer;
	unsigned short itemsize;
	unsigned long count;
	int zeroed;
};

struct capwap_array* capwap_array_create(unsigned short itemsize, unsigned long initcount);
struct capwap_array* capwap_array_clone(struct capwap_array* array);
void capwap_array_free(struct capwap_array* array);
void* capwap_array_get_item_pointer(struct capwap_array* array, unsigned long pos);
void capwap_array_resize(struct capwap_array* array, unsigned long count);

#endif /* __CAPWAP_ARRAY_HEADER__ */
