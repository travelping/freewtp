#include "capwap.h"
#include "capwap_array.h"

/* */
struct capwap_array* capwap_array_create(unsigned short itemsize, unsigned long initcount, int zeroed) {
	struct capwap_array* array;

	ASSERT(itemsize > 0);

	array = (struct capwap_array*)capwap_alloc(sizeof(struct capwap_array));
	if (!array) {
		capwap_outofmemory();
	}

	memset(array, 0, sizeof(struct capwap_array));
	array->itemsize = itemsize;
	array->zeroed = zeroed;
	if (initcount > 0) {
		capwap_array_resize(array, initcount);
	}

	return array;
}

/* */
struct capwap_array* capwap_array_clone(struct capwap_array* array) {
	struct capwap_array* clone;

	ASSERT (array != NULL);

	/* Clone array e items */
	clone = capwap_array_create(array->itemsize, array->count, array->zeroed);
	memcpy(clone->buffer, array->buffer, array->itemsize * array->count);

	return clone;
}

/* */
void capwap_array_free(struct capwap_array* array) {
	ASSERT(array != NULL);

	if (array->buffer) {
		capwap_free(array->buffer);
	}

	capwap_free(array);
}

/* */
void* capwap_array_get_item_pointer(struct capwap_array* array, unsigned long pos) {
	ASSERT(array != NULL);
	ASSERT((array->count == 0) || (array->buffer != NULL));

	if (pos >= array->count) {
		capwap_array_resize(array, pos + 1);
	}

	return (void*)(((char*)array->buffer) + array->itemsize * pos);
}

/* */
void capwap_array_resize(struct capwap_array* array, unsigned long count) {
	int newcount;
	void* newbuffer = NULL;

	ASSERT(array != NULL);
	ASSERT(array->itemsize > 0);

	if (array->count == count) {
		return;
	}

	newcount = min(array->count, count);

	if (count > 0) {
		newbuffer = capwap_alloc(array->itemsize * count);
		if (!newbuffer) {
			capwap_outofmemory();
		}

		/* Zeroed new items */
		if (array->zeroed && (count > newcount)) {
			memset(newbuffer + array->itemsize * newcount, 0, array->itemsize * (count - newcount));
		}
	}

	if (array->buffer) {
		if ((newbuffer != NULL) && (newcount > 0)) {
			memcpy(newbuffer, array->buffer, array->itemsize * newcount);
		}

		capwap_free(array->buffer);
	}

	array->buffer = newbuffer;
	array->count = count;
}
