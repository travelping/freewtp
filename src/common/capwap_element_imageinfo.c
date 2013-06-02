#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           File Size                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              Hash                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              Hash                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              Hash                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              Hash                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   26 for Image Information

Length:   20

********************************************************************/

/* */
static void capwap_imageinfo_element_create(void* data, capwap_message_elements_handle handle, struct capwap_write_message_elements_ops* func) {
	struct capwap_imageinfo_element* element = (struct capwap_imageinfo_element*)data;

	ASSERT(data != NULL);

	func->write_u32(handle, element->length);
	func->write_block(handle, element->hash, CAPWAP_IMAGEINFO_HASH_LENGTH);
}

/* */
static void capwap_imageinfo_element_free(void* data) {
	ASSERT(data != NULL);

	capwap_free(data);
}

/* */
static void* capwap_imageinfo_element_parsing(capwap_message_elements_handle handle, struct capwap_read_message_elements_ops* func) {
	struct capwap_imageinfo_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) != 20) {
		capwap_logging_debug("Invalid Image Information element");
		return NULL;
	}

	/* */
	data = (struct capwap_imageinfo_element*)capwap_alloc(sizeof(struct capwap_imageinfo_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* Retrieve data */
	memset(data, 0, sizeof(struct capwap_imageinfo_element));
	func->read_u32(handle, &data->length);
	func->read_block(handle, data->hash, CAPWAP_IMAGEINFO_HASH_LENGTH);

	return data;
}

/* */
struct capwap_message_elements_ops capwap_element_imageinfo_ops = {
	.create_message_element = capwap_imageinfo_element_create,
	.parsing_message_element = capwap_imageinfo_element_parsing,
	.free_parsed_message_element = capwap_imageinfo_element_free
};
