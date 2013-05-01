#include "capwap.h"
#include "capwap_list.h"

/* */
struct capwap_list* capwap_list_create(void) {
	struct capwap_list* list;
		
	list = (struct capwap_list*)capwap_alloc(sizeof(struct capwap_list));
	if (!list) {
		capwap_outofmemory();
	}
	
	memset(list, 0, sizeof(struct capwap_list));
	return list;
}

/* */
void capwap_list_free(struct capwap_list* list) {
	ASSERT(list != NULL);
	
	capwap_list_flush(list);
	capwap_free(list);
}

/* */
void capwap_list_flush(struct capwap_list* list) {
	struct capwap_list_item* item;
	struct capwap_list_item* next;

	ASSERT(list != NULL);

	item = list->first;
	while (item) {
		next = item->next;
		capwap_itemlist_free(item);
		item = next;
	}
	
	list->first = NULL;
	list->last = NULL;
	list->count = 0;
}

/* */
struct capwap_list_item* capwap_itemlist_create_with_item(void* item, int size) {
	struct capwap_list_item* itemlist;
	
	itemlist = (struct capwap_list_item*)capwap_alloc(sizeof(struct capwap_list_item));
	if (!itemlist) {
		capwap_outofmemory();
	}
	
	memset(itemlist, 0, sizeof(struct capwap_list_item));
	itemlist->item = item;
	itemlist->itemsize = size;
	itemlist->autodelete = 1;
	
	return itemlist;
}

/* */
struct capwap_list_item* capwap_itemlist_create(int size) {
	void* item;

	ASSERT(size > 0);
	
	item = capwap_alloc(size);
	if (!item) {
		capwap_outofmemory();
	}
	
	return capwap_itemlist_create_with_item(item, size);
}

/* */
void capwap_itemlist_free(struct capwap_list_item* item) {
	ASSERT(item != NULL);
	ASSERT(item->item != NULL);
	
	if (item->autodelete) {
		capwap_free(item->item);
	}
	
	capwap_free(item);
}

/* */
struct capwap_list_item* capwap_itemlist_remove(struct capwap_list* list, struct capwap_list_item* item) {
	ASSERT(list != NULL);
	ASSERT(item != NULL);

	if (item->prev) {
		item->prev->next = item->next;
	} else {
		list->first = item->next;
	}

	if (item->next) {
		item->next->prev = item->prev;
	} else {
		list->last = item->prev;
	}

	item->next = NULL;
	item->prev = NULL;
	list->count--;
	
	return item;
}

/* */
struct capwap_list_item* capwap_itemlist_remove_head(struct capwap_list* list) {
	struct capwap_list_item* item;
	
	ASSERT(list != NULL);
	
	item = list->first;
	if (item != NULL) {
		list->first = item->next;
		if (list->first) {
			list->first->prev = NULL;
		} else {
			list->last = NULL;
		}
	
		item->next = NULL;
		item->prev = NULL;
		list->count--;
	}
	
	return item;
}

/* */
void capwap_itemlist_insert_before(struct capwap_list* list, struct capwap_list_item* before, struct capwap_list_item* item) {
	ASSERT(list != NULL);
	ASSERT(item != NULL);

	list->count++;
	
	if (!before) {
		if (list->first) {
			before = list->first;
		} else {
			list->first = item;
			list->last = item;
			item->next = NULL;
			item->prev = NULL;
			return;
		}
	}
	
	item->prev = before->prev;
	item->next = before;
	if (!before->prev) {
		list->first = item;
	} else {
		before->prev->next = item;
	}
	before->prev = item;
}

/* */
void capwap_itemlist_insert_after(struct capwap_list* list, struct capwap_list_item* after, struct capwap_list_item* item) {
	ASSERT(list != NULL);
	ASSERT(item != NULL);
	
	list->count++;

	if (!after) {
		if (list->last) {
			after = list->last;
		} else {
			list->first = item;
			list->last = item;
			item->next = NULL;
			item->prev = NULL;
			return;
		}
	}
	
	item->prev = after;
	item->next = after->next;
	if (!after->next) {
		list->last = item;
	} else {
		after->next->prev = item;
	}
	after->next = item;
}
