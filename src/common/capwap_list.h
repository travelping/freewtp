#ifndef __CAPWAP_LIST_HEADER__
#define __CAPWAP_LIST_HEADER__

/* Item */
struct capwap_list_item {
	void* item;
	int itemsize;
	int autodelete;
	struct capwap_list_item* next;
	struct capwap_list_item* prev;
};

/* List */
struct capwap_list {
	unsigned long count;
	struct capwap_list_item* first;
	struct capwap_list_item* last;
};

struct capwap_list* capwap_list_create(void);
void capwap_list_free(struct capwap_list* list);
void capwap_list_flush(struct capwap_list* list);

struct capwap_list_item* capwap_itemlist_create(int size);
struct capwap_list_item* capwap_itemlist_create_with_item(void* item, int size);
void capwap_itemlist_free(struct capwap_list_item* item);

struct capwap_list_item* capwap_itemlist_remove(struct capwap_list* list, struct capwap_list_item* item);
struct capwap_list_item* capwap_itemlist_remove_head(struct capwap_list* list);
void capwap_itemlist_insert_before(struct capwap_list* list, struct capwap_list_item* before, struct capwap_list_item* item);
void capwap_itemlist_insert_after(struct capwap_list* list, struct capwap_list_item* after, struct capwap_list_item* item);

#endif /* __CAPWAP_LIST_HEADER__ */
