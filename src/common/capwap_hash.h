#ifndef __CAPWAP_HASH_HEADER__
#define __CAPWAP_HASH_HEADER__

typedef unsigned long (*capwap_hash_item_gethash)(const void* key, unsigned long hashsize);
typedef const void* (*capwap_hash_item_getkey)(const void* data);
typedef int (*capwap_hash_item_cmp)(const void* key1, const void* key2);
typedef void (*capwap_hash_item_free)(void* data);

#define HASH_BREAK						0
#define HASH_CONTINUE					1
#define HASH_DELETE_AND_BREAK			2
#define HASH_DELETE_AND_CONTINUE		3
typedef int (*capwap_hash_item_foreach)(void* data, void* param); 

struct capwap_hash_item {
	void* data;

	int height;

	struct capwap_hash_item* parent;
	struct capwap_hash_item* left;
	struct capwap_hash_item* right;

	struct capwap_hash_item* removenext;
};

struct capwap_hash {
	struct capwap_hash_item** items;
	unsigned long hashsize;

	/* */
	unsigned long count;

	/* */
	struct capwap_hash_item* removeitems;

	/* Callback functions */
	capwap_hash_item_gethash item_gethash;
	capwap_hash_item_getkey item_getkey;
	capwap_hash_item_cmp item_cmp;
	capwap_hash_item_free item_free;
};

struct capwap_hash* capwap_hash_create(unsigned long hashsize);
void capwap_hash_free(struct capwap_hash* hash);

void capwap_hash_add(struct capwap_hash* hash, void* data);
void capwap_hash_delete(struct capwap_hash* hash, const void* key);
void capwap_hash_deleteall(struct capwap_hash* hash);

void* capwap_hash_search(struct capwap_hash* hash, const void* key);
void capwap_hash_foreach(struct capwap_hash* hash, capwap_hash_item_foreach item_foreach, void* param);

#endif /* __CAPWAP_HASH_HEADER__ */
