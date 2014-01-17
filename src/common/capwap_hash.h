#ifndef __CAPWAP_HASH_HEADER__
#define __CAPWAP_HASH_HEADER__

typedef unsigned long (*capwap_hash_item_gethash)(const void* key, unsigned long keysize);
typedef int (*capwap_hash_item_cmp)(const void* key1, const void* key2, unsigned long keysize);
typedef void (*capwap_hash_item_free)(const void* key, unsigned long keysize, void* data);

typedef int (*capwap_hash_item_foreach)(const void* key, unsigned long keysize, void* data, void* param); 

struct capwap_hash_item {
	void* key;
	void* data;

	int height;

	struct capwap_hash_item* parent;
	struct capwap_hash_item* left;
	struct capwap_hash_item* right;
};

struct capwap_hash {
	struct capwap_hash_item** items;
	unsigned long count;
	unsigned long keysize;

	/* Callback functions */
	capwap_hash_item_gethash item_hash;
	capwap_hash_item_cmp item_cmp;
	capwap_hash_item_free item_free;
};

struct capwap_hash* capwap_hash_create(unsigned long count, unsigned long keysize, capwap_hash_item_gethash item_hash, capwap_hash_item_cmp item_cmp, capwap_hash_item_free item_free);
void capwap_hash_free(struct capwap_hash* hash);

void capwap_hash_add(struct capwap_hash* hash, void* key, void* data);
void capwap_hash_delete(struct capwap_hash* hash, void* key);

void* capwap_hash_search(struct capwap_hash* hash, void* key);
void capwap_hash_foreach(struct capwap_hash* hash, capwap_hash_item_foreach item_foreach, void* param);

#endif /* __CAPWAP_HASH_HEADER__ */
