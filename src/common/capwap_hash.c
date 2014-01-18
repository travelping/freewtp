#include "capwap.h"
#include "capwap_hash.h"

/* */
static void capwap_hash_free_item(struct capwap_hash* hash, struct capwap_hash_item* item) {
	ASSERT(hash != NULL);
	ASSERT(item != NULL);
	ASSERT(item->key != NULL);

	if (item->data && hash->item_free) {
		hash->item_free(item->key, hash->keysize, item->data);
	}

	capwap_free(item->key);
	capwap_free(item);
}

/* */
static void capwap_hash_free_items(struct capwap_hash* hash, struct capwap_hash_item* item) {
	ASSERT(hash != NULL);
	ASSERT(item != NULL);

	/* Free child */
	if (item->left) {
		capwap_hash_free_items(hash, item->left);
	}

	if (item->right) {
		capwap_hash_free_items(hash, item->right);
	}

	/* */
	capwap_hash_free_item(hash, item);
}

/* */
static struct capwap_hash_item* capwap_hash_search_items(struct capwap_hash* hash, struct capwap_hash_item* item, const void* key) {
	int result;
	struct capwap_hash_item* search;

	ASSERT(hash != NULL);
	ASSERT(key != NULL);

	search = item;
	while (search) {
		result = hash->item_cmp(key, search->key, hash->keysize);

		if (!result) {
			return search;
		} else if (result < 0) {
			search = item->left;
		} else if (result > 0) {
			search = item->right;
		}
	}

	return NULL;
}

/* */
static int capwap_hash_foreach_items(struct capwap_hash* hash, struct capwap_hash_item* item, capwap_hash_item_foreach item_foreach, void* param) {
	int result;

	ASSERT(hash != NULL);
	ASSERT(item_foreach != NULL);
	ASSERT(item != NULL);

	/* */
	if (item->left) {
		if (!capwap_hash_foreach_items(hash, item->left, item_foreach, param)) {
			return 0;
		}
	}

	/* */
	result = item_foreach(item->key, hash->keysize, item->data, param);
	if (!result) {
		return 0;
	}

	/* */
	if (item->right) {
		if (!capwap_hash_foreach_items(hash, item->right, item_foreach, param)) {
			return 0;
		}
	}

	return 1;
}

/* */
static struct capwap_hash_item* capwap_hash_create_item(struct capwap_hash* hash, const void* key, void* data) {
	struct capwap_hash_item* item;

	ASSERT(hash != NULL);
	ASSERT(key != NULL);

	/* */
	item = (struct capwap_hash_item*)capwap_alloc(sizeof(struct capwap_hash_item));
	memset(item, 0, sizeof(struct capwap_hash_item));

	item->key = capwap_clone(key, hash->keysize);
	item->data = data;

	return item;
}

/* */
static void capwap_hash_update_height(struct capwap_hash_item* item) {
	ASSERT(item != NULL);

	if (item->left && item->right) {
		item->height = ((item->left->height > item->right->height) ? item->left->height + 1 : item->right->height + 1);
	} else if (item->left) {
		item->height = item->left->height + 1;
	} else if (item->right) {
		item->height = item->right->height + 1;
	} else {
		item->height = 0;
	}
}

/* */
static void capwap_hash_set_left_item(struct capwap_hash_item* item, struct capwap_hash_item* child) {
	ASSERT(item != NULL);

	if (child) {
		child->parent = item;
	}

	item->left = child;
	capwap_hash_update_height(item);
}

/* */
static void capwap_hash_set_right_item(struct capwap_hash_item* item, struct capwap_hash_item* child) {
	ASSERT(item != NULL);

	if (child) {
		child->parent = item;
	}

	item->right = child;
	capwap_hash_update_height(item);
}

/* */
static void capwap_hash_rotate_left(struct capwap_hash_item* item, struct capwap_hash_item** root) {
	int parentside;
	struct capwap_hash_item* right;
	struct capwap_hash_item* parent;

	ASSERT(item != NULL);

	/* Check parent */
	parent = item->parent;
	if (parent) {
		parentside = ((parent->left == item) ? 1 : 0);
	}

	/* Rotate */
	right = item->right;
	capwap_hash_set_right_item(item, right->left);
	capwap_hash_set_left_item(right, item);

	/* Update parent */
	if (parent) {
		if (parentside) {
			capwap_hash_set_left_item(parent, right);
		} else {
			capwap_hash_set_right_item(parent, right);
		}
	} else {
		right->parent = NULL;
		*root = right;
	}
}

/* */
static void capwap_hash_rotate_right(struct capwap_hash_item* item, struct capwap_hash_item** root) {
	int parentside;
	struct capwap_hash_item* left;
	struct capwap_hash_item* parent;

	ASSERT(item != NULL);

	/* Check parent */
	parent = item->parent;
	if (parent) {
		parentside = ((parent->left == item) ? 1 : 0);
	}

	/* Rotate */
	left = item->left;
	capwap_hash_set_left_item(item, left->right);
	capwap_hash_set_right_item(left, item);

	/* Update parent */
	if (parent) {
		if (parentside) {
			capwap_hash_set_left_item(parent, left);
		} else {
			capwap_hash_set_right_item(parent, left);
		}
	} else {
		left->parent = NULL;
		*root = left;
	}
}

/* */
static int capwap_hash_get_balance_item(struct capwap_hash_item* item) {
	ASSERT(item != NULL);

	if (item->left && item->right) {
		return item->left->height - item->right->height;
	} else if (item->left) {
		return item->left->height + 1;
	} else if (item->right) {
		return -(item->right->height + 1);
	}

	return 0;
}

/* */
static void capwap_hash_balance_tree(struct capwap_hash_item* item, struct capwap_hash_item** root) {
	int result;

	ASSERT(item != NULL);

	result = capwap_hash_get_balance_item(item);
	if (result > 1) {
		if (capwap_hash_get_balance_item(item->left) < 0) {
			capwap_hash_rotate_left(item->left, root);
		}

		capwap_hash_rotate_right(item, root);
	} else if (result < -1) {
		if (capwap_hash_get_balance_item(item->right) > 0) {
			capwap_hash_rotate_right(item->right, root);
		}

		capwap_hash_rotate_left(item, root);
	}
}

/* */
static int capwap_hash_item_memcmp(const void* key1, const void* key2, unsigned long keysize) {
	return memcmp(key1, key2, keysize);
}

/* */
struct capwap_hash* capwap_hash_create(unsigned long count, unsigned long keysize, capwap_hash_item_gethash item_hash, capwap_hash_item_cmp item_cmp, capwap_hash_item_free item_free) {
	unsigned long size;
	struct capwap_hash* hash;

	ASSERT(count > 0);
	ASSERT(keysize > 0);
	ASSERT(item_hash != NULL);

	size = sizeof(struct capwap_hash_item*) * count;

	/* */
	hash = (struct capwap_hash*)capwap_alloc(sizeof(struct capwap_hash));
	hash->count = count;
	hash->keysize = keysize;
	hash->items = (struct capwap_hash_item**)capwap_alloc(size);
	memset(hash->items, 0, size);
	hash->item_hash = item_hash;
	hash->item_cmp = (item_cmp ? item_cmp : capwap_hash_item_memcmp);
	hash->item_free = item_free;

	return hash;
}

/* */
void capwap_hash_free(struct capwap_hash* hash) {
	ASSERT(hash != NULL);

	/* Delete all items */
	capwap_hash_deleteall(hash);

	/* Free */
	capwap_free(hash->items);
	capwap_free(hash);
}

/* */
void capwap_hash_add(struct capwap_hash* hash, const void* key, void* data) {
	int result;
	unsigned long hashvalue;
	struct capwap_hash_item* search;
	struct capwap_hash_item* item = NULL;

	ASSERT(hash != NULL);
	ASSERT(key != NULL);

	hashvalue = hash->item_hash(key, hash->keysize, hash->count);

	/* Search position where insert item */
	search = hash->items[hashvalue];
	if (!search) {
		hash->items[hashvalue] = capwap_hash_create_item(hash, key, data);
	} else {
		while (search) {
			result = hash->item_cmp(key, search->key, hash->keysize);
			if (!result) {
				/* Free old element and update data value without create new item */
				if (search->data && hash->item_free) {
					hash->item_free(search->key, hash->keysize, search->data);
				}

				search->data = data;
				break;
			} else if (result < 0) {
				if (search->left) {
					search = search->left;
				} else {
					item = capwap_hash_create_item(hash, key, data);
					capwap_hash_set_left_item(search, item);
					break;
				}
			} else if (result > 0) {
				if (search->right) {
					search = search->right;
				} else {
					item = capwap_hash_create_item(hash, key, data);
					capwap_hash_set_right_item(search, item);
					break;
				}
			}
		}

		/* Rebalancing tree */
		while (item) {
			capwap_hash_update_height(item);
			capwap_hash_balance_tree(item, &hash->items[hashvalue]);

			/* Rebalancing parent */
			item = item->parent;
		}
	}
}

/* */
void capwap_hash_delete(struct capwap_hash* hash, const void* key) {
	unsigned long hashvalue;
	struct capwap_hash_item* search;
	struct capwap_hash_item* parent;

	ASSERT(hash != NULL);
	ASSERT(key != NULL);

	/* */
	hashvalue = hash->item_hash(key, hash->keysize, hash->count);
	if (!hash->items[hashvalue]) {
		return;
	}

	/* */
	search = capwap_hash_search_items(hash, hash->items[hashvalue], key);
	if (!search) {
		return;
	}

	/* Rebalancing tree */
	parent = search->parent;
	if (!search->left && !search->right) {
		if (parent) {
			if (parent->left == search) {
				capwap_hash_set_left_item(parent, NULL);
			} else {
				capwap_hash_set_right_item(parent, NULL);
			}

			/* */
			capwap_hash_balance_tree(parent, &hash->items[hashvalue]);
		} else {
			hash->items[hashvalue] = NULL;
		}
	} else if (!search->right) {
		if (parent) {
			if (parent->left == search) {
				capwap_hash_set_left_item(parent, search->left);
			} else {
				capwap_hash_set_right_item(parent, search->left);
			}

			/* */
			capwap_hash_balance_tree(parent, &hash->items[hashvalue]);
		} else {
			search->left->parent = NULL;
			hash->items[hashvalue] = search->left;
		}
	} else if (!search->left) {
		if (parent) {
			if (parent->left == search) {
				capwap_hash_set_left_item(parent, search->right);
			} else {
				capwap_hash_set_right_item(parent, search->right);
			}

			/* */
			capwap_hash_balance_tree(parent, &hash->items[hashvalue]);
		} else {
			search->right->parent = NULL;
			hash->items[hashvalue] = search->right;
		}
	} else {
		struct capwap_hash_item* replacement = NULL;

		if (capwap_hash_get_balance_item(search) > 0) {
			if (!search->left->right) {
				replacement = search->left;
				capwap_hash_set_right_item(replacement, search->right);
			} else {
				replacement = search->left->right;
				while (replacement->right) {
					replacement = replacement->right;
				}

				capwap_hash_set_right_item(replacement->parent, replacement->left);
				capwap_hash_set_left_item(replacement, search->left);
				capwap_hash_set_right_item(replacement, search->right);
			}
		} else {
			if (!search->right->left) {
				replacement = search->right;
				capwap_hash_set_left_item(replacement, search->left);
			} else {
				replacement = search->right->left;
				while (replacement->left) {
					replacement = replacement->left;
				}

				capwap_hash_set_left_item(replacement->parent, replacement->right);
				capwap_hash_set_left_item(replacement, search->left);
				capwap_hash_set_right_item(replacement, search->right);
			}
		}

		if (parent) {
			if (parent->left == search) {
				capwap_hash_set_left_item(parent, replacement);
			} else {
				capwap_hash_set_right_item(parent, replacement);
			}
		} else {
			replacement->parent = NULL;
			hash->items[hashvalue] = replacement;
		}

		capwap_hash_balance_tree(replacement, &hash->items[hashvalue]);
	}

	/* Free node */
	capwap_hash_free_item(hash, search);
}

/* */
void capwap_hash_deleteall(struct capwap_hash* hash) {
	unsigned long i;

	ASSERT(hash != NULL);

	for (i = 0; i < hash->count; i++) {
		if (hash->items[i]) {
			capwap_hash_free_items(hash, hash->items[i]);
			hash->items[i] = NULL;
		}
	}

}

/* */
int capwap_hash_hasitem(struct capwap_hash* hash, const void* key) {
	unsigned long hashvalue;
	struct capwap_hash_item* items;
	struct capwap_hash_item* result;

	ASSERT(hash != NULL);
	ASSERT(key != NULL);

	/* Search item */
	hashvalue = hash->item_hash(key, hash->keysize, hash->count);
	items = hash->items[hashvalue];
	if (!items) {
		return 0;
	}

	/* */
	result = capwap_hash_search_items(hash, items, key);
	return (result ? 1 : 0);
}

/* */
void* capwap_hash_search(struct capwap_hash* hash, const void* key) {
	unsigned long hashvalue;
	struct capwap_hash_item* items;
	struct capwap_hash_item* result;

	ASSERT(hash != NULL);
	ASSERT(key != NULL);

	/* Search item */
	hashvalue = hash->item_hash(key, hash->keysize, hash->count);
	items = hash->items[hashvalue];
	if (!items) {
		return NULL;
	}

	/* */
	result = capwap_hash_search_items(hash, items, key);
	if (!result) {
		return NULL;
	}

	return result->data;
}

/* */
void capwap_hash_foreach(struct capwap_hash* hash, capwap_hash_item_foreach item_foreach, void* param) {
	unsigned long i;

	ASSERT(hash != NULL);
	ASSERT(item_foreach != NULL);

	for (i = 0; i < hash->count; i++) {
		if (hash->items[i]) {
			capwap_hash_foreach_items(hash, hash->items[i], item_foreach, param);
		}
	}
}
