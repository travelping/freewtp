#include "capwap.h"
#include "capwap_hash.h"

/* */
static void capwap_hash_free_item(struct capwap_hash* hash, struct capwap_hash_item* item) {
	ASSERT(hash != NULL);
	ASSERT(item != NULL);

	if (item->data && hash->item_free) {
		hash->item_free(item->data);
	}

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
		result = hash->item_cmp(key, hash->item_getkey(search->data));

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
		result = capwap_hash_foreach_items(hash, item->left, item_foreach, param);
		if (result == HASH_BREAK) {
			return HASH_BREAK;
		}
	}

	/* */
	item->removenext = NULL;
	result = item_foreach(item->data, param);

	/* Delete item */
	if ((result == HASH_DELETE_AND_BREAK) || (result == HASH_DELETE_AND_CONTINUE)) {
		item->removenext = hash->removeitems;
		hash->removeitems = item;
	}

	/* Break */
	if ((result == HASH_BREAK) || (result == HASH_DELETE_AND_BREAK)) {
		return HASH_BREAK;
	}

	/* */
	if (item->right) {
		result = capwap_hash_foreach_items(hash, item->right, item_foreach, param);
		if (result == HASH_BREAK) {
			return HASH_BREAK;
		}
	}

	return HASH_CONTINUE;
}

/* */
static struct capwap_hash_item* capwap_hash_create_item(struct capwap_hash* hash, void* data) {
	struct capwap_hash_item* item;

	ASSERT(hash != NULL);
	ASSERT(data != NULL);

	/* */
	item = (struct capwap_hash_item*)capwap_alloc(sizeof(struct capwap_hash_item));
	memset(item, 0, sizeof(struct capwap_hash_item));

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
static void capwap_hash_deleteitem(struct capwap_hash* hash, const void* key, struct capwap_hash_item* search, unsigned long hashvalue) {
	struct capwap_hash_item* parent;

	ASSERT(hash != NULL);
	ASSERT(key != NULL);
	ASSERT(search != NULL);
	ASSERT(hashvalue < hash->hashsize);

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
	hash->count--;
	capwap_hash_free_item(hash, search);
}

/* */
struct capwap_hash* capwap_hash_create(unsigned long hashsize) {
	unsigned long size;
	struct capwap_hash* hash;

	ASSERT(hashsize > 0);

	/* */
	hash = (struct capwap_hash*)capwap_alloc(sizeof(struct capwap_hash));
	hash->hashsize = hashsize;
	hash->count = 0;

	size = sizeof(struct capwap_hash_item*) * hashsize;
	hash->items = (struct capwap_hash_item**)capwap_alloc(size);
	memset(hash->items, 0, size);

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
void capwap_hash_add(struct capwap_hash* hash, void* data) {
	int result;
	const void* key;
	unsigned long hashvalue;
	struct capwap_hash_item* search;
	struct capwap_hash_item* item = NULL;

	ASSERT(data != NULL);
	ASSERT(hash != NULL);
	ASSERT(hash->item_gethash != NULL);
	ASSERT(hash->item_getkey != NULL);
	ASSERT(hash->item_cmp != NULL);

	/* */
	key = hash->item_getkey(data);
	hashvalue = hash->item_gethash(key, hash->hashsize);
	ASSERT(hashvalue < hash->hashsize);

	/* Search position where insert item */
	search = hash->items[hashvalue];
	if (!search) {
		hash->count++;
		hash->items[hashvalue] = capwap_hash_create_item(hash, data);
	} else {
		while (search) {
			result = hash->item_cmp(key, hash->item_getkey(search->data));
			if (!result) {
				/* Free old element and update data value without create new item */
				if (search->data && hash->item_free) {
					hash->item_free(search->data);
				}

				search->data = data;
				break;
			} else if (result < 0) {
				if (search->left) {
					search = search->left;
				} else {
					hash->count++;
					item = capwap_hash_create_item(hash, data);
					capwap_hash_set_left_item(search, item);
					break;
				}
			} else if (result > 0) {
				if (search->right) {
					search = search->right;
				} else {
					hash->count++;
					item = capwap_hash_create_item(hash, data);
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

	ASSERT(hash != NULL);
	ASSERT(key != NULL);

	/* */
	hashvalue = hash->item_gethash(key, hash->hashsize);
	ASSERT(hashvalue < hash->hashsize);
	if (!hash->items[hashvalue]) {
		return;
	}

	/* */
	search = capwap_hash_search_items(hash, hash->items[hashvalue], key);
	if (!search) {
		return;
	}

	/* */
	capwap_hash_deleteitem(hash, key, search, hashvalue);
}

/* */
void capwap_hash_deleteall(struct capwap_hash* hash) {
	unsigned long i;

	ASSERT(hash != NULL);

	for (i = 0; i < hash->hashsize; i++) {
		if (hash->items[i]) {
			capwap_hash_free_items(hash, hash->items[i]);
			hash->items[i] = NULL;
		}
	}

	/* */
	hash->count = 0;
}

/* */
void* capwap_hash_search(struct capwap_hash* hash, const void* key) {
	unsigned long hashvalue;
	struct capwap_hash_item* items;
	struct capwap_hash_item* result;

	ASSERT(hash != NULL);
	ASSERT(key != NULL);

	/* Search item */
	hashvalue = hash->item_gethash(key, hash->hashsize);
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
	int result;
	unsigned long i;

	ASSERT(hash != NULL);
	ASSERT(item_foreach != NULL);

	/* */
	hash->removeitems = NULL;

	/* */
	for (i = 0; i < hash->hashsize; i++) {
		if (hash->items[i]) {
			result = capwap_hash_foreach_items(hash, hash->items[i], item_foreach, param);
			if (result == HASH_BREAK) {
				break;
			}
		}
	}

	/* Delete marked items */
	while (hash->removeitems) {
		struct capwap_hash_item* item = hash->removeitems;
		const void* key = hash->item_getkey(item->data);

		/* */
		hash->removeitems = item->removenext;
		capwap_hash_deleteitem(hash, key, item, hash->item_gethash(key, hash->hashsize));
	}
}
