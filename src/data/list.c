#include "list.h"

tg_list *tg_list_init(size_t initial_len, void (*free)(void *item))
{
	tg_list *list;

	if(initial_len > TG_LIST_PREALLOC)
	{
		initial_len -= TG_LIST_PREALLOC;
	}
	else
	{
		initial_len = 0;
	}

	list = calloc(1, sizeof(tg_list) + (sizeof(tg_list_item) * initial_len));

	assert(list);

	list->magic = TG_LIST_MAGIC;
	list->size = 0;
	list->prealloc_len = TG_LIST_PREALLOC + initial_len;
	list->callback = free;
	list->malloc = 1;

	TAILQ_INIT(&list->head);

	assert(!pthread_rwlock_init(&list->rwlock, NULL));

	return list;
}

static tg_list_item *tg_list_item_alloc(tg_list *list)
{
	tg_list_item *item;
	int i;

	//if(list->prealloc_len && !list->prealloc[list->prealloc_len - 1].magic)
	if(list->size < list->prealloc_len)
	{
		for(i = 0; i < list->prealloc_len; i++)
		{
			item = &list->prealloc[i];

			if(!item->magic)
			{
				item->magic = TG_LIST_ITEM_MAGIC;
				item->malloc = 0;

				return item;
			}
		}
	}

	item = malloc(sizeof(tg_list_item));

	assert(item);

	item->magic = TG_LIST_ITEM_MAGIC;
	item->malloc = 1;

	return item;
}

void tg_list_add(tg_list *list, void *value)
{
	tg_list_item *add;

	assert(list && list->magic == TG_LIST_MAGIC);
	assert(value);

	assert(!pthread_rwlock_wrlock(&list->rwlock));

	add = tg_list_item_alloc(list);

	add->value = value;

	TAILQ_INSERT_TAIL(&list->head, add, entry);

	list->size++;

	assert(!pthread_rwlock_unlock(&list->rwlock));
}

int tg_list_item_valid(tg_list_item *item)
{
	if(!item)
	{
		return 0;
	}
	
	assert(item->magic == TG_LIST_ITEM_MAGIC);

	return 1;
}

int tg_list_rlock(tg_list *list)
{
	assert(list && list->magic == TG_LIST_MAGIC);

	assert(!pthread_rwlock_rdlock(&list->rwlock));

	return 1;
}

int tg_list_unlock(tg_list *list)
{
	assert(list && list->magic == TG_LIST_MAGIC);
	
	assert(!pthread_rwlock_unlock(&list->rwlock));

	return 1;
}

void tg_list_free(tg_list *list)
{
	tg_list_item *item, *next;

	assert(list && list->magic == TG_LIST_MAGIC);

	assert(!pthread_rwlock_wrlock(&list->rwlock));

	TAILQ_FOREACH_SAFE(item, &list->head, entry, next) {
		TAILQ_REMOVE(&list->head, item, entry);

		assert(item->magic == TG_LIST_ITEM_MAGIC);

		if(list->callback)
		{
			list->callback(item->value);
		}

		item->magic = 0;

		if(item->malloc)
		{
			free(item);
		}

		list->size--;
	}

	assert(!list->size);

	TAILQ_INIT(&list->head);

	list->magic = 0;

	assert(!pthread_rwlock_unlock(&list->rwlock));

	assert(!pthread_rwlock_destroy(&list->rwlock));

	if(list->malloc)
	{
		free(list);
	}
}
