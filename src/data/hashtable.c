/*
 * Copyright (c) 2015 TextGlass
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

#include "hashtable.h"

tg_hashtable *tg_hashtable_alloc(size_t buckets, void (*callback)(void *value))
{
    tg_hashtable *hashtable;

    assert(buckets > 0);

    hashtable = malloc(sizeof(tg_hashtable));

    assert(hashtable);

    hashtable->magic = TG_HASHTABLE_MAGIC;
    hashtable->callback = callback;
    hashtable->dict = raxNew();

    assert(hashtable->dict);

    return hashtable;
}

void *tg_hashtable_get2(tg_hashtable *hashtable, const char *key, size_t key_len)
{
    void *ret = NULL;

    assert(hashtable && hashtable->magic == TG_HASHTABLE_MAGIC);
    assert(key);

    ret = raxFind(hashtable->dict, (unsigned char *)key, key_len);

    return ret == raxNotFound ? NULL : ret;
}

void *tg_hashtable_get(tg_hashtable *hashtable, const char *key)
{
    return tg_hashtable_get2(hashtable, key, strlen(key));
}

void tg_hashtable_set(tg_hashtable *hashtable, const char *key, void *value)
{
    assert(hashtable && hashtable->magic == TG_HASHTABLE_MAGIC);
    assert(key);
    assert(value);

    void *old = NULL;
    raxInsert(hashtable->dict, (unsigned char *)key, strlen(key), value, &old);

    if (old) {
        if (hashtable->callback) {
            hashtable->callback(old);
        }
    }
}

int tg_hashtable_delete(tg_hashtable *hashtable, const char *key)
{
    int ret = 0;

    assert(hashtable && hashtable->magic == TG_HASHTABLE_MAGIC);
    assert(key);

    void *old = NULL;
    int removed = raxRemove(hashtable->dict, (unsigned char *)key, strlen(key), &old);
    if (removed) {
        if (hashtable->callback) {
            hashtable->callback(old);
        }
        ret = 1;
    }

    return ret;
}

size_t tg_hashtable_size(tg_hashtable *hashtable)
{
    size_t size = 0;

    assert(hashtable && hashtable->magic == TG_HASHTABLE_MAGIC);

    size = raxSize(hashtable->dict);

    return size;
}

void tg_hashtable_free(tg_hashtable *hashtable)
{
    if (!hashtable) {
        return;
    }

    assert(hashtable && hashtable->magic == TG_HASHTABLE_MAGIC);

    if (hashtable->callback) {
        raxFreeWithCallback(hashtable->dict, hashtable->callback);
    } else {
        raxFree(hashtable->dict);
    }

    hashtable->magic = 0;

    free(hashtable);
}
