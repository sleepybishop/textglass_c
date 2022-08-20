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

#ifndef _TG_HASHTABLE_H_INCLUDED_
#define _TG_HASHTABLE_H_INCLUDED_

#include <stdlib.h>
#include <string.h>

#ifndef _TEXTGLASS_SKIP_ASSERT
#include <assert.h>
#else
#define assert(e)
#endif

#include "rax.h"

typedef struct
{
	unsigned int			magic;
#define	TG_HASHTABLE_MAGIC		0x815BDDAB
	rax *dict;
	void				(*callback)(void*);
}
tg_hashtable;

tg_hashtable *tg_hashtable_alloc(size_t buckets, void (*callback)(void *value));
void *tg_hashtable_get(tg_hashtable *hashtable, const char *key);
void *tg_hashtable_get2(tg_hashtable *hashtable, const char *key, size_t key_len);
void tg_hashtable_set(tg_hashtable *hashtable, const char *key, void *value);
int tg_hashtable_delete(tg_hashtable *hashtable, const char *key);
size_t tg_hashtable_size(tg_hashtable *hashtable);
void tg_hashtable_free(tg_hashtable *hashtable);


#endif  /* _TG_HASHTABLE_H_INCLUDED_ */
