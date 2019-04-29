/*
 * Copyright © 2017-2019 The OpenEBS Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef	_UZFS_ZAP_H
#define	_UZFS_ZAP_H

#include <sys/spa.h>

typedef struct {
	char *key;	/* zap key to update */
	uint64_t value;	/* value to update against zap key */
	size_t size;	/* size of value */
} uzfs_zap_kv_t;

#define	LAST_ITER_TXG	"last_iter_txg"

/*
 * Here, allocation/freeing of kv_array needs to be handled by
 * caller function. uzfs_*_zap_entry will handle only microzap
 * entries or value with uint64_t entries.
 */
int uzfs_update_zap_entries(void *zv, const uzfs_zap_kv_t **kv_array,
    uint64_t n);
int uzfs_read_zap_entry(void *zv, uzfs_zap_kv_t *entry);
int uzfs_read_last_iter_txg(void *spa, uint64_t *val);
void uzfs_update_txg_zap_thread(void *s);
void uzfs_update_txg_interval(spa_t *spa, uint32_t timeout);

#endif
