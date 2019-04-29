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

#include <sys/zfs_context.h>
#include <sys/dsl_synctask.h>
#include <sys/dsl_pool.h>
#include <sys/dmu_objset.h>
#include <sys/zap_impl.h>
#include <sys/dmu_tx.h>
#include <sys/zap.h>
#include <sys/uzfs_zvol.h>
#include <uzfs_zap.h>

/*
 * update/add key-value entry in zvol zap object
 */
int
uzfs_update_zap_entries(void *zvol, const uzfs_zap_kv_t **array,
    uint64_t count)
{
	zvol_state_t *zv = (zvol_state_t *)zvol;
	objset_t *os = zv->zv_objset;
	dmu_tx_t *tx;
	const uzfs_zap_kv_t *kv;
	int err;
	int i = 0;

	/*
	 * micro zap will upgrade to fat-zap in following cases:
	 * 	1. key length is greater or equal to MZAP_NAME_LEN
	 *	2. value size is greater than 8
	 * To avoid this, update zap-entries only if key length < MZAP_NAME_LEN
	 * and value_size == 1.
	 */
	for (i = 0; i < count; i++) {
		kv = array[i];
		/*
		 * checks to avoid fat zap upgrade and value size
		 */
		if (strlen(kv->key) >= MZAP_NAME_LEN)
			return (EINVAL);
		if (kv->size != 8)
			return (EINVAL);
	}

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);

	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err) {
		dmu_tx_abort(tx);
		return (SET_ERROR(err));
	}

	for (i = 0; i < count; i++) {
		kv = array[i];
		VERIFY0(zap_update(os, ZVOL_ZAP_OBJ, kv->key, kv->size, 1,
		    &kv->value, tx));
	}

	dmu_tx_commit(tx);

	return (0);
}

/*
 * fetch value stored in zap object of zvol by key
 */
int
uzfs_read_zap_entry(void *zvol, uzfs_zap_kv_t *entry)
{
	zvol_state_t *zv = (zvol_state_t *)zvol;
	objset_t *os = zv->zv_objset;
	int err;

	err = zap_lookup(os, ZVOL_ZAP_OBJ, entry->key, entry->size, 1,
	    &entry->value);
	if (err)
		return (SET_ERROR(err));

	return (0);
}

void
update_txg_sync_impl(void *txg, dmu_tx_t *tx)
{
	objset_t *mos = dmu_tx_pool(tx)->dp_meta_objset;
	uint64_t zapobj = DMU_POOL_DIRECTORY_OBJECT;
	VERIFY0(zap_update(mos, zapobj, LAST_ITER_TXG, 1, 8, txg, tx));
}
