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

#ifndef	_UZFS_MGMT_H
#define	_UZFS_MGMT_H
#ifdef __cplusplus
extern "C" {
#endif
#include <sys/spa.h>
#include <sys/uzfs_zvol.h>

extern int uzfs_init(void);
extern int uzfs_create_pool(char *name, char *path, spa_t **spa);
extern int uzfs_open_pool(char *name, spa_t **spa);
extern int uzfs_vdev_add(spa_t *spa, char *path, int ashift, int log);
extern int uzfs_create_dataset(spa_t *spa, char *ds, uint64_t vol_size,
    uint64_t block_size, zvol_state_t **zv);
extern int uzfs_zvol_create_meta(objset_t *os, uint64_t block_size,
    uint64_t meta_block_size, dmu_tx_t *tx);
extern int uzfs_open_dataset(spa_t *spa, const char *ds, zvol_state_t **zv);
extern int uzfs_zvol_create_cb(const char *ds_name, void *n);
extern void uzfs_zvol_create_minors(spa_t *spa, const char *name);
extern int uzfs_zvol_destroy_cb(const char *ds_name, void *n);
extern uint64_t uzfs_synced_txg(zvol_state_t *zv);
extern void uzfs_close_dataset(zvol_state_t *zv);
extern void uzfs_close_pool(spa_t *spa);
extern void uzfs_fini(void);
extern uint64_t uzfs_random(uint64_t);
extern int uzfs_hold_dataset(zvol_state_t *zv);
extern void uzfs_rele_dataset(zvol_state_t *zv);
int get_snapshot_zv(zvol_state_t *zv, const char *snap_name,
    zvol_state_t **snap_zv, boolean_t fail_exists, boolean_t fail_notexists);
extern int destroy_snapshot_zv(zvol_state_t *zv, char *snap_name);

int uzfs_pool_create(const char *name, char *path, spa_t **spa);
#ifdef __cplusplus
}
#endif
#endif
