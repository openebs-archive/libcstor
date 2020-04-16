/*
 * Copyright © 2020 The OpenEBS Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef	_UZFS_PROP_H
#define	_UZFS_PROP_H
#include <sys/nvpair.h>


#ifdef	__cplusplus
extern "C" {
#endif

int uzfs_zinfo_update_rdonly(const char *name, const char *val);

int uzfs_zpool_rdonly_cb(const char *name, void *arg);
#ifdef	__cplusplus
}
#endif

#endif
