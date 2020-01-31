#include <zrepl_mgmt.h>
#include <uzfs_mgmt.h>

/*
 * This file defines function to set property of uzfs zvol
 */
int
uzfs_zfs_set_prop(const char *name, zprop_source_t source, nvlist_t *list)
{
	zvol_info_t *zinfo;
	int error;

	/* fetch zinfo for given volume */
	zinfo = uzfs_zinfo_lookup(name);
	if (zinfo == NULL) {
		LOG_ERR("Invalid volume %s", name);
		return (EINVAL);
	}

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	error = update_zvol_property(zinfo->main_zv, list);
	if (error) {
		LOG_ERR("Property updation failed(%d)", error);
		goto end;
	}

	if (error == 0 && zinfo->clone_zv != NULL) {
		error = update_zvol_property(zinfo->clone_zv, list);
		if (error) {
			LOG_ERR("Updation property failed(%d)", error);
			goto end;
		}

	}

end:
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
	/* dropping refcount for uzfs_zinfo_lookup */
	uzfs_zinfo_drop_refcnt(zinfo);
	return (error);
}
