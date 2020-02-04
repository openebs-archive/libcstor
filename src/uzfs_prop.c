#include <zrepl_mgmt.h>
#include <uzfs_mgmt.h>
#include <mgmt_conn.h>

/*
 * This file defines function to set property of uzfs zvol
 */
int
uzfs_zinfo_update_rdonly(const char *name, const char *val)
{
	zvol_info_t *zinfo;
	int error;
	nvlist_t *props;

	/* fetch zinfo for given volume */
	zinfo = uzfs_zinfo_lookup(name);
	if (zinfo == NULL) {
		LOG_ERR("Invalid volume %s", name);
		return (EINVAL);
	}

	nvlist_alloc(&props, NV_UNIQUE_NAME, 0);
	nvlist_add_string(props,
	    zfs_prop_to_name(ZFS_PROP_ZVOL_READONLY), val);

	error = update_zvol_property(zinfo->main_zv, props);
	if (error) {
		LOG_ERR("Property updation failed(%d)", error);
		goto end;
	}

	if (IS_ZVOL_READONLY(zinfo->main_zv)) {
		disable_zinfo_mgmt_conn(zinfo);
	} else {
		enable_zinfo_mgmt_conn(zinfo);
	}

end:
	/* dropping refcount for uzfs_zinfo_lookup */
	uzfs_zinfo_drop_refcnt(zinfo);
	nvlist_free(props);
	return (error);
}

int
uzfs_zpool_rdonly_cb(const char *ds_name, void *arg)
{
	char *val = arg;
	zvol_info_t *zinfo;

	if (strrchr(ds_name, '@') != NULL) {
		return (0);
	}

	if (strchr(ds_name, '/') == NULL) {
		return (0);
	}

	if (is_internally_created_clone_volume(ds_name) == 0) {
		return (0);
	}

	/* fetch zinfo for given volume */
	zinfo = uzfs_zinfo_lookup(ds_name);
	if (zinfo == NULL) {
		LOG_ERR("Invalid volume %s", ds_name);
		return (EINVAL);
	}

	if (IS_ZVOL_READONLY(zinfo->main_zv)) {
		disable_zinfo_mgmt_conn(zinfo);
	} else {
		enable_zinfo_mgmt_conn(zinfo);
	}

	uzfs_zinfo_drop_refcnt(zinfo);
	return (0);
}
