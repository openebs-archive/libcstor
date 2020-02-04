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
