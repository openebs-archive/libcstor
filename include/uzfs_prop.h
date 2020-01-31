#ifndef	_UZFS_PROP_H
#define	_UZFS_PROP_H
#include <sys/nvpair.h>


#ifdef	__cplusplus
extern "C" {
#endif

int uzfs_zfs_set_prop(const char *name, zprop_source_t source, nvlist_t *list);

#ifdef	__cplusplus
}
#endif

#endif
