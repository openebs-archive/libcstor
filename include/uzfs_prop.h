#ifndef	_UZFS_PROP_H
#define	_UZFS_PROP_H
#include <sys/nvpair.h>


#ifdef	__cplusplus
extern "C" {
#endif

int uzfs_zinfo_update_rdonly(const char *name, const char *val);

#ifdef	__cplusplus
}
#endif

#endif
