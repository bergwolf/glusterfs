#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#define __XOPEN_SOURCE 500

#include <stdint.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <ftw.h>
#include <sys/stat.h>
#include <signal.h>

#ifndef GF_BSD_HOST_OS
#include <alloca.h>
#endif /* GF_BSD_HOST_OS */

#include "glusterfs.h"
#include "checksum.h"
#include "dict.h"
#include "logging.h"
#include "bdb.h"
#include "xlator.h"
#include "defaults.h"
#include "common-utils.h"
#include "compat-errno.h"
#include "compat.h"
#include "byte-order.h"
#include "syscall.h"
#include "statedump.h"
#include "locking.h"
#include "timer.h"
#include "glusterfs3-xdr.h"
#include "hashfn.h"
#include "glusterfs-acl.h"
#include <fnmatch.h>

/* uuid of a file is saved in the same db as data of the file, with a seperate
 * key as <filename>_uuid.
 */
int
bdb_fill_gfid (xlator_t *this, const struct bdb_fd *bfd, struct iatt *iatt)
{
        int ret = 0;
        ssize_t size = 0;
        char *uuid_key;

        if (!iatt)
                return 0;

        MAKE_UUID_KEY_FROM_PATH(uuid_key, bfd->key);
        size = bdb_db_get(bfd->ctx, NULL, uuid_key, iatt->ia_gfid, 16, 0);
        /* Return value of getxattr */
        if ((size == 16) || (size == -1))
                ret = 0;
        else
                ret = size;

        return ret;
}

int
bdb_set_gfid (xlator_t *this, loc_t *loc, const bctx_t *ctx,
              const char *key, dict_t *xattr_req, uuid_t uuid_req)
{
        char        *uuid_key;
        struct stat  statbuf = {0, };
        int          ret = 0;


        if (!xattr_req || !key)
                goto out;

        ret = dict_get_ptr (xattr_req, "gfid-req", &uuid_req);
        if (ret) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "failed to get the gfid from dict for %s",
                        loc->path);
                goto out;
        }

        MAKE_UUID_KEY_FROM_PATH(uuid_key, bfd->key);
        ret = bdb_db_put (ctx, NULL, uuid_key, uuid_req, 16, 0, 0);
        if (ret < 0)
                gf_log (this->name, GF_LOG_ERROR,
                        "failed to save uuid for %s", loc->path);

out:
        return ret;
}

void
bdb_fill_ino_from_gfid (xlator_t *this, struct iatt *buf)
{
        uint64_t temp_ino = 0;
        int j = 0;
        int i = 0;

        /* consider least significant 8 bytes of value out of gfid */
        if (uuid_is_null (buf->ia_gfid)) {
                buf->ia_ino = -1;
                goto out;
        }
        for (i = 15; i > (15 - 8); i--) {
		temp_ino += (uint64_t)(buf->ia_gfid[i]) << j;
                j += 8;
        }
        buf->ia_ino = temp_ino;
out:
        return;
}

/* XXX: do we need to care about directories? */
int
bdb_fdstat (xlator_t *this, struct bdb_fd *bfd, struct iatt *stbuf_p)
{
        bctx_t        *pctx     = bfd->ctx;
        char          *db_path  = NULL;
        struct stat   stbuf;
        struct istat  istatbuf = {0, };
        int32_t       op_errno;
        int           ret;

        MAKE_REAL_PATH_TO_STORAGE_DB (db_path, this, pctx->directory);
        ret = lstat (db_path, &stbuf);
        op_errno = errno;
        if (ret != 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "FSTAT: %s(failed to stat database file %s)",
                        strerror (op_errno), db_path);
                goto out;
        }

        stbuf.st_size = bdb_db_fread (bfd, NULL, 0, 0);
        stbuf.st_blocks = BDB_COUNT_BLOCKS (stbuf.st_size, stbuf.st_blksize);
        iatt_from_stat (&istatbuf, &stbuf);

        if (bdb_fill_gfid (this, bfd, &istatbuf))
                gf_log_callingfn (this->name, GF_LOG_DEBUG, "failed to get gfid");

        bdb_fill_ino_from_gfid (this, &istatbuf);

        if (stbuf_p)
                *stbuf_p = istatbuf;
out:
        return ret;
}
