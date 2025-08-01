// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2008 Red Hat, Inc.  All rights reserved.
 */

#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/buffer_head.h>
#include <linux/gfs2_ondisk.h>
#include <linux/bio.h>
#include <linux/posix_acl.h>
#include <linux/security.h>
#include <linux/log2.h>

#include "gfs2.h"
#include "incore.h"
#include "bmap.h"
#include "glock.h"
#include "glops.h"
#include "inode.h"
#include "log.h"
#include "meta_io.h"
#include "recovery.h"
#include "rgrp.h"
#include "util.h"
#include "trans.h"
#include "dir.h"
#include "lops.h"

struct workqueue_struct *gfs2_freeze_wq;

extern struct workqueue_struct *gfs2_control_wq;

static void gfs2_ail_error(struct gfs2_glock *gl, const struct buffer_head *bh)
{
	struct gfs2_sbd *sdp = gl->gl_name.ln_sbd;

	fs_err(sdp,
	       "AIL buffer %p: blocknr %llu state 0x%08lx mapping %p page "
	       "state 0x%lx\n",
	       bh, (unsigned long long)bh->b_blocknr, bh->b_state,
	       bh->b_folio->mapping, bh->b_folio->flags);
	fs_err(sdp, "AIL glock %u:%llu mapping %p\n",
	       gl->gl_name.ln_type, gl->gl_name.ln_number,
	       gfs2_glock2aspace(gl));
	gfs2_lm(sdp, "AIL error\n");
	gfs2_withdraw_delayed(sdp);
}

/**
 * __gfs2_ail_flush - remove all buffers for a given lock from the AIL
 * @gl: the glock
 * @fsync: set when called from fsync (not all buffers will be clean)
 * @nr_revokes: Number of buffers to revoke
 *
 * None of the buffers should be dirty, locked, or pinned.
 */

static void __gfs2_ail_flush(struct gfs2_glock *gl, bool fsync,
			     unsigned int nr_revokes)
{
	struct gfs2_sbd *sdp = gl->gl_name.ln_sbd;
	struct list_head *head = &gl->gl_ail_list;
	struct gfs2_bufdata *bd, *tmp;
	struct buffer_head *bh;
	const unsigned long b_state = (1UL << BH_Dirty)|(1UL << BH_Pinned)|(1UL << BH_Lock);

	gfs2_log_lock(sdp);
	spin_lock(&sdp->sd_ail_lock);
	list_for_each_entry_safe_reverse(bd, tmp, head, bd_ail_gl_list) {
		if (nr_revokes == 0)
			break;
		bh = bd->bd_bh;
		if (bh->b_state & b_state) {
			if (fsync)
				continue;
			gfs2_ail_error(gl, bh);
		}
		gfs2_trans_add_revoke(sdp, bd);
		nr_revokes--;
	}
	GLOCK_BUG_ON(gl, !fsync && atomic_read(&gl->gl_ail_count));
	spin_unlock(&sdp->sd_ail_lock);
	gfs2_log_unlock(sdp);

	if (gfs2_withdrawing(sdp))
		gfs2_withdraw(sdp);
}


static int gfs2_ail_empty_gl(struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_name.ln_sbd;
	struct gfs2_trans tr;
	unsigned int revokes;
	int ret = 0;

	revokes = atomic_read(&gl->gl_ail_count);

	if (!revokes) {
		bool have_revokes;
		bool log_in_flight;

		/*
		 * We have nothing on the ail, but there could be revokes on
		 * the sdp revoke queue, in which case, we still want to flush
		 * the log and wait for it to finish.
		 *
		 * If the sdp revoke list is empty too, we might still have an
		 * io outstanding for writing revokes, so we should wait for
		 * it before returning.
		 *
		 * If none of these conditions are true, our revokes are all
		 * flushed and we can return.
		 */
		gfs2_log_lock(sdp);
		have_revokes = !list_empty(&sdp->sd_log_revokes);
		log_in_flight = atomic_read(&sdp->sd_log_in_flight);
		gfs2_log_unlock(sdp);
		if (have_revokes)
			goto flush;
		if (log_in_flight)
			log_flush_wait(sdp);
		return 0;
	}

	memset(&tr, 0, sizeof(tr));
	set_bit(TR_ONSTACK, &tr.tr_flags);
	ret = __gfs2_trans_begin(&tr, sdp, 0, revokes, _RET_IP_);
	if (ret) {
		fs_err(sdp, "Transaction error %d: Unable to write revokes.", ret);
		goto flush;
	}
	__gfs2_ail_flush(gl, 0, revokes);
	gfs2_trans_end(sdp);

flush:
	if (!ret)
		gfs2_log_flush(sdp, NULL, GFS2_LOG_HEAD_FLUSH_NORMAL |
				GFS2_LFC_AIL_EMPTY_GL);
	return ret;
}

void gfs2_ail_flush(struct gfs2_glock *gl, bool fsync)
{
	struct gfs2_sbd *sdp = gl->gl_name.ln_sbd;
	unsigned int revokes = atomic_read(&gl->gl_ail_count);
	int ret;

	if (!revokes)
		return;

	ret = gfs2_trans_begin(sdp, 0, revokes);
	if (ret)
		return;
	__gfs2_ail_flush(gl, fsync, revokes);
	gfs2_trans_end(sdp);
	gfs2_log_flush(sdp, NULL, GFS2_LOG_HEAD_FLUSH_NORMAL |
		       GFS2_LFC_AIL_FLUSH);
}

/**
 * gfs2_rgrp_metasync - sync out the metadata of a resource group
 * @gl: the glock protecting the resource group
 *
 */

static int gfs2_rgrp_metasync(struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_name.ln_sbd;
	struct address_space *metamapping = gfs2_aspace(sdp);
	struct gfs2_rgrpd *rgd = gfs2_glock2rgrp(gl);
	const unsigned bsize = sdp->sd_sb.sb_bsize;
	loff_t start = (rgd->rd_addr * bsize) & PAGE_MASK;
	loff_t end = PAGE_ALIGN((rgd->rd_addr + rgd->rd_length) * bsize) - 1;
	int error;

	filemap_fdatawrite_range(metamapping, start, end);
	error = filemap_fdatawait_range(metamapping, start, end);
	WARN_ON_ONCE(error && !gfs2_withdrawing_or_withdrawn(sdp));
	mapping_set_error(metamapping, error);
	if (error)
		gfs2_io_error(sdp);
	return error;
}

/**
 * rgrp_go_sync - sync out the metadata for this glock
 * @gl: the glock
 *
 * Called when demoting or unlocking an EX glock.  We must flush
 * to disk all dirty buffers/pages relating to this glock, and must not
 * return to caller to demote/unlock the glock until I/O is complete.
 */

static int rgrp_go_sync(struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_name.ln_sbd;
	struct gfs2_rgrpd *rgd = gfs2_glock2rgrp(gl);
	int error;

	if (!rgd || !test_and_clear_bit(GLF_DIRTY, &gl->gl_flags))
		return 0;
	GLOCK_BUG_ON(gl, gl->gl_state != LM_ST_EXCLUSIVE);

	gfs2_log_flush(sdp, gl, GFS2_LOG_HEAD_FLUSH_NORMAL |
		       GFS2_LFC_RGRP_GO_SYNC);
	error = gfs2_rgrp_metasync(gl);
	if (!error)
		error = gfs2_ail_empty_gl(gl);
	gfs2_free_clones(rgd);
	return error;
}

/**
 * rgrp_go_inval - invalidate the metadata for this glock
 * @gl: the glock
 * @flags:
 *
 * We never used LM_ST_DEFERRED with resource groups, so that we
 * should always see the metadata flag set here.
 *
 */

static void rgrp_go_inval(struct gfs2_glock *gl, int flags)
{
	struct gfs2_sbd *sdp = gl->gl_name.ln_sbd;
	struct address_space *mapping = gfs2_aspace(sdp);
	struct gfs2_rgrpd *rgd = gfs2_glock2rgrp(gl);
	const unsigned bsize = sdp->sd_sb.sb_bsize;
	loff_t start, end;

	if (!rgd)
		return;
	start = (rgd->rd_addr * bsize) & PAGE_MASK;
	end = PAGE_ALIGN((rgd->rd_addr + rgd->rd_length) * bsize) - 1;
	gfs2_rgrp_brelse(rgd);
	WARN_ON_ONCE(!(flags & DIO_METADATA));
	truncate_inode_pages_range(mapping, start, end);
}

static void gfs2_rgrp_go_dump(struct seq_file *seq, const struct gfs2_glock *gl,
			      const char *fs_id_buf)
{
	struct gfs2_rgrpd *rgd = gl->gl_object;

	if (rgd)
		gfs2_rgrp_dump(seq, rgd, fs_id_buf);
}

static struct gfs2_inode *gfs2_glock2inode(struct gfs2_glock *gl)
{
	struct gfs2_inode *ip;

	spin_lock(&gl->gl_lockref.lock);
	ip = gl->gl_object;
	if (ip)
		set_bit(GIF_GLOP_PENDING, &ip->i_flags);
	spin_unlock(&gl->gl_lockref.lock);
	return ip;
}

struct gfs2_rgrpd *gfs2_glock2rgrp(struct gfs2_glock *gl)
{
	struct gfs2_rgrpd *rgd;

	spin_lock(&gl->gl_lockref.lock);
	rgd = gl->gl_object;
	spin_unlock(&gl->gl_lockref.lock);

	return rgd;
}

static void gfs2_clear_glop_pending(struct gfs2_inode *ip)
{
	if (!ip)
		return;

	clear_bit_unlock(GIF_GLOP_PENDING, &ip->i_flags);
	wake_up_bit(&ip->i_flags, GIF_GLOP_PENDING);
}

/**
 * gfs2_inode_metasync - sync out the metadata of an inode
 * @gl: the glock protecting the inode
 *
 */
int gfs2_inode_metasync(struct gfs2_glock *gl)
{
	struct address_space *metamapping = gfs2_glock2aspace(gl);
	int error;

	filemap_fdatawrite(metamapping);
	error = filemap_fdatawait(metamapping);
	if (error)
		gfs2_io_error(gl->gl_name.ln_sbd);
	return error;
}

/**
 * inode_go_sync - Sync the dirty metadata of an inode
 * @gl: the glock protecting the inode
 *
 */

static int inode_go_sync(struct gfs2_glock *gl)
{
	struct gfs2_inode *ip = gfs2_glock2inode(gl);
	int isreg = ip && S_ISREG(ip->i_inode.i_mode);
	struct address_space *metamapping = gfs2_glock2aspace(gl);
	int error = 0, ret;

	if (isreg) {
		if (test_and_clear_bit(GIF_SW_PAGED, &ip->i_flags))
			unmap_shared_mapping_range(ip->i_inode.i_mapping, 0, 0);
		inode_dio_wait(&ip->i_inode);
	}
	if (!test_and_clear_bit(GLF_DIRTY, &gl->gl_flags))
		goto out;

	GLOCK_BUG_ON(gl, gl->gl_state != LM_ST_EXCLUSIVE);

	gfs2_log_flush(gl->gl_name.ln_sbd, gl, GFS2_LOG_HEAD_FLUSH_NORMAL |
		       GFS2_LFC_INODE_GO_SYNC);
	filemap_fdatawrite(metamapping);
	if (isreg) {
		struct address_space *mapping = ip->i_inode.i_mapping;
		filemap_fdatawrite(mapping);
		error = filemap_fdatawait(mapping);
		mapping_set_error(mapping, error);
	}
	ret = gfs2_inode_metasync(gl);
	if (!error)
		error = ret;
	ret = gfs2_ail_empty_gl(gl);
	if (!error)
		error = ret;
	/*
	 * Writeback of the data mapping may cause the dirty flag to be set
	 * so we have to clear it again here.
	 */
	smp_mb__before_atomic();
	clear_bit(GLF_DIRTY, &gl->gl_flags);

out:
	gfs2_clear_glop_pending(ip);
	return error;
}

/**
 * inode_go_inval - prepare a inode glock to be released
 * @gl: the glock
 * @flags:
 *
 * Normally we invalidate everything, but if we are moving into
 * LM_ST_DEFERRED from LM_ST_SHARED or LM_ST_EXCLUSIVE then we
 * can keep hold of the metadata, since it won't have changed.
 *
 */

static void inode_go_inval(struct gfs2_glock *gl, int flags)
{
	struct gfs2_inode *ip = gfs2_glock2inode(gl);

	if (flags & DIO_METADATA) {
		struct address_space *mapping = gfs2_glock2aspace(gl);
		truncate_inode_pages(mapping, 0);
		if (ip) {
			set_bit(GLF_INSTANTIATE_NEEDED, &gl->gl_flags);
			forget_all_cached_acls(&ip->i_inode);
			security_inode_invalidate_secctx(&ip->i_inode);
			gfs2_dir_hash_inval(ip);
		}
	}

	if (ip == GFS2_I(gl->gl_name.ln_sbd->sd_rindex)) {
		gfs2_log_flush(gl->gl_name.ln_sbd, NULL,
			       GFS2_LOG_HEAD_FLUSH_NORMAL |
			       GFS2_LFC_INODE_GO_INVAL);
		gl->gl_name.ln_sbd->sd_rindex_uptodate = 0;
	}
	if (ip && S_ISREG(ip->i_inode.i_mode))
		truncate_inode_pages(ip->i_inode.i_mapping, 0);

	gfs2_clear_glop_pending(ip);
}

static int gfs2_dinode_in(struct gfs2_inode *ip, const void *buf)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	const struct gfs2_dinode *str = buf;
	struct timespec64 atime, iatime;
	u16 height, depth;
	umode_t mode = be32_to_cpu(str->di_mode);
	struct inode *inode = &ip->i_inode;
	bool is_new = inode->i_state & I_NEW;

	if (unlikely(ip->i_no_addr != be64_to_cpu(str->di_num.no_addr))) {
		gfs2_consist_inode(ip);
		return -EIO;
	}
	if (unlikely(!is_new && inode_wrong_type(inode, mode))) {
		gfs2_consist_inode(ip);
		return -EIO;
	}
	ip->i_no_formal_ino = be64_to_cpu(str->di_num.no_formal_ino);
	inode->i_mode = mode;
	if (is_new) {
		inode->i_rdev = 0;
		switch (mode & S_IFMT) {
		case S_IFBLK:
		case S_IFCHR:
			inode->i_rdev = MKDEV(be32_to_cpu(str->di_major),
					      be32_to_cpu(str->di_minor));
			break;
		}
	}

	i_uid_write(inode, be32_to_cpu(str->di_uid));
	i_gid_write(inode, be32_to_cpu(str->di_gid));
	set_nlink(inode, be32_to_cpu(str->di_nlink));
	i_size_write(inode, be64_to_cpu(str->di_size));
	gfs2_set_inode_blocks(inode, be64_to_cpu(str->di_blocks));
	atime.tv_sec = be64_to_cpu(str->di_atime);
	atime.tv_nsec = be32_to_cpu(str->di_atime_nsec);
	iatime = inode_get_atime(inode);
	if (timespec64_compare(&iatime, &atime) < 0)
		inode_set_atime_to_ts(inode, atime);
	inode_set_mtime(inode, be64_to_cpu(str->di_mtime),
			be32_to_cpu(str->di_mtime_nsec));
	inode_set_ctime(inode, be64_to_cpu(str->di_ctime),
			be32_to_cpu(str->di_ctime_nsec));

	ip->i_goal = be64_to_cpu(str->di_goal_meta);
	ip->i_generation = be64_to_cpu(str->di_generation);

	ip->i_diskflags = be32_to_cpu(str->di_flags);
	ip->i_eattr = be64_to_cpu(str->di_eattr);
	/* i_diskflags and i_eattr must be set before gfs2_set_inode_flags() */
	gfs2_set_inode_flags(inode);
	height = be16_to_cpu(str->di_height);
	if (unlikely(height > sdp->sd_max_height)) {
		gfs2_consist_inode(ip);
		return -EIO;
	}
	ip->i_height = (u8)height;

	depth = be16_to_cpu(str->di_depth);
	if (unlikely(depth > GFS2_DIR_MAX_DEPTH)) {
		gfs2_consist_inode(ip);
		return -EIO;
	}
	if ((ip->i_diskflags & GFS2_DIF_EXHASH) &&
	    depth < ilog2(sdp->sd_hash_ptrs)) {
		gfs2_consist_inode(ip);
		return -EIO;
	}
	ip->i_depth = (u8)depth;
	ip->i_entries = be32_to_cpu(str->di_entries);

	if (gfs2_is_stuffed(ip) && inode->i_size > gfs2_max_stuffed_size(ip)) {
		gfs2_consist_inode(ip);
		return -EIO;
	}
	if (S_ISREG(inode->i_mode))
		gfs2_set_aops(inode);

	return 0;
}

/**
 * gfs2_inode_refresh - Refresh the incore copy of the dinode
 * @ip: The GFS2 inode
 *
 * Returns: errno
 */

static int gfs2_inode_refresh(struct gfs2_inode *ip)
{
	struct buffer_head *dibh;
	int error;

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		return error;

	error = gfs2_dinode_in(ip, dibh->b_data);
	brelse(dibh);
	return error;
}

/**
 * inode_go_instantiate - read in an inode if necessary
 * @gl: The glock
 *
 * Returns: errno
 */

static int inode_go_instantiate(struct gfs2_glock *gl)
{
	struct gfs2_inode *ip = gl->gl_object;
	struct gfs2_glock *io_gl;
	int error;

	if (!ip) /* no inode to populate - read it in later */
		return 0;

	error = gfs2_inode_refresh(ip);
	if (error)
		return error;
	io_gl = ip->i_iopen_gh.gh_gl;
	io_gl->gl_no_formal_ino = ip->i_no_formal_ino;
	return 0;
}

static int inode_go_held(struct gfs2_holder *gh)
{
	struct gfs2_glock *gl = gh->gh_gl;
	struct gfs2_inode *ip = gl->gl_object;
	int error = 0;

	if (!ip) /* no inode to populate - read it in later */
		return 0;

	if (gh->gh_state != LM_ST_DEFERRED)
		inode_dio_wait(&ip->i_inode);

	if ((ip->i_diskflags & GFS2_DIF_TRUNC_IN_PROG) &&
	    (gl->gl_state == LM_ST_EXCLUSIVE) &&
	    (gh->gh_state == LM_ST_EXCLUSIVE))
		error = gfs2_truncatei_resume(ip);

	return error;
}

/**
 * inode_go_dump - print information about an inode
 * @seq: The iterator
 * @gl: The glock
 * @fs_id_buf: file system id (may be empty)
 *
 */

static void inode_go_dump(struct seq_file *seq, const struct gfs2_glock *gl,
			  const char *fs_id_buf)
{
	struct gfs2_inode *ip = gl->gl_object;
	const struct inode *inode = &ip->i_inode;

	if (ip == NULL)
		return;

	gfs2_print_dbg(seq, "%s I: n:%llu/%llu t:%u f:0x%02lx d:0x%08x s:%llu "
		       "p:%lu\n", fs_id_buf,
		  (unsigned long long)ip->i_no_formal_ino,
		  (unsigned long long)ip->i_no_addr,
		  IF2DT(inode->i_mode), ip->i_flags,
		  (unsigned int)ip->i_diskflags,
		  (unsigned long long)i_size_read(inode),
		  inode->i_data.nrpages);
}

/**
 * freeze_go_callback - A cluster node is requesting a freeze
 * @gl: the glock
 * @remote: true if this came from a different cluster node
 */

static void freeze_go_callback(struct gfs2_glock *gl, bool remote)
{
	struct gfs2_sbd *sdp = gl->gl_name.ln_sbd;
	struct super_block *sb = sdp->sd_vfs;

	if (!remote ||
	    (gl->gl_state != LM_ST_SHARED &&
	     gl->gl_state != LM_ST_UNLOCKED) ||
	    gl->gl_demote_state != LM_ST_UNLOCKED)
		return;

	/*
	 * Try to get an active super block reference to prevent racing with
	 * unmount (see super_trylock_shared()).  But note that unmount isn't
	 * the only place where a write lock on s_umount is taken, and we can
	 * fail here because of things like remount as well.
	 */
	if (down_read_trylock(&sb->s_umount)) {
		atomic_inc(&sb->s_active);
		up_read(&sb->s_umount);
		if (!queue_work(gfs2_freeze_wq, &sdp->sd_freeze_work))
			deactivate_super(sb);
	}
}

/**
 * freeze_go_xmote_bh - After promoting/demoting the freeze glock
 * @gl: the glock
 */
static int freeze_go_xmote_bh(struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_name.ln_sbd;
	struct gfs2_inode *ip = GFS2_I(sdp->sd_jdesc->jd_inode);
	struct gfs2_glock *j_gl = ip->i_gl;
	struct gfs2_log_header_host head;
	int error;

	if (test_bit(SDF_JOURNAL_LIVE, &sdp->sd_flags)) {
		j_gl->gl_ops->go_inval(j_gl, DIO_METADATA);

		error = gfs2_find_jhead(sdp->sd_jdesc, &head);
		if (gfs2_assert_withdraw_delayed(sdp, !error))
			return error;
		if (gfs2_assert_withdraw_delayed(sdp, head.lh_flags &
						 GFS2_LOG_HEAD_UNMOUNT))
			return -EIO;
		gfs2_log_pointers_init(sdp, &head);
	}
	return 0;
}

/**
 * iopen_go_callback - schedule the dcache entry for the inode to be deleted
 * @gl: the glock
 * @remote: true if this came from a different cluster node
 *
 * gl_lockref.lock lock is held while calling this
 */
static void iopen_go_callback(struct gfs2_glock *gl, bool remote)
{
	struct gfs2_inode *ip = gl->gl_object;
	struct gfs2_sbd *sdp = gl->gl_name.ln_sbd;

	if (!remote || sb_rdonly(sdp->sd_vfs) ||
	    test_bit(SDF_KILL, &sdp->sd_flags))
		return;

	if (gl->gl_demote_state == LM_ST_UNLOCKED &&
	    gl->gl_state == LM_ST_SHARED && ip) {
		gl->gl_lockref.count++;
		if (!gfs2_queue_try_to_evict(gl))
			gl->gl_lockref.count--;
	}
}

/**
 * inode_go_unlocked - wake up anyone waiting for dlm's unlock ast
 * @gl: glock being unlocked
 *
 * For now, this is only used for the journal inode glock. In withdraw
 * situations, we need to wait for the glock to be unlocked so that we know
 * other nodes may proceed with recovery / journal replay.
 */
static void inode_go_unlocked(struct gfs2_glock *gl)
{
	/* Note that we cannot reference gl_object because it's already set
	 * to NULL by this point in its lifecycle. */
	if (!test_bit(GLF_UNLOCKED, &gl->gl_flags))
		return;
	clear_bit_unlock(GLF_UNLOCKED, &gl->gl_flags);
	wake_up_bit(&gl->gl_flags, GLF_UNLOCKED);
}

/**
 * nondisk_go_callback - used to signal when a node did a withdraw
 * @gl: the nondisk glock
 * @remote: true if this came from a different cluster node
 *
 */
static void nondisk_go_callback(struct gfs2_glock *gl, bool remote)
{
	struct gfs2_sbd *sdp = gl->gl_name.ln_sbd;

	/* Ignore the callback unless it's from another node, and it's the
	   live lock. */
	if (!remote || gl->gl_name.ln_number != GFS2_LIVE_LOCK)
		return;

	/* First order of business is to cancel the demote request. We don't
	 * really want to demote a nondisk glock. At best it's just to inform
	 * us of another node's withdraw. We'll keep it in SH mode. */
	clear_bit(GLF_DEMOTE, &gl->gl_flags);
	clear_bit(GLF_PENDING_DEMOTE, &gl->gl_flags);

	/* Ignore the unlock if we're withdrawn, unmounting, or in recovery. */
	if (test_bit(SDF_NORECOVERY, &sdp->sd_flags) ||
	    test_bit(SDF_WITHDRAWN, &sdp->sd_flags) ||
	    test_bit(SDF_REMOTE_WITHDRAW, &sdp->sd_flags))
		return;

	/* We only care when a node wants us to unlock, because that means
	 * they want a journal recovered. */
	if (gl->gl_demote_state != LM_ST_UNLOCKED)
		return;

	if (sdp->sd_args.ar_spectator) {
		fs_warn(sdp, "Spectator node cannot recover journals.\n");
		return;
	}

	fs_warn(sdp, "Some node has withdrawn; checking for recovery.\n");
	set_bit(SDF_REMOTE_WITHDRAW, &sdp->sd_flags);
	/*
	 * We can't call remote_withdraw directly here or gfs2_recover_journal
	 * because this is called from the glock unlock function and the
	 * remote_withdraw needs to enqueue and dequeue the same "live" glock
	 * we were called from. So we queue it to the control work queue in
	 * lock_dlm.
	 */
	queue_delayed_work(gfs2_control_wq, &sdp->sd_control_work, 0);
}

const struct gfs2_glock_operations gfs2_meta_glops = {
	.go_type = LM_TYPE_META,
	.go_flags = GLOF_NONDISK,
};

const struct gfs2_glock_operations gfs2_inode_glops = {
	.go_sync = inode_go_sync,
	.go_inval = inode_go_inval,
	.go_instantiate = inode_go_instantiate,
	.go_held = inode_go_held,
	.go_dump = inode_go_dump,
	.go_type = LM_TYPE_INODE,
	.go_flags = GLOF_ASPACE | GLOF_LVB,
	.go_unlocked = inode_go_unlocked,
};

const struct gfs2_glock_operations gfs2_rgrp_glops = {
	.go_sync = rgrp_go_sync,
	.go_inval = rgrp_go_inval,
	.go_instantiate = gfs2_rgrp_go_instantiate,
	.go_dump = gfs2_rgrp_go_dump,
	.go_type = LM_TYPE_RGRP,
	.go_flags = GLOF_LVB,
};

const struct gfs2_glock_operations gfs2_freeze_glops = {
	.go_xmote_bh = freeze_go_xmote_bh,
	.go_callback = freeze_go_callback,
	.go_type = LM_TYPE_NONDISK,
	.go_flags = GLOF_NONDISK,
};

const struct gfs2_glock_operations gfs2_iopen_glops = {
	.go_type = LM_TYPE_IOPEN,
	.go_callback = iopen_go_callback,
	.go_dump = inode_go_dump,
	.go_flags = GLOF_NONDISK,
	.go_subclass = 1,
};

const struct gfs2_glock_operations gfs2_flock_glops = {
	.go_type = LM_TYPE_FLOCK,
	.go_flags = GLOF_NONDISK,
};

const struct gfs2_glock_operations gfs2_nondisk_glops = {
	.go_type = LM_TYPE_NONDISK,
	.go_flags = GLOF_NONDISK,
	.go_callback = nondisk_go_callback,
};

const struct gfs2_glock_operations gfs2_quota_glops = {
	.go_type = LM_TYPE_QUOTA,
	.go_flags = GLOF_LVB | GLOF_NONDISK,
};

const struct gfs2_glock_operations gfs2_journal_glops = {
	.go_type = LM_TYPE_JOURNAL,
	.go_flags = GLOF_NONDISK,
};

const struct gfs2_glock_operations *gfs2_glops_list[] = {
	[LM_TYPE_META] = &gfs2_meta_glops,
	[LM_TYPE_INODE] = &gfs2_inode_glops,
	[LM_TYPE_RGRP] = &gfs2_rgrp_glops,
	[LM_TYPE_IOPEN] = &gfs2_iopen_glops,
	[LM_TYPE_FLOCK] = &gfs2_flock_glops,
	[LM_TYPE_NONDISK] = &gfs2_nondisk_glops,
	[LM_TYPE_QUOTA] = &gfs2_quota_glops,
	[LM_TYPE_JOURNAL] = &gfs2_journal_glops,
};

