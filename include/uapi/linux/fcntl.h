/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_FCNTL_H
#define _UAPI_LINUX_FCNTL_H

#include <asm/fcntl.h>
#include <linux/openat2.h>

#define F_SETLEASE	(F_LINUX_SPECIFIC_BASE + 0)
#define F_GETLEASE	(F_LINUX_SPECIFIC_BASE + 1)

/*
 * Request nofications on a directory.
 * See below for events that may be notified.
 */
#define F_NOTIFY	(F_LINUX_SPECIFIC_BASE + 2)

#define F_DUPFD_QUERY	(F_LINUX_SPECIFIC_BASE + 3)

/* Was the file just created? */
#define F_CREATED_QUERY	(F_LINUX_SPECIFIC_BASE + 4)

/*
 * Cancel a blocking posix lock; internal use only until we expose an
 * asynchronous lock api to userspace:
 */
#define F_CANCELLK	(F_LINUX_SPECIFIC_BASE + 5)

/* Create a file descriptor with FD_CLOEXEC set. */
#define F_DUPFD_CLOEXEC	(F_LINUX_SPECIFIC_BASE + 6)

/*
 * Set and get of pipe page size array
 */
#define F_SETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 7)
#define F_GETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 8)

/*
 * Set/Get seals
 */
#define F_ADD_SEALS	(F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS	(F_LINUX_SPECIFIC_BASE + 10)

/*
 * Types of seals
 */
#define F_SEAL_SEAL	0x0001	/* prevent further seals from being set */
#define F_SEAL_SHRINK	0x0002	/* prevent file from shrinking */
#define F_SEAL_GROW	0x0004	/* prevent file from growing */
#define F_SEAL_WRITE	0x0008	/* prevent writes */
#define F_SEAL_FUTURE_WRITE	0x0010  /* prevent future writes while mapped */
#define F_SEAL_EXEC	0x0020  /* prevent chmod modifying exec bits */
/* (1U << 31) is reserved for signed error codes */

/*
 * Set/Get write life time hints. {GET,SET}_RW_HINT operate on the
 * underlying inode, while {GET,SET}_FILE_RW_HINT operate only on
 * the specific file.
 */
#define F_GET_RW_HINT		(F_LINUX_SPECIFIC_BASE + 11)
#define F_SET_RW_HINT		(F_LINUX_SPECIFIC_BASE + 12)
#define F_GET_FILE_RW_HINT	(F_LINUX_SPECIFIC_BASE + 13)
#define F_SET_FILE_RW_HINT	(F_LINUX_SPECIFIC_BASE + 14)

/*
 * Valid hint values for F_{GET,SET}_RW_HINT. 0 is "not set", or can be
 * used to clear any hints previously set.
 */
#define RWH_WRITE_LIFE_NOT_SET	0
#define RWH_WRITE_LIFE_NONE	1
#define RWH_WRITE_LIFE_SHORT	2
#define RWH_WRITE_LIFE_MEDIUM	3
#define RWH_WRITE_LIFE_LONG	4
#define RWH_WRITE_LIFE_EXTREME	5

/*
 * The originally introduced spelling is remained from the first
 * versions of the patch set that introduced the feature, see commit
 * v4.13-rc1~212^2~51.
 */
#define RWF_WRITE_LIFE_NOT_SET	RWH_WRITE_LIFE_NOT_SET

/*
 * Types of directory notifications that may be requested.
 */
#define DN_ACCESS	0x00000001	/* File accessed */
#define DN_MODIFY	0x00000002	/* File modified */
#define DN_CREATE	0x00000004	/* File created */
#define DN_DELETE	0x00000008	/* File removed */
#define DN_RENAME	0x00000010	/* File renamed */
#define DN_ATTRIB	0x00000020	/* File changed attibutes */
#define DN_MULTISHOT	0x80000000	/* Don't remove notifier */

/* Reserved kernel ranges [-100], [-10000, -40000]. */
#define AT_FDCWD		-100    /* Special value for dirfd used to
					   indicate openat should use the
					   current working directory. */

/*
 * The concept of process and threads in userland and the kernel is a confusing
 * one - within the kernel every thread is a 'task' with its own individual PID,
 * however from userland's point of view threads are grouped by a single PID,
 * which is that of the 'thread group leader', typically the first thread
 * spawned.
 *
 * To cut the Gideon knot, for internal kernel usage, we refer to
 * PIDFD_SELF_THREAD to refer to the current thread (or task from a kernel
 * perspective), and PIDFD_SELF_THREAD_GROUP to refer to the current thread
 * group leader...
 */
#define PIDFD_SELF_THREAD		-10000 /* Current thread. */
#define PIDFD_SELF_THREAD_GROUP		-10001 /* Current thread group leader. */

#define FD_PIDFS_ROOT			-10002 /* Root of the pidfs filesystem */
#define FD_INVALID			-10009 /* Invalid file descriptor: -10000 - EBADF = -10009 */

/* Generic flags for the *at(2) family of syscalls. */

/* Reserved for per-syscall flags	0xff. */
#define AT_SYMLINK_NOFOLLOW		0x100   /* Do not follow symbolic
						   links. */
/* Reserved for per-syscall flags	0x200 */
#define AT_SYMLINK_FOLLOW		0x400   /* Follow symbolic links. */
#define AT_NO_AUTOMOUNT			0x800	/* Suppress terminal automount
						   traversal. */
#define AT_EMPTY_PATH			0x1000	/* Allow empty relative
						   pathname to operate on dirfd
						   directly. */
/*
 * These flags are currently statx(2)-specific, but they could be made generic
 * in the future and so they should not be used for other per-syscall flags.
 */
#define AT_STATX_SYNC_TYPE		0x6000	/* Type of synchronisation required from statx() */
#define AT_STATX_SYNC_AS_STAT		0x0000	/* - Do whatever stat() does */
#define AT_STATX_FORCE_SYNC		0x2000	/* - Force the attributes to be sync'd with the server */
#define AT_STATX_DONT_SYNC		0x4000	/* - Don't sync attributes with the server */

#define AT_RECURSIVE			0x8000	/* Apply to the entire subtree */

/*
 * Per-syscall flags for the *at(2) family of syscalls.
 *
 * These are flags that are so syscall-specific that a user passing these flags
 * to the wrong syscall is so "clearly wrong" that we can safely call such
 * usage "undefined behaviour".
 *
 * For example, the constants AT_REMOVEDIR and AT_EACCESS have the same value.
 * AT_EACCESS is meaningful only to faccessat, while AT_REMOVEDIR is meaningful
 * only to unlinkat. The two functions do completely different things and
 * therefore, the flags can be allowed to overlap. For example, passing
 * AT_REMOVEDIR to faccessat would be undefined behavior and thus treating it
 * equivalent to AT_EACCESS is valid undefined behavior.
 *
 * Note for implementers: When picking a new per-syscall AT_* flag, try to
 * reuse already existing flags first. This leaves us with as many unused bits
 * as possible, so we can use them for generic bits in the future if necessary.
 */

/* Flags for renameat2(2) (must match legacy RENAME_* flags). */
#define AT_RENAME_NOREPLACE	0x0001
#define AT_RENAME_EXCHANGE	0x0002
#define AT_RENAME_WHITEOUT	0x0004

/* Flag for faccessat(2). */
#define AT_EACCESS		0x200	/* Test access permitted for
                                           effective IDs, not real IDs.  */
/* Flag for unlinkat(2). */
#define AT_REMOVEDIR		0x200   /* Remove directory instead of
                                           unlinking file.  */
/* Flags for name_to_handle_at(2). */
#define AT_HANDLE_FID		0x200	/* File handle is needed to compare
					   object identity and may not be
					   usable with open_by_handle_at(2). */
#define AT_HANDLE_MNT_ID_UNIQUE	0x001	/* Return the u64 unique mount ID. */
#define AT_HANDLE_CONNECTABLE	0x002	/* Request a connectable file handle */

/* Flags for execveat2(2). */
#define AT_EXECVE_CHECK		0x10000	/* Only perform a check if execution
					   would be allowed. */

#endif /* _UAPI_LINUX_FCNTL_H */
