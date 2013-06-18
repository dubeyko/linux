/*
 * debug.h - NILFS debug output infrastructure.
 *
 * Copyright (C) 2005-2013 Nippon Telegraph and Telephone Corporation.
 * Copyright (c) 2013 Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Vyacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _NILFS_DEBUG_H
#define _NILFS_DEBUG_H

#include <linux/printk.h>

/*
 * These flags enable debugging output in modules that
 * implement base file system operations functionality
 * (super.c, the_nilfs.c, namei.c, ioctl.c, inode.c,
 * file.c, dir.c).
 */
#define DBG_SUPER	0x00000002
#define DBG_THE_NILFS	0x00000004
#define DBG_NAMEI	0x00000008
#define DBG_IOCTL	0x00000010
#define DBG_INODE	0x00000020
#define DBG_FILE	0x00000040
#define DBG_DIR		0x00000080

/*
 * These flags enable debugging output in modules that
 * implement metadata (MDT) files functionality
 * (mdt.c, cpfile.c, dat.c, ifile.c, sufile.c).
 */
#define DBG_MDT		0x00000100
#define DBG_CPFILE	0x00000200
#define DBG_DAT		0x00000400
#define DBG_IFILE	0x00000800
#define DBG_SUFILE	0x00001000

/*
 * These flags enable debugging output in modules that
 * implement segments subsystem functionality
 * (segbuf.c, segment.c).
 */
#define DBG_SEGBUF	0x00002000
#define DBG_SEGMENT	0x00004000

/*
 * These flags enable debugging output in modules that
 * implement GC subsystem functionality (gcinode.c).
 */
#define DBG_GCINODE	0x00008000

/*
 * These flags enable debugging output in modules that
 * implement recovery subsystem functionality (recovery.c).
 */
#define DBG_RECOVERY	0x00010000

/*
 * These flags enable debugging output in modules that
 * implement block mapping subsystem functionality
 * (alloc.c, bmap.c, btnode.c, btree.c, direct.c).
 */
#define DBG_ALLOC	0x00020000
#define DBG_BMAP	0x00040000
#define DBG_BTNODE	0x00080000
#define DBG_BTREE	0x00100000
#define DBG_DIRECT	0x00200000

/*
 * These flags enable debugging output in modules that
 * implement buffer management subsystem functionality
 * (page.c).
 */
#define DBG_PAGE	0x00400000

/*
 * This flag enables output of dump stack. Usually, every
 * function in NILFS2 driver begins from debugging output of
 * function name, file, line and input arguments' value.
 * In the case of enabling this option debugging output
 * will include dump stack too.
 */
#define DBG_DUMP_STACK	0x20000000

#ifdef CONFIG_NILFS2_DEBUG

/* Definition of flags' set for debugging */
static u32 DBG_MASK = (
#ifdef CONFIG_NILFS2_DEBUG_BASE_OPERATIONS
	DBG_SUPER | DBG_THE_NILFS | DBG_NAMEI |
	DBG_IOCTL | DBG_INODE | DBG_FILE | DBG_DIR |
#endif /* CONFIG_NILFS2_DEBUG_BASE_OPERATIONS */
#ifdef CONFIG_NILFS2_DEBUG_MDT_FILES
	DBG_MDT | DBG_CPFILE | DBG_DAT |
	DBG_IFILE | DBG_SUFILE |
#endif /* CONFIG_NILFS2_DEBUG_MDT_FILES */
#ifdef CONFIG_NILFS2_DEBUG_SEGMENTS_SUBSYSTEM
	DBG_SEGBUF | DBG_SEGMENT |
#endif /* CONFIG_NILFS2_DEBUG_SEGMENTS_SUBSYSTEM */
#ifdef CONFIG_NILFS2_DEBUG_GC_SUBSYSTEM
	DBG_GCINODE | DBG_IOCTL |
#endif /* CONFIG_NILFS2_DEBUG_GC_SUBSYSTEM */
#ifdef CONFIG_NILFS2_DEBUG_RECOVERY_SUBSYSTEM
	DBG_RECOVERY |
#endif /* CONFIG_NILFS2_DEBUG_RECOVERY_SUBSYSTEM */
#ifdef CONFIG_NILFS2_DEBUG_BLOCK_MAPPING
	DBG_ALLOC | DBG_BMAP | DBG_BTNODE |
	DBG_BTREE | DBG_DIRECT |
#endif /* CONFIG_NILFS2_DEBUG_BLOCK_MAPPING */
#ifdef CONFIG_NILFS2_DEBUG_BUFFER_MANAGEMENT
	DBG_PAGE |
#endif /* CONFIG_NILFS2_DEBUG_BUFFER_MANAGEMENT */
#ifdef CONFIG_NILFS2_DEBUG_DUMP_STACK
	DBG_DUMP_STACK |
#endif /* CONFIG_NILFS2_DEBUG_DUMP_STACK */
	0);

#define NILFS2_SUBSYS_MASK	0x0FFFFFFF
#define NILFS2_DBG_OUT_MASK	0xF0000000

#define nilfs2_printk(f, a...) \
	do { \
		printk(KERN_DEBUG "NILFS DEBUG (%s, %d): %s:\n", \
			__FILE__, __LINE__, __func__); \
		printk(KERN_DEBUG f, ## a); \
	} while (0)

#define nilfs2_debug(flg, f, a...) \
	do { \
		bool can_dump_stack = DBG_MASK & DBG_DUMP_STACK; \
		bool should_dump_stack = flg & DBG_DUMP_STACK; \
		if ((flg & NILFS2_SUBSYS_MASK) & DBG_MASK) { \
			nilfs2_printk(f, ## a); \
			if (can_dump_stack && should_dump_stack) \
				dump_stack(); \
		} \
	} while (0)

#else /* CONFIG_NILFS2_DEBUG */

#define nilfs2_debug(flg, fmt, ...)	no_printk(fmt, ##__VA_ARGS__)

#endif /* CONFIG_NILFS2_DEBUG */

#endif	/* _NILFS_DEBUG_H */
