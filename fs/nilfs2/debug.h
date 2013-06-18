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

#ifdef CONFIG_NILFS2_DEBUG

/* Definition of flags' set for debugging */
static u32 DBG_MASK = (
#ifdef CONFIG_NILFS2_DEBUG_BASE_OPERATIONS
	DBG_SUPER | DBG_THE_NILFS | DBG_NAMEI |
	DBG_IOCTL | DBG_INODE | DBG_FILE | DBG_DIR |
#endif /* CONFIG_NILFS2_DEBUG_BASE_OPERATIONS */
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
		if ((flg & NILFS2_SUBSYS_MASK) & DBG_MASK) \
			nilfs2_printk(f, ## a); \
	} while (0)

#else /* CONFIG_NILFS2_DEBUG */

#define nilfs2_debug(flg, fmt, ...)	no_printk(fmt, ##__VA_ARGS__)

#endif /* CONFIG_NILFS2_DEBUG */

#endif	/* _NILFS_DEBUG_H */
