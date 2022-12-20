//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/offset_translation_table.c - offset translation table functionality.
 *
 * Copyright (c) 2014-2022 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2022, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#include <linux/bitmap.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "offset_translation_table.h"
#include "page_array.h"
#include "page_vector.h"
#include "peb.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_blk2off_page_leaks;
atomic64_t ssdfs_blk2off_memory_leaks;
atomic64_t ssdfs_blk2off_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_blk2off_cache_leaks_increment(void *kaddr)
 * void ssdfs_blk2off_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_blk2off_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_blk2off_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_blk2off_kvzalloc(size_t size, gfp_t flags)
 * void *ssdfs_blk2off_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_blk2off_kfree(void *kaddr)
 * void ssdfs_blk2off_kvfree(void *kaddr)
 * struct page *ssdfs_blk2off_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_blk2off_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_blk2off_free_page(struct page *page)
 * void ssdfs_blk2off_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(blk2off)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(blk2off)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_blk2off_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_blk2off_page_leaks, 0);
	atomic64_set(&ssdfs_blk2off_memory_leaks, 0);
	atomic64_set(&ssdfs_blk2off_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_blk2off_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_blk2off_page_leaks) != 0) {
		SSDFS_ERR("BLK2OFF TABLE: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_blk2off_page_leaks));
	}

	if (atomic64_read(&ssdfs_blk2off_memory_leaks) != 0) {
		SSDFS_ERR("BLK2OFF TABLE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_blk2off_memory_leaks));
	}

	if (atomic64_read(&ssdfs_blk2off_cache_leaks) != 0) {
		SSDFS_ERR("BLK2OFF TABLE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_blk2off_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/******************************************************************************
 *                           BLK2OFF TABLE CACHE                              *
 ******************************************************************************/

static struct kmem_cache *ssdfs_blk2off_frag_obj_cachep;

void ssdfs_zero_blk2off_frag_obj_cache_ptr(void)
{
	ssdfs_blk2off_frag_obj_cachep = NULL;
}

static void ssdfs_init_blk2off_frag_object_once(void *obj)
{
	struct ssdfs_phys_offset_table_fragment *frag_obj = obj;

	memset(frag_obj, 0, sizeof(struct ssdfs_phys_offset_table_fragment));
}

void ssdfs_shrink_blk2off_frag_obj_cache(void)
{
	if (ssdfs_blk2off_frag_obj_cachep)
		kmem_cache_shrink(ssdfs_blk2off_frag_obj_cachep);
}

void ssdfs_destroy_blk2off_frag_obj_cache(void)
{
	if (ssdfs_blk2off_frag_obj_cachep)
		kmem_cache_destroy(ssdfs_blk2off_frag_obj_cachep);
}

int ssdfs_init_blk2off_frag_obj_cache(void)
{
	size_t obj_size = sizeof(struct ssdfs_phys_offset_table_fragment);

	ssdfs_blk2off_frag_obj_cachep =
			kmem_cache_create("ssdfs_blk2off_frag_obj_cache",
					obj_size, 0,
					SLAB_RECLAIM_ACCOUNT |
					SLAB_MEM_SPREAD |
					SLAB_ACCOUNT,
					ssdfs_init_blk2off_frag_object_once);
	if (!ssdfs_blk2off_frag_obj_cachep) {
		SSDFS_ERR("unable to create blk2off fragments cache\n");
		return -ENOMEM;
	}

	return 0;
}

/*
 * ssdfs_blk2off_frag_alloc() - allocate memory for blk2off fragment
 */
static
struct ssdfs_phys_offset_table_fragment *ssdfs_blk2off_frag_alloc(void)
{
	struct ssdfs_phys_offset_table_fragment *ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_blk2off_frag_obj_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = kmem_cache_alloc(ssdfs_blk2off_frag_obj_cachep, GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for blk2off fragment\n");
		return ERR_PTR(-ENOMEM);
	}

	ssdfs_blk2off_cache_leaks_increment(ptr);

	return ptr;
}

/*
 * ssdfs_blk2off_frag_free() - free memory for blk2off fragment
 */
static
void ssdfs_blk2off_frag_free(void *ptr)
{
	struct ssdfs_phys_offset_table_fragment *frag;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_blk2off_frag_obj_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!ptr)
		return;

	SSDFS_DBG("ptr %p\n", ptr);

	frag = (struct ssdfs_phys_offset_table_fragment *)ptr;

	WARN_ON(atomic_read(&frag->state) == SSDFS_BLK2OFF_FRAG_DIRTY);

	if (frag->buf) {
		ssdfs_blk2off_kfree(frag->buf);
		frag->buf = NULL;
	}

	ssdfs_blk2off_cache_leaks_decrement(frag);
	kmem_cache_free(ssdfs_blk2off_frag_obj_cachep, frag);
}

/******************************************************************************
 *                      BLK2OFF TABLE OBJECT FUNCTIONALITY                    *
 ******************************************************************************/

/*
 * struct ssdfs_blk2off_init - initialization environment
 * @table: pointer on translation table object
 * @blk2off_pvec: blk2off table fragment
 * @blk_desc_pvec: blk desc table fragment
 * @peb_index: PEB's index
 * @cno: checkpoint
 * @fragments_count: count of fragments in portion
 * @capacity: maximum amount of items
 * @tbl_hdr: portion header
 * @tbl_hdr_off: portion header's offset
 * @pot_hdr: fragment header
 * @pot_hdr_off: fragment header's offset
 * @bmap: temporary bitmap
 * @bmap_bytes: bytes in temporaray bitmap
 * @extent_array: translation extents temporary array
 * @extents_count: count of extents in array
 */
struct ssdfs_blk2off_init {
	struct ssdfs_blk2off_table *table;
	struct pagevec *blk2off_pvec;
	struct pagevec *blk_desc_pvec;
	u16 peb_index;
	u64 cno;
	u32 fragments_count;
	u16 capacity;

	struct ssdfs_blk2off_table_header tbl_hdr;
	u32 tbl_hdr_off;
	struct ssdfs_phys_offset_table_header pot_hdr;
	u32 pot_hdr_off;

	unsigned long *bmap;
	u32 bmap_bytes;

	struct ssdfs_translation_extent *extent_array;
	u16 extents_count;
};

static
void ssdfs_debug_blk2off_table_object(struct ssdfs_blk2off_table *tbl);

/*
 * ssdfs_blk2off_table_init_fragment() - init PEB's fragment
 * @ptr: fragment pointer
 * @sequence_id: fragment's sequence ID
 * @start_id: fragment's start ID
 * @pages_per_peb: PEB's pages count
 * @state: fragment state after initialization
 * @buf_size: pointer on buffer size
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 */
static int
ssdfs_blk2off_table_init_fragment(struct ssdfs_phys_offset_table_fragment *ptr,
				  u16 sequence_id, u16 start_id,
				  u32 pages_per_peb, int state,
				  size_t *buf_size)
{
	size_t blk2off_tbl_hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	size_t hdr_size = sizeof(struct ssdfs_phys_offset_table_header);
	size_t off_size = sizeof(struct ssdfs_phys_offset_descriptor);
	size_t fragment_size = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ptr %p, sequence_id %u, start_id %u, "
		  "pages_per_peb %u, state %#x, buf_size %p\n",
		  ptr, sequence_id, start_id, pages_per_peb,
		  state, buf_size);

	BUG_ON(!ptr);
	BUG_ON(sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD);
	BUG_ON(state < SSDFS_BLK2OFF_FRAG_CREATED ||
		state >= SSDFS_BLK2OFF_FRAG_STATE_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	init_rwsem(&ptr->lock);

	down_write(&ptr->lock);

	if (buf_size) {
		fragment_size = min_t(size_t, *buf_size, PAGE_SIZE);
	} else {
		fragment_size += blk2off_tbl_hdr_size;
		fragment_size += hdr_size + (off_size * pages_per_peb);
		fragment_size = min_t(size_t, fragment_size, PAGE_SIZE);
	}

	ptr->buf_size = fragment_size;
	ptr->buf = ssdfs_blk2off_kzalloc(ptr->buf_size, GFP_KERNEL);
	if (!ptr->buf) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate table buffer\n");
		goto finish_fragment_init;
	}

	ptr->start_id = start_id;
	ptr->sequence_id = sequence_id;
	atomic_set(&ptr->id_count, 0);

	ptr->hdr = SSDFS_POFFTH(ptr->buf);
	ptr->phys_offs = SSDFS_PHYSOFFD(ptr->buf + hdr_size);

	atomic_set(&ptr->state, state);

	SSDFS_DBG("FRAGMENT: sequence_id %u, start_id %u, id_count %d\n",
		  sequence_id, start_id, atomic_read(&ptr->id_count));

finish_fragment_init:
	up_write(&ptr->lock);
	return err;
}

/*
 * ssdfs_get_migrating_block() - get pointer on migrating block
 * @table: pointer on translation table object
 * @logical_blk: logical block ID
 * @need_allocate: should descriptor being allocated?
 *
 * This method tries to return pointer on migrating block's
 * descriptor. In the case of necessity the descriptor
 * will be allocated (if @need_allocate is true).
 *
 * RETURN:
 * [success] - pointer on migrating block's descriptor.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid value.
 * %-ENOMEM     - fail to allocate memory.
 */
static
struct ssdfs_migrating_block *
ssdfs_get_migrating_block(struct ssdfs_blk2off_table *table,
			  u16 logical_blk,
			  bool need_allocate)
{
	struct ssdfs_migrating_block *migrating_blk = NULL;
	void *kaddr;
	size_t blk_desc_size = sizeof(struct ssdfs_migrating_block);
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(logical_blk >= table->lblk2off_capacity);

	SSDFS_DBG("logical_blk %u, need_allocate %#x\n",
		  logical_blk, need_allocate);
#endif /* CONFIG_SSDFS_DEBUG */

	if (need_allocate) {
		migrating_blk = ssdfs_blk2off_kzalloc(blk_desc_size,
							GFP_KERNEL);
		if (!migrating_blk) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate migrating block desc\n");
			goto fail_get_migrating_blk;
		}

		err = ssdfs_dynamic_array_set(&table->migrating_blks,
						logical_blk, &migrating_blk);
		if (unlikely(err)) {
			ssdfs_blk2off_kfree(migrating_blk);
			SSDFS_ERR("fail to store migrating block in array: "
				  "logical_blk %u, err %d\n",
				  logical_blk, err);
			goto fail_get_migrating_blk;
		}

		SSDFS_DBG("logical_blk %u descriptor has been allocated\n",
			  logical_blk);
	} else {
		kaddr = ssdfs_dynamic_array_get_locked(&table->migrating_blks,
							logical_blk);
		if (IS_ERR_OR_NULL(kaddr)) {
			err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
			SSDFS_ERR("fail to get migrating block: "
				  "logical_blk %u, err %d\n",
				  logical_blk, err);
			goto fail_get_migrating_blk;
		}

		migrating_blk = SSDFS_MIGRATING_BLK(*(u8 **)kaddr);

		err = ssdfs_dynamic_array_release(&table->migrating_blks,
						  logical_blk, kaddr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to release: "
				  "logical_blk %u, err %d\n",
				  logical_blk, err);
			goto fail_get_migrating_blk;
		}
	}

	if (migrating_blk) {
		SSDFS_DBG("logical_blk %u, state %#x\n",
			  logical_blk, migrating_blk->state);
	}

	return migrating_blk;

fail_get_migrating_blk:
	return ERR_PTR(err);
}

/*
 * ssdfs_destroy_migrating_blocks_array() - destroy descriptors array
 * @table: pointer on translation table object
 *
 * This method tries to free memory of migrating block
 * descriptors array.
 */
static
void ssdfs_destroy_migrating_blocks_array(struct ssdfs_blk2off_table *table)
{
	struct ssdfs_migrating_block *migrating_blk = NULL;
	void *kaddr;
	u32 items_count;
	u32 i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
#endif /* CONFIG_SSDFS_DEBUG */

	items_count = table->last_allocated_blk + 1;

	for (i = 0; i < items_count; i++) {
		kaddr = ssdfs_dynamic_array_get_locked(&table->migrating_blks,
							i);
		if (IS_ERR_OR_NULL(kaddr))
			continue;

		migrating_blk = SSDFS_MIGRATING_BLK(*(u8 **)kaddr);

		if (migrating_blk)
			ssdfs_blk2off_kfree(migrating_blk);

		ssdfs_dynamic_array_release(&table->migrating_blks,
					    i, kaddr);
	}

	ssdfs_dynamic_array_destroy(&table->migrating_blks);
}

/*
 * ssdfs_blk2off_table_create() - create translation table object
 * @fsi: pointer on shared file system object
 * @items_count: table's capacity
 * @type: table's type
 * @state: initial state of object
 *
 * This method tries to create translation table object.
 *
 * RETURN:
 * [success] - pointer on created object.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid value.
 * %-ENOMEM     - fail to allocate memory.
 */
struct ssdfs_blk2off_table *
ssdfs_blk2off_table_create(struct ssdfs_fs_info *fsi,
			   u16 items_count, u8 type,
			   int state)
{
	struct ssdfs_blk2off_table *ptr;
	size_t table_size = sizeof(struct ssdfs_blk2off_table);
	size_t off_pos_size = sizeof(struct ssdfs_offset_position);
	size_t ptr_size = sizeof(struct ssdfs_migrating_block *);
	u32 bytes;
	u32 bits_count;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(state <= SSDFS_BLK2OFF_OBJECT_UNKNOWN ||
		state >= SSDFS_BLK2OFF_OBJECT_STATE_MAX);
	BUG_ON(items_count > (2 * fsi->pages_per_seg));
	BUG_ON(type <= SSDFS_UNKNOWN_OFF_TABLE_TYPE ||
		type >= SSDFS_OFF_TABLE_MAX_TYPE);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("fsi %p, items_count %u, type %u, state %#x\n",
		  fsi, items_count, type,  state);
#else
	SSDFS_DBG("fsi %p, items_count %u, type %u, state %#x\n",
		  fsi, items_count, type,  state);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ptr = (struct ssdfs_blk2off_table *)ssdfs_blk2off_kzalloc(table_size,
								  GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate translation table\n");
		return ERR_PTR(-ENOMEM);
	}

	ptr->fsi = fsi;

	atomic_set(&ptr->flags, 0);
	atomic_set(&ptr->state, SSDFS_BLK2OFF_OBJECT_UNKNOWN);

	ptr->pages_per_peb = fsi->pages_per_peb;
	ptr->pages_per_seg = fsi->pages_per_seg;
	ptr->type = type;

	init_rwsem(&ptr->translation_lock);
	init_waitqueue_head(&ptr->wait_queue);

	ptr->init_cno = U64_MAX;
	ptr->used_logical_blks = 0;
	ptr->free_logical_blks = items_count;
	ptr->last_allocated_blk = U16_MAX;

	bytes = ssdfs_blk2off_table_bmap_bytes(items_count);
	bytes = min_t(u32, bytes, PAGE_SIZE);
	bits_count = bytes * BITS_PER_BYTE;

	ptr->lbmap.bits_count = bits_count;
	ptr->lbmap.bytes_count = bytes;

	for (i = 0; i < SSDFS_LBMAP_ARRAY_MAX; i++) {
		ptr->lbmap.array[i] =
			(unsigned long *)ssdfs_blk2off_kvzalloc(bytes,
								GFP_KERNEL);
		if (!ptr->lbmap.array[i]) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate bitmaps\n");
			goto free_bmap;
		}
	}

	SSDFS_DBG("init_bmap %lx, state_bmap %lx, modification_bmap %lx\n",
		  *ptr->lbmap.array[SSDFS_LBMAP_INIT_INDEX],
		  *ptr->lbmap.array[SSDFS_LBMAP_STATE_INDEX],
		  *ptr->lbmap.array[SSDFS_LBMAP_MODIFICATION_INDEX]);

	ptr->lblk2off_capacity = items_count;

	err = ssdfs_dynamic_array_create(&ptr->lblk2off,
					 ptr->lblk2off_capacity,
					 off_pos_size,
					 0xFF);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create translation array: "
			  "off_pos_size %zu, items_count %u\n",
			  off_pos_size,
			  ptr->lblk2off_capacity);
		goto free_bmap;
	}

	err = ssdfs_dynamic_array_create(&ptr->migrating_blks,
					 ptr->lblk2off_capacity,
					 ptr_size,
					 0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create migrating blocks array: "
			  "ptr_size %zu, items_count %u\n",
			  ptr_size,
			  ptr->lblk2off_capacity);
		goto free_bmap;
	}

	ptr->pebs_count = fsi->pebs_per_seg;

	ptr->peb = ssdfs_blk2off_kcalloc(ptr->pebs_count,
				 sizeof(struct ssdfs_phys_offset_table_array),
				 GFP_KERNEL);
	if (!ptr->peb) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate phys offsets array\n");
		goto free_translation_array;
	}

	for (i = 0; i < ptr->pebs_count; i++) {
		struct ssdfs_phys_offset_table_array *table = &ptr->peb[i];
		struct ssdfs_sequence_array *seq_ptr = NULL;
		u32 threshold = SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD;

		seq_ptr = ssdfs_create_sequence_array(threshold);
		if (IS_ERR_OR_NULL(seq_ptr)) {
			err = (seq_ptr == NULL ? -ENOMEM : PTR_ERR(seq_ptr));
			SSDFS_ERR("fail to allocate sequence: "
				  "err %d\n", err);
			goto free_phys_offs_array;
		} else
			table->sequence = seq_ptr;

		if (state == SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT) {
			struct ssdfs_phys_offset_table_fragment *fragment;
			u16 start_id = i * fsi->pages_per_peb;
			u32 pages_per_peb = fsi->pages_per_peb;
			int fragment_state = SSDFS_BLK2OFF_FRAG_INITIALIZED;

			atomic_set(&table->fragment_count, 1);

			fragment = ssdfs_blk2off_frag_alloc();
			if (IS_ERR_OR_NULL(fragment)) {
				err = (fragment == NULL ? -ENOMEM :
							PTR_ERR(fragment));
				SSDFS_ERR("fail to allocate fragment: "
					  "err %d\n", err);
				goto free_phys_offs_array;
			}

			err = ssdfs_sequence_array_init_item(table->sequence,
							     0, fragment);
			if (unlikely(err)) {
				ssdfs_blk2off_frag_free(fragment);
				SSDFS_ERR("fail to init fragment: "
					  "err %d\n", err);
				goto free_phys_offs_array;
			}

			err = ssdfs_blk2off_table_init_fragment(fragment, 0,
								start_id,
								pages_per_peb,
								fragment_state,
								NULL);
			if (unlikely(err)) {
				SSDFS_ERR("fail to init fragment: "
					  "fragment_index %d, err %d\n",
					  i, err);
				goto free_phys_offs_array;
			}

			atomic_set(&table->state,
				   SSDFS_BLK2OFF_TABLE_COMPLETE_INIT);
		} else if (state == SSDFS_BLK2OFF_OBJECT_CREATED) {
			atomic_set(&table->fragment_count, 0);
			atomic_set(&table->state,
				   SSDFS_BLK2OFF_TABLE_CREATED);
		} else
			BUG();
	}

	SSDFS_DBG("init_bmap %lx, state_bmap %lx, modification_bmap %lx\n",
		  *ptr->lbmap.array[SSDFS_LBMAP_INIT_INDEX],
		  *ptr->lbmap.array[SSDFS_LBMAP_STATE_INDEX],
		  *ptr->lbmap.array[SSDFS_LBMAP_MODIFICATION_INDEX]);

	init_completion(&ptr->partial_init_end);
	init_completion(&ptr->full_init_end);

	atomic_set(&ptr->state, state);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return ptr;

free_phys_offs_array:
	for (i = 0; i < ptr->pebs_count; i++) {
		struct ssdfs_sequence_array *sequence;

		sequence = ptr->peb[i].sequence;
		ssdfs_destroy_sequence_array(sequence, ssdfs_blk2off_frag_free);
		ptr->peb[i].sequence = NULL;
	}

	ssdfs_blk2off_kfree(ptr->peb);

free_translation_array:
	ssdfs_dynamic_array_destroy(&ptr->lblk2off);

free_bmap:
	for (i = 0; i < SSDFS_LBMAP_ARRAY_MAX; i++) {
		ssdfs_blk2off_kvfree(ptr->lbmap.array[i]);
		ptr->lbmap.array[i] = NULL;
	}

	ptr->lbmap.bits_count = 0;
	ptr->lbmap.bytes_count = 0;

	ssdfs_blk2off_kfree(ptr);

	return ERR_PTR(err);
}

/*
 * ssdfs_blk2off_table_destroy() - destroy translation table object
 * @table: pointer on translation table object
 */
void ssdfs_blk2off_table_destroy(struct ssdfs_blk2off_table *table)
{
#ifdef CONFIG_SSDFS_DEBUG
	int migrating_blks = -1;
#endif /* CONFIG_SSDFS_DEBUG */
	int state;
	int i;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("table %p\n", table);
#else
	SSDFS_DBG("table %p\n", table);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (!table) {
		WARN_ON(!table);
		return;
	}

	if (table->peb) {
		for (i = 0; i < table->pebs_count; i++) {
			struct ssdfs_sequence_array *sequence;

			sequence = table->peb[i].sequence;
			ssdfs_destroy_sequence_array(sequence,
						ssdfs_blk2off_frag_free);
			table->peb[i].sequence = NULL;

			state = atomic_read(&table->peb[i].state);

			switch (state) {
			case SSDFS_BLK2OFF_TABLE_DIRTY:
			case SSDFS_BLK2OFF_TABLE_DIRTY_PARTIAL_INIT:
				SSDFS_WARN("unexpected table state %#x\n",
					   state);
				break;

			default:
				/* do nothing */
				break;
			}
		}

		ssdfs_blk2off_kfree(table->peb);
		table->peb = NULL;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (table->last_allocated_blk >= U16_MAX)
		migrating_blks = 0;
	else
		migrating_blks = table->last_allocated_blk + 1;

	for (i = 0; i < migrating_blks; i++) {
		struct ssdfs_migrating_block *blk =
				ssdfs_get_migrating_block(table, i, false);

		if (IS_ERR_OR_NULL(blk))
			continue;

		switch (blk->state) {
		case SSDFS_LBLOCK_UNDER_MIGRATION:
		case SSDFS_LBLOCK_UNDER_COMMIT:
			SSDFS_ERR("logical blk %d is under migration\n", i);
			ssdfs_blk2off_pagevec_release(&blk->pvec);
			break;
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_dynamic_array_destroy(&table->lblk2off);

	ssdfs_destroy_migrating_blocks_array(table);

	for (i = 0; i < SSDFS_LBMAP_ARRAY_MAX; i++) {
		ssdfs_blk2off_kvfree(table->lbmap.array[i]);
		table->lbmap.array[i] = NULL;
	}

	table->lbmap.bits_count = 0;
	table->lbmap.bytes_count = 0;

	ssdfs_blk2off_kfree(table);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */
}

/*
 * ssdfs_blk2off_table_resize_bitmap_array() - resize bitmap array
 * @lbmap: bitmap pointer
 * @logical_blk: new threshold
 */
static inline
int ssdfs_blk2off_table_resize_bitmap_array(struct ssdfs_bitmap_array *lbmap,
					    u16 logical_blk)
{
	unsigned long *bmap_ptr;
	u32 new_bits_count;
	u32 new_bytes_count;
	u32 bits_per_page;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap);

	SSDFS_DBG("lbmap %p, logical_blk %u\n",
		  lbmap, logical_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	bits_per_page = PAGE_SIZE * BITS_PER_BYTE;

	new_bits_count = logical_blk + bits_per_page - 1;
	new_bits_count /= bits_per_page;
	new_bits_count *= bits_per_page;

	new_bytes_count = ssdfs_blk2off_table_bmap_bytes(new_bits_count);

	for (i = 0; i < SSDFS_LBMAP_ARRAY_MAX; i++) {
		bmap_ptr = kvrealloc(lbmap->array[i],
				     lbmap->bytes_count,
				     new_bytes_count,
				     GFP_KERNEL | __GFP_ZERO);
		if (!bmap_ptr) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate bitmaps\n");
			goto finish_bitmap_array_resize;
		} else
			lbmap->array[i] = (unsigned long *)bmap_ptr;
	}

	lbmap->bits_count = new_bits_count;
	lbmap->bytes_count = new_bytes_count;

finish_bitmap_array_resize:
	return err;
}

/*
 * ssdfs_blk2off_table_bmap_set() - set bit for logical block
 * @lbmap: bitmap pointer
 * @bitmap_index: index of bitmap
 * @logical_blk: logical block number
 */
static inline
int ssdfs_blk2off_table_bmap_set(struct ssdfs_bitmap_array *lbmap,
				 int bitmap_index, u16 logical_blk)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap);

	SSDFS_DBG("lbmap %p, bitmap_index %d, logical_blk %u\n",
		  lbmap, bitmap_index, logical_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	if (bitmap_index >= SSDFS_LBMAP_ARRAY_MAX) {
		SSDFS_ERR("invalid bitmap index %d\n",
			  bitmap_index);
		return -EINVAL;
	}

	if (logical_blk >= lbmap->bits_count) {
		err = ssdfs_blk2off_table_resize_bitmap_array(lbmap,
							      logical_blk);
		if (unlikely(err)) {
			SSDFS_ERR("fail to realloc bitmap array: "
				  "logical_blk %u, err %d\n",
				  logical_blk, err);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap->array[bitmap_index]);
#endif /* CONFIG_SSDFS_DEBUG */

	bitmap_set(lbmap->array[bitmap_index], logical_blk, 1);

	return 0;
}

/*
 * ssdfs_blk2off_table_bmap_clear() - clear bit for logical block
 * @lbmap: bitmap pointer
 * @bitmap_index: index of bitmap
 * @logical_blk: logical block number
 */
static inline
int ssdfs_blk2off_table_bmap_clear(struct ssdfs_bitmap_array *lbmap,
				   int bitmap_index, u16 logical_blk)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap);

	SSDFS_DBG("lbmap %p, bitmap_index %d, logical_blk %u\n",
		  lbmap, bitmap_index, logical_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	if (bitmap_index >= SSDFS_LBMAP_ARRAY_MAX) {
		SSDFS_ERR("invalid bitmap index %d\n",
			  bitmap_index);
		return -EINVAL;
	}

	if (logical_blk >= lbmap->bits_count) {
		err = ssdfs_blk2off_table_resize_bitmap_array(lbmap,
							      logical_blk);
		if (unlikely(err)) {
			SSDFS_ERR("fail to realloc bitmap array: "
				  "logical_blk %u, err %d\n",
				  logical_blk, err);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap->array[bitmap_index]);
#endif /* CONFIG_SSDFS_DEBUG */

	bitmap_clear(lbmap->array[bitmap_index], logical_blk, 1);

	return 0;
}

/*
 * ssdfs_blk2off_table_bmap_vacant() - check bit for logical block
 * @lbmap: bitmap pointer
 * @bitmap_index: index of bitmap
 * @lbmap_bits: count of bits in bitmap
 * @logical_blk: logical block number
 */
static inline
bool ssdfs_blk2off_table_bmap_vacant(struct ssdfs_bitmap_array *lbmap,
				     int bitmap_index,
				     u16 lbmap_bits,
				     u16 logical_blk)
{
	unsigned long found;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap);

	SSDFS_DBG("lbmap %p, bitmap_index %d, "
		  "lbmap_bits %u, logical_blk %u\n",
		  lbmap, bitmap_index,
		  lbmap_bits, logical_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	if (bitmap_index >= SSDFS_LBMAP_ARRAY_MAX) {
		SSDFS_ERR("invalid bitmap index %d\n",
			  bitmap_index);
		return false;
	}

	if (logical_blk >= lbmap->bits_count)
		return true;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap->array[bitmap_index]);
#endif /* CONFIG_SSDFS_DEBUG */

	found = find_next_zero_bit(lbmap->array[bitmap_index],
				   lbmap_bits, logical_blk);

	return found == logical_blk;
}

/*
 * ssdfs_blk2off_table_extent_vacant() - check extent vacancy
 * @lbmap: bitmap pointer
 * @bitmap_index: index of bitmap
 * @lbmap_bits: count of bits in bitmap
 * @extent: pointer on extent
 */
static inline
bool ssdfs_blk2off_table_extent_vacant(struct ssdfs_bitmap_array *lbmap,
					int bitmap_index,
					u16 lbmap_bits,
					struct ssdfs_blk2off_range *extent)
{
	unsigned long start, end;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap || !extent);

	SSDFS_DBG("lbmap %p, bitmap_index %d, "
		  "lbmap_bits %u, extent (start %u, len %u)\n",
		  lbmap, bitmap_index, lbmap_bits,
		  extent->start_lblk, extent->len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (bitmap_index >= SSDFS_LBMAP_ARRAY_MAX) {
		SSDFS_ERR("invalid bitmap index %d\n",
			  bitmap_index);
		return false;
	}

	if (extent->start_lblk >= lbmap_bits) {
		SSDFS_ERR("invalid extent start %u\n",
			  extent->start_lblk);
		return false;
	}

	if (extent->len == 0 || extent->len >= U16_MAX) {
		SSDFS_ERR("invalid extent length\n");
		return false;
	}

	if (extent->start_lblk >= lbmap->bits_count)
		return true;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap->array[bitmap_index]);
#endif /* CONFIG_SSDFS_DEBUG */

	start = find_next_zero_bit(lbmap->array[bitmap_index],
				   lbmap_bits, extent->start_lblk);

	if (start != extent->start_lblk)
		return false;
	else if (extent->len == 1)
		return true;

	end = find_next_bit(lbmap->array[bitmap_index], lbmap_bits, start);

	if ((end - start) == extent->len)
		return true;

	return false;
}

/*
 * is_ssdfs_table_header_magic_valid() - check segment header's magic
 * @hdr: table header
 */
bool is_ssdfs_table_header_magic_valid(struct ssdfs_blk2off_table_header *hdr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	return le16_to_cpu(hdr->magic.key) == SSDFS_BLK2OFF_TABLE_HDR_MAGIC;
}

/*
 * ssdfs_check_table_header() - check table header
 * @hdr: table header
 * @size: size of header
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO     - header is invalid.
 */
static
int ssdfs_check_table_header(struct ssdfs_blk2off_table_header *hdr,
			     size_t size)
{
	u16 extents_off = offsetof(struct ssdfs_blk2off_table_header,
				   sequence);
	size_t extent_size = sizeof(struct ssdfs_translation_extent);
	size_t extent_area;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);

	SSDFS_DBG("hdr %p, size %zu\n", hdr, size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_ssdfs_magic_valid(&hdr->magic) ||
	    !is_ssdfs_table_header_magic_valid(hdr)) {
		SSDFS_ERR("invalid table magic\n");
		return -EIO;
	}

	if (!is_csum_valid(&hdr->check, hdr, size)) {
		SSDFS_ERR("invalid checksum\n");
		return -EIO;
	}

	if (extents_off != le16_to_cpu(hdr->extents_off)) {
		SSDFS_ERR("invalid extents offset %u\n",
			  le16_to_cpu(hdr->extents_off));
		return -EIO;
	}

	extent_area = extent_size * le16_to_cpu(hdr->extents_count);
	if (le16_to_cpu(hdr->offset_table_off) != (extents_off + extent_area)) {
		SSDFS_ERR("invalid table offset: extents_off %u, "
			  "extents_count %u, offset_table_off %u\n",
			  le16_to_cpu(hdr->extents_off),
			  le16_to_cpu(hdr->extents_count),
			  le16_to_cpu(hdr->offset_table_off));
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_check_fragment() - check table's fragment
 * @table: pointer on table object
 * @peb_index: PEB's index
 * @hdr: fragment's header
 * @fragment_size: size of fragment in bytes
 *
 * Method tries to check fragment validity.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - corrupted fragment.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_check_fragment(struct ssdfs_blk2off_table *table,
			 u16 peb_index,
			 struct ssdfs_phys_offset_table_header *hdr,
			 size_t fragment_size)
{
	u16 start_id, peb_start_id;
	u16 sequence_id;
	u16 id_count;
	u32 byte_size;
	u32 items_size;
	__le32 csum1, csum2;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !hdr);
	BUG_ON(peb_index >= table->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	start_id = le16_to_cpu(hdr->start_id);
	id_count = le16_to_cpu(hdr->id_count);
	byte_size = le32_to_cpu(hdr->byte_size);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("table %p, peb_index %u, start_id %u, "
		  "id_count %u, byte_size %u, "
		  "fragment_id %u\n",
		  table, peb_index,
		  start_id, id_count, byte_size,
		  hdr->sequence_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (le32_to_cpu(hdr->magic) != SSDFS_PHYS_OFF_TABLE_MAGIC) {
		SSDFS_ERR("invalid magic %#x\n",
			  le32_to_cpu(hdr->magic));
		return -EIO;
	}

	if (byte_size > fragment_size) {
		SSDFS_ERR("byte_size %u > fragment_size %zu\n",
			  byte_size, fragment_size);
		return -ERANGE;
	}

	csum1 = hdr->checksum;
	hdr->checksum = 0;
	csum2 = ssdfs_crc32_le(hdr, byte_size);
	hdr->checksum = csum1;

	if (csum1 != csum2) {
		SSDFS_ERR("csum1 %#x != csum2 %#x\n",
			  le32_to_cpu(csum1),
			  le32_to_cpu(csum2));
		return -EIO;
	}

	if (le16_to_cpu(hdr->peb_index) != peb_index) {
		SSDFS_ERR("invalid peb_index %u\n",
			  le16_to_cpu(hdr->peb_index));
		return -EIO;
	}

	if (start_id >= table->pages_per_seg)
		start_id %= table->pages_per_seg;

	peb_start_id = peb_index * table->pages_per_peb;

	if (start_id < peb_start_id ||
	    start_id >= (peb_start_id + table->pages_per_peb)) {
		SSDFS_ERR("invalid start_id %u for peb_index %u\n",
			  le16_to_cpu(hdr->start_id),
			  peb_index);
		return -EIO;
	}

	if (id_count == 0 || id_count > table->pages_per_peb) {
		SSDFS_ERR("invalid id_count %u for peb_index %u\n",
			  le16_to_cpu(hdr->id_count),
			  peb_index);
		return -EIO;
	}

	items_size = (u32)id_count *
			sizeof(struct ssdfs_phys_offset_descriptor);

	if (byte_size < items_size) {
		SSDFS_ERR("invalid byte_size %u for peb_index %u\n",
			  le32_to_cpu(hdr->byte_size),
			  peb_index);
		return -EIO;
	}

	sequence_id = le16_to_cpu(hdr->sequence_id);
	if (sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		SSDFS_ERR("invalid sequence_id %u for peb_index %u\n",
			  sequence_id, peb_index);
		return -EIO;
	}

	if (le16_to_cpu(hdr->type) == SSDFS_UNKNOWN_OFF_TABLE_TYPE ||
	    le16_to_cpu(hdr->type) >= SSDFS_OFF_TABLE_MAX_TYPE) {
		SSDFS_ERR("invalid type %#x for peb_index %u\n",
			  le16_to_cpu(hdr->type), peb_index);
		return -EIO;
	}

	if (le16_to_cpu(hdr->flags) & ~SSDFS_OFF_TABLE_FLAGS_MASK) {
		SSDFS_ERR("invalid flags set %#x for peb_index %u\n",
			  le16_to_cpu(hdr->flags), peb_index);
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_get_checked_table_header() - get and check table header
 * @portion: pointer on portion init environment [out]
 */
static
int ssdfs_get_checked_table_header(struct ssdfs_blk2off_init *portion)
{
	size_t hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	struct page *page;
	int page_index;
	u32 page_off;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || !portion->blk2off_pvec);

	SSDFS_DBG("source %p, offset %u\n",
		  portion->blk2off_pvec, portion->tbl_hdr_off);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = portion->tbl_hdr_off >> PAGE_SHIFT;
	if (portion->tbl_hdr_off >= PAGE_SIZE)
		page_off = portion->tbl_hdr_off % PAGE_SIZE;
	else
		page_off = portion->tbl_hdr_off;

	if (page_index >= pagevec_count(portion->blk2off_pvec)) {
		SSDFS_ERR("invalid page index %d: "
			  "offset %u, pagevec_count %u\n",
			  page_index, portion->tbl_hdr_off,
			  pagevec_count(portion->blk2off_pvec));
		return -EINVAL;
	}

	page = portion->blk2off_pvec->pages[page_index];

	ssdfs_lock_page(page);
	err = ssdfs_memcpy_from_page(&portion->tbl_hdr, 0, hdr_size,
				     page, page_off, PAGE_SIZE,
				     hdr_size);
	ssdfs_unlock_page(page);

	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: "
			  "page_off %u, hdr_size %zu\n",
			  page_off, hdr_size);
		return err;
	}

	err = ssdfs_check_table_header(&portion->tbl_hdr, hdr_size);
	if (err) {
		SSDFS_ERR("invalid table header\n");
		return err;
	}

	portion->fragments_count =
		le16_to_cpu(portion->tbl_hdr.fragments_count);

	return 0;
}

/*
 * ssdfs_blk2off_prepare_temp_bmap() - prepare temporary bitmap
 * @portion: initialization environment [in | out]
 */
static inline
int ssdfs_blk2off_prepare_temp_bmap(struct ssdfs_blk2off_init *portion)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || portion->bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	portion->bmap_bytes = ssdfs_blk2off_table_bmap_bytes(portion->capacity);
	portion->bmap = ssdfs_blk2off_kvzalloc(portion->bmap_bytes,
						GFP_KERNEL);
	if (unlikely(!portion->bmap)) {
		SSDFS_ERR("fail to allocate memory\n");
		return -ENOMEM;
	}

	return 0;
}

/*
 * ssdfs_blk2off_prepare_extent_array() - prepare extents array
 * @portion: initialization environment [in | out]
 */
static
int ssdfs_blk2off_prepare_extent_array(struct ssdfs_blk2off_init *portion)
{
	size_t extent_size = sizeof(struct ssdfs_translation_extent);
	u32 extents_off, table_off;
	size_t ext_array_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || !portion->blk2off_pvec || portion->extent_array);
#endif /* CONFIG_SSDFS_DEBUG */

	extents_off = offsetof(struct ssdfs_blk2off_table_header, sequence);
	if (extents_off != le16_to_cpu(portion->tbl_hdr.extents_off)) {
		SSDFS_ERR("invalid extents offset %u\n",
			  le16_to_cpu(portion->tbl_hdr.extents_off));
		return -EIO;
	}

	portion->extents_count = le16_to_cpu(portion->tbl_hdr.extents_count);
	ext_array_size = extent_size * portion->extents_count;
	table_off = le16_to_cpu(portion->tbl_hdr.offset_table_off);

	if (ext_array_size == 0 ||
	    (extents_off + ext_array_size) != table_off) {
		SSDFS_ERR("invalid table header: "
			  "extents_off %u, extents_count %u, "
			  "offset_table_off %u\n",
			  extents_off, portion->extents_count, table_off);
		return -EIO;
	}

	if (ext_array_size > 0) {
		u32 array_size = ext_array_size;
		u32 read_bytes = 0;
		int page_index;
		u32 page_off;
#ifdef CONFIG_SSDFS_DEBUG
		int i;
#endif /* CONFIG_SSDFS_DEBUG */

		portion->extent_array = ssdfs_blk2off_kzalloc(ext_array_size,
							      GFP_KERNEL);
		if (unlikely(!portion->extent_array)) {
			SSDFS_ERR("fail to allocate memory\n");
			return -ENOMEM;
		}

		extents_off = offsetof(struct ssdfs_blk2off_table_header,
					sequence);
		page_index = extents_off >> PAGE_SHIFT;
		page_off = extents_off % PAGE_SIZE;

		while (array_size > 0) {
			u32 size;
			struct page *page;

			if (page_index >= pagevec_count(portion->blk2off_pvec)) {
				SSDFS_ERR("invalid request: "
					  "page_index %d, pagevec_size %u\n",
					  page_index,
					  pagevec_count(portion->blk2off_pvec));
				return -ERANGE;
			}

			size = min_t(u32, PAGE_SIZE - page_off,
					array_size);
			page = portion->blk2off_pvec->pages[page_index];

			ssdfs_lock_page(page);
			err = ssdfs_memcpy_from_page(portion->extent_array,
						     read_bytes, ext_array_size,
						     page,
						     page_off, PAGE_SIZE,
						     size);
			ssdfs_unlock_page(page);

			if (unlikely(err)) {
				SSDFS_ERR("fail to copy: err %d\n",
					  err);
				return err;
			}

			read_bytes += size;
			array_size -= size;
			extents_off += size;

			page_index = extents_off >> PAGE_SHIFT;
			page_off = extents_off % PAGE_SIZE;
		};

#ifdef CONFIG_SSDFS_DEBUG
		for (i = 0; i < portion->extents_count; i++) {
			struct ssdfs_translation_extent *extent;
			extent = &portion->extent_array[i];

			SSDFS_DBG("index %d, logical_blk %u, offset_id %u, "
				  "len %u, sequence_id %u, state %u\n",
				  i,
				  le16_to_cpu(extent->logical_blk),
				  le16_to_cpu(extent->offset_id),
				  le16_to_cpu(extent->len),
				  extent->sequence_id,
				  extent->state);
		}
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return 0;
}

/*
 * ssdfs_get_fragment_header() - get fragment header
 * @portion: initialization environment [in | out]
 * @offset: header offset in bytes
 */
static
int ssdfs_get_fragment_header(struct ssdfs_blk2off_init *portion,
			      u32 offset)
{
	size_t hdr_size = sizeof(struct ssdfs_phys_offset_table_header);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || !portion->blk2off_pvec);

	SSDFS_DBG("source %p, offset %u\n",
		  portion->blk2off_pvec, offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_unaligned_read_pagevec(portion->blk2off_pvec,
					   offset,
					   hdr_size,
					   &portion->pot_hdr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_get_checked_fragment() - get checked table's fragment
 * @portion: initialization environment [in | out]
 *
 * This method tries to get and to check fragment validity.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EIO        - corrupted fragment.
 * %-EEXIST     - has been initialized already.
 */
static
int ssdfs_get_checked_fragment(struct ssdfs_blk2off_init *portion)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_phys_offset_table_fragment *fragment;
	struct page *page;
	void *kaddr;
	int page_index;
	u32 page_off;
	size_t fragment_size;
	u16 start_id;
	u16 sequence_id;
	int state;
	u32 read_bytes;
#ifdef CONFIG_SSDFS_DEBUG
	int i;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || !portion->table || !portion->blk2off_pvec);

	SSDFS_DBG("table %p, peb_index %u, source %p, offset %u\n",
		  portion->table, portion->peb_index,
		  portion->blk2off_pvec, portion->pot_hdr_off);
#endif /* CONFIG_SSDFS_DEBUG */

	fragment_size = le32_to_cpu(portion->pot_hdr.byte_size);
	start_id = le16_to_cpu(portion->pot_hdr.start_id);
	sequence_id = le16_to_cpu(portion->pot_hdr.sequence_id);

	SSDFS_DBG("sequence_id %u\n", sequence_id);

	if (fragment_size > PAGE_SIZE) {
		SSDFS_ERR("invalid fragment_size %zu\n",
			  fragment_size);

#ifdef CONFIG_SSDFS_DEBUG
		for (i = 0; i < pagevec_count(portion->blk2off_pvec); i++) {
			page = portion->blk2off_pvec->pages[i];

			kaddr = kmap_local_page(page);
			SSDFS_DBG("PAGE DUMP: index %d\n",
				  i);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr,
					     PAGE_SIZE);
			SSDFS_DBG("\n");
			kunmap_local(kaddr);
		}
#endif /* CONFIG_SSDFS_DEBUG */

		return -EIO;
	}

	if (sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		SSDFS_ERR("invalid sequence_id %u\n",
			  sequence_id);
		return -EIO;
	}

	phys_off_table = &portion->table->peb[portion->peb_index];

	kaddr = ssdfs_sequence_array_get_item(phys_off_table->sequence,
						sequence_id);
	if (IS_ERR_OR_NULL(kaddr)) {
		/* expected state -> continue logic */
		SSDFS_DBG("fragment %u is absent\n",
			  sequence_id);
	} else {
		SSDFS_DBG("fragment %u has been initialized already\n",
			  sequence_id);
		return -EEXIST;
	}

	fragment = ssdfs_blk2off_frag_alloc();
	if (IS_ERR_OR_NULL(fragment)) {
		err = (fragment == NULL ? -ENOMEM : PTR_ERR(fragment));
		SSDFS_ERR("fail to allocate fragment: "
			  "err %d\n", err);
		return err;
	}

	err = ssdfs_sequence_array_init_item(phys_off_table->sequence,
					     sequence_id,
					     fragment);
	if (unlikely(err)) {
		ssdfs_blk2off_frag_free(fragment);
		SSDFS_ERR("fail to init fragment: "
			  "err %d\n", err);
		return err;
	}

	state = SSDFS_BLK2OFF_FRAG_CREATED;
	err = ssdfs_blk2off_table_init_fragment(fragment,
						sequence_id,
						start_id,
						portion->table->pages_per_peb,
						state,
						&fragment_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to initialize fragment: err %d\n",
			  err);
		return err;
	}

	page_index = portion->pot_hdr_off >> PAGE_SHIFT;
	if (portion->pot_hdr_off >= PAGE_SIZE)
		page_off = portion->pot_hdr_off % PAGE_SIZE;
	else
		page_off = portion->pot_hdr_off;

	down_write(&fragment->lock);

	read_bytes = 0;
	while (fragment_size > 0) {
		u32 size;

		size = min_t(u32, PAGE_SIZE - page_off, fragment_size);

		if (page_index >= pagevec_count(portion->blk2off_pvec)) {
			err = -ERANGE;
			SSDFS_ERR("invalid request: "
				  "page_index %d, pvec_size %u\n",
				  page_index,
				  pagevec_count(portion->blk2off_pvec));
			goto finish_fragment_read;
		}

		page = portion->blk2off_pvec->pages[page_index];

		SSDFS_DBG("read_bytes %u, fragment->buf_size %zu, "
			  "page_off %u, size %u\n",
			  read_bytes, fragment->buf_size, page_off, page_off);

		ssdfs_lock_page(page);
		err = ssdfs_memcpy_from_page(fragment->buf,
					     read_bytes, fragment->buf_size,
					     page, page_off, PAGE_SIZE,
					     size);
		ssdfs_unlock_page(page);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n", err);
			goto finish_fragment_read;
		}

		read_bytes += size;
		fragment_size -= size;
		portion->pot_hdr_off += size;

		SSDFS_DBG("read_bytes %u, fragment_size %zu, "
			  "pot_hdr_off %u\n",
			  read_bytes, fragment_size,
			  portion->pot_hdr_off);

		page_index = portion->pot_hdr_off >> PAGE_SHIFT;
		if (portion->pot_hdr_off >= PAGE_SIZE)
			page_off = portion->pot_hdr_off % PAGE_SIZE;
		else
			page_off = portion->pot_hdr_off;
	};

	err = ssdfs_check_fragment(portion->table, portion->peb_index,
				   fragment->hdr,
				   fragment->buf_size);
	if (err)
		goto finish_fragment_read;

	fragment->start_id = start_id;
	atomic_set(&fragment->id_count,
		   le16_to_cpu(fragment->hdr->id_count));
	atomic_set(&fragment->state, SSDFS_BLK2OFF_FRAG_INITIALIZED);

	SSDFS_DBG("FRAGMENT: sequence_id %u, start_id %u, id_count %d\n",
		  sequence_id, start_id, atomic_read(&fragment->id_count));

finish_fragment_read:
	up_write(&fragment->lock);

	if (err) {
		SSDFS_ERR("corrupted fragment: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * is_ssdfs_offset_position_older() - is position checkpoint older?
 * @pos: position offset
 * @cno: checkpoint number for comparison
 */
static inline
bool is_ssdfs_offset_position_older(struct ssdfs_offset_position *pos,
				    u64 cno)
{
	if (pos->cno != SSDFS_INVALID_CNO)
		return pos->cno >= cno;

	return false;
}

/*
 * ssdfs_check_translation_extent() - check translation extent
 * @extent: pointer on translation extent
 * @capacity: logical blocks capacity
 * @sequence_id: extent's sequence id
 *
 * This method tries to check extent's validity.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - corrupted translation extent.
 */
static
int ssdfs_check_translation_extent(struct ssdfs_translation_extent *extent,
				   u16 capacity, u8 sequence_id)
{
	u16 logical_blk;
	u16 offset_id;
	u16 len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extent);
#endif /* CONFIG_SSDFS_DEBUG */

	logical_blk = le16_to_cpu(extent->logical_blk);
	offset_id = le16_to_cpu(extent->offset_id);
	len = le16_to_cpu(extent->len);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("logical_blk %u, offset_id %u, len %u, "
		  "sequence_id %u, state %#x\n",
		  logical_blk, offset_id, len,
		  extent->sequence_id, extent->state);
#endif /* CONFIG_SSDFS_DEBUG */

	if (extent->state <= SSDFS_LOGICAL_BLK_UNKNOWN_STATE ||
	    extent->state >= SSDFS_LOGICAL_BLK_STATE_MAX) {
		SSDFS_ERR("invalid translation extent: "
			  "unknown state %#x\n",
			  extent->state);
		return -EIO;
	}

	if (logical_blk > (U16_MAX - len) ||
	    (logical_blk + len) > capacity) {
		SSDFS_ERR("invalid translation extent: "
			  "logical_blk %u, len %u, capacity %u\n",
			  logical_blk, len, capacity);
		return -EIO;
	}

	if (extent->state != SSDFS_LOGICAL_BLK_FREE) {
		if (offset_id > (U16_MAX - len)) {
			SSDFS_ERR("invalid translation extent: "
				  "offset_id %u, len %u\n",
				  offset_id, len);
			return -EIO;
		}
	}

	if (sequence_id != extent->sequence_id) {
		SSDFS_ERR("invalid translation extent: "
			  "sequence_id %u != extent->sequence_id %u\n",
			  sequence_id, extent->sequence_id);
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_process_used_translation_extent() - process used translation extent
 * @portion: pointer on portion init environment [in | out]
 * @extent_index: index of extent
 *
 * This method checks translation extent, to set bitmap for
 * logical blocks in the extent and to fill portion of
 * offset position array by physical offsets id.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EIO        - corrupted translation extent.
 * %-EAGAIN     - extent is partially processed in the fragment.
 */
static
int ssdfs_process_used_translation_extent(struct ssdfs_blk2off_init *portion,
					  int *extent_index)
{
	struct ssdfs_sequence_array *sequence = NULL;
	struct ssdfs_phys_offset_table_fragment *frag = NULL;
	struct ssdfs_phys_offset_descriptor *phys_off = NULL;
	struct ssdfs_translation_extent *extent = NULL;
	struct ssdfs_dynamic_array *lblk2off;
	void *ptr;
	u16 peb_index;
	u16 sequence_id;
	u16 pos_array_items;
	u16 start_id;
	u16 id_count;
	u16 id_diff;
	u32 logical_blk;
	u16 offset_id;
	u16 len;
	int phys_off_index;
	bool is_partially_processed = false;
	int i, j;
	struct ssdfs_blk_state_offset *state_off;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || !extent_index);
	BUG_ON(!portion->bmap || !portion->extent_array);
	BUG_ON(portion->cno == SSDFS_INVALID_CNO);
	BUG_ON(*extent_index >= portion->extents_count);
#endif /* CONFIG_SSDFS_DEBUG */

	lblk2off = &portion->table->lblk2off;

	peb_index = portion->peb_index;
	sequence_id = le16_to_cpu(portion->pot_hdr.sequence_id);

	sequence = portion->table->peb[peb_index].sequence;
	ptr = ssdfs_sequence_array_get_item(sequence, sequence_id);
	if (IS_ERR_OR_NULL(ptr)) {
		err = (ptr == NULL ? -ENOENT : PTR_ERR(ptr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  sequence_id, err);
		return err;
	}
	frag = (struct ssdfs_phys_offset_table_fragment *)ptr;

	start_id = le16_to_cpu(portion->pot_hdr.start_id);
	id_count = le16_to_cpu(portion->pot_hdr.id_count);

	SSDFS_DBG("start_id %u, id_count %u\n",
		  start_id, id_count);

	extent = &portion->extent_array[*extent_index];

	err = ssdfs_check_translation_extent(extent, portion->capacity,
					     *extent_index);
	if (err) {
		SSDFS_ERR("invalid translation extent: "
			  "index %u, err %d\n",
			  *extent_index, err);
		return err;
	}

	if (*extent_index == 0 && extent->state != SSDFS_LOGICAL_BLK_USED) {
		SSDFS_ERR("invalid translation extent state %#x\n",
			  extent->state);
		return -EIO;
	}

	logical_blk = le16_to_cpu(extent->logical_blk);
	offset_id = le16_to_cpu(extent->offset_id);
	len = le16_to_cpu(extent->len);

	SSDFS_DBG("logical_blk %u, offset_id %u, len %u, "
		  "sequence_id %u, state %#x\n",
		  logical_blk, offset_id, len,
		  extent->sequence_id, extent->state);

	if ((start_id + id_count) < offset_id) {
		SSDFS_ERR("start_id %u + id_count %u < offset_id %u\n",
			  start_id, id_count, offset_id);
		return -EIO;
	}

	if ((offset_id + len) <= start_id) {
		SSDFS_ERR("offset_id %u + len %u <= start_id %u\n",
			  offset_id, len, start_id);
		return -EIO;
	}

	if (offset_id < start_id) {
		SSDFS_DBG("offset_id %u, len %u, "
			  "start_id %u,id_count %u\n",
			  offset_id, len,
			  start_id, id_count);

		id_diff = start_id - offset_id;
		offset_id += id_diff;
		logical_blk += id_diff;
		len -= id_diff;
	}

	if ((offset_id + len) > (start_id + id_count)) {
		SSDFS_DBG("offset_id %u, len %u, "
			  "start_id %u,id_count %u\n",
			  offset_id, len,
			  start_id, id_count);

		is_partially_processed = true;

		/* correct lenght */
		len = (start_id + id_count) - offset_id;
	}

	pos_array_items = portion->capacity - logical_blk;

	if (pos_array_items < len) {
		SSDFS_ERR("array_items %u < len %u\n",
			  pos_array_items, len);
		return -EINVAL;
	}

	if (id_count > atomic_read(&frag->id_count)) {
		SSDFS_ERR("id_count %u > frag->id_count %d\n",
			  id_count,
			  atomic_read(&frag->id_count));
		return -EIO;
	}

	phys_off_index = offset_id - start_id;

	if ((phys_off_index + len) > id_count) {
		SSDFS_ERR("phys_off_index %d, len %u, id_count %u\n",
			  phys_off_index, len, id_count);
		return -EIO;
	}

	bitmap_clear(portion->bmap, 0, portion->capacity);

	down_read(&frag->lock);

#ifdef CONFIG_SSDFS_DEBUG
	for (j = 0; j < pagevec_count(portion->blk_desc_pvec); j++) {
		void *kaddr;
		struct page *page = portion->blk_desc_pvec->pages[j];

		kaddr = kmap_local_page(page);
		SSDFS_DBG("PAGE DUMP: index %d\n",
			  j);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr,
				     PAGE_SIZE);
		SSDFS_DBG("\n");
		kunmap_local(kaddr);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < len; i++) {
		size_t area_tbl_size = sizeof(struct ssdfs_area_block_table);
		size_t desc_size = sizeof(struct ssdfs_block_descriptor);
		struct ssdfs_offset_position *pos;
		u16 id = offset_id + i;
		u16 cur_blk;
		u32 byte_offset;
		bool is_invalid = false;

		phys_off = &frag->phys_offs[phys_off_index + i];

		cur_blk = le16_to_cpu(phys_off->page_desc.logical_blk);
		byte_offset = le32_to_cpu(phys_off->blk_state.byte_offset);

		if (byte_offset < area_tbl_size) {
			err = -EIO;
			SSDFS_ERR("corrupted phys offset: "
				  "byte_offset %u, area_tbl_size %zu\n",
				  byte_offset, area_tbl_size);
			goto finish_process_fragment;
		}

		byte_offset -= area_tbl_size;

		SSDFS_DBG("cur_blk %u, byte_offset %u\n",
			  cur_blk, byte_offset);

		if (cur_blk >= portion->capacity) {
			err = -EIO;
			SSDFS_ERR("logical_blk %u >= portion->capacity %u\n",
				  cur_blk, portion->capacity);
			goto finish_process_fragment;
		}

		if (cur_blk < logical_blk || cur_blk >= (logical_blk + len)) {
			err = -EIO;
			SSDFS_ERR("cur_blk %u, logical_blk %u, len %u\n",
				  cur_blk, logical_blk, len);
			goto finish_process_fragment;
		}

		pos = SSDFS_OFF_POS(ssdfs_dynamic_array_get_locked(lblk2off,
								   cur_blk));
		if (IS_ERR_OR_NULL(pos)) {
			err = (pos == NULL ? -ENOENT : PTR_ERR(pos));
			SSDFS_ERR("fail to get logical block: "
				  "cur_blk %u, err %d\n",
				  cur_blk, err);
			goto finish_process_fragment;
		}

		SSDFS_DBG("portion->cno %#llx, "
			  "pos (cno %#llx, id %u, peb_index %u, "
			  "sequence_id %u, offset_index %u)\n",
			  portion->cno,
			  pos->cno, pos->id, pos->peb_index,
			  pos->sequence_id, pos->offset_index);

		if (is_ssdfs_offset_position_older(pos, portion->cno)) {
			/* logical block has been initialized already */
			SSDFS_DBG("logical block %u has been initialized already\n",
				  cur_blk);
			err = ssdfs_dynamic_array_release(lblk2off,
							  cur_blk, pos);
			if (unlikely(err)) {
				SSDFS_ERR("fail to release: "
					  "cur_blk %u, err %d\n",
					  cur_blk, err);
				goto finish_process_fragment;
			} else
				continue;
		}

		peb_index = portion->peb_index;

		bitmap_set(portion->bmap, cur_blk, 1);

		pos->cno = portion->cno;
		pos->id = id;
		pos->peb_index = peb_index;
		pos->sequence_id = sequence_id;
		pos->offset_index = phys_off_index + i;

		err = ssdfs_unaligned_read_pagevec(portion->blk_desc_pvec,
						   byte_offset,
						   desc_size,
						   &pos->blk_desc.buf);
		if (err == -E2BIG) {
			err = 0;
			SSDFS_DBG("unable init block descriptor: "
				  "logical block %u\n",
				  cur_blk);

			pos->blk_desc.status = SSDFS_BLK_DESC_BUF_UNKNOWN_STATE;
			memset(&pos->blk_desc.buf, 0xFF,
				sizeof(desc_size));
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to read block descriptor: "
				  "cur_blk %u, err %d\n",
				  cur_blk, err);
			ssdfs_dynamic_array_release(lblk2off,
						    cur_blk, pos);
			goto finish_process_fragment;
		} else
			pos->blk_desc.status = SSDFS_BLK_DESC_BUF_INITIALIZED;

		state_off = &pos->blk_desc.buf.state[0];

		switch (pos->blk_desc.status) {
		case SSDFS_BLK_DESC_BUF_INITIALIZED:
			is_invalid =
				IS_SSDFS_BLK_STATE_OFFSET_INVALID(state_off);
			break;

		default:
			is_invalid = false;
			break;
		}

		if (is_invalid) {
			err = -ERANGE;
			SSDFS_ERR("block state offset invalid\n");

			SSDFS_ERR("status %#x, ino %llu, "
				  "logical_offset %u, peb_index %u, "
				  "peb_page %u\n",
				  pos->blk_desc.status,
				  le64_to_cpu(pos->blk_desc.buf.ino),
				  le32_to_cpu(pos->blk_desc.buf.logical_offset),
				  le16_to_cpu(pos->blk_desc.buf.peb_index),
				  le16_to_cpu(pos->blk_desc.buf.peb_page));

			for (j = 0; j < SSDFS_BLK_STATE_OFF_MAX; j++) {
				state_off = &pos->blk_desc.buf.state[j];

				SSDFS_ERR("BLK STATE OFFSET %d: "
					  "log_start_page %u, log_area %#x, "
					  "byte_offset %u, "
					  "peb_migration_id %u\n",
					  j,
					  le16_to_cpu(state_off->log_start_page),
					  state_off->log_area,
					  le32_to_cpu(state_off->byte_offset),
					  state_off->peb_migration_id);
			}

			ssdfs_dynamic_array_release(lblk2off, cur_blk, pos);

#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */

			goto finish_process_fragment;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("status %#x, ino %llu, "
			  "logical_offset %u, peb_index %u, peb_page %u\n",
			  pos->blk_desc.status,
			  le64_to_cpu(pos->blk_desc.buf.ino),
			  le32_to_cpu(pos->blk_desc.buf.logical_offset),
			  le16_to_cpu(pos->blk_desc.buf.peb_index),
			  le16_to_cpu(pos->blk_desc.buf.peb_page));

		for (j = 0; j < SSDFS_BLK_STATE_OFF_MAX; j++) {
			state_off = &pos->blk_desc.buf.state[j];

			SSDFS_DBG("BLK STATE OFFSET %d: "
				  "log_start_page %u, log_area %#x, "
				  "byte_offset %u, peb_migration_id %u\n",
				  j,
				  le16_to_cpu(state_off->log_start_page),
				  state_off->log_area,
				  le32_to_cpu(state_off->byte_offset),
				  state_off->peb_migration_id);
		}

		SSDFS_DBG("set init bitmap: cur_blk %u\n",
			  cur_blk);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_dynamic_array_release(lblk2off, cur_blk, pos);
		if (unlikely(err)) {
			SSDFS_ERR("fail to release: "
				  "cur_blk %u, err %d\n",
				  cur_blk, err);
			goto finish_process_fragment;
		}

		err = ssdfs_blk2off_table_bmap_set(&portion->table->lbmap,
						   SSDFS_LBMAP_INIT_INDEX,
						   cur_blk);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set init bitmap: "
				  "logical_blk %u, err %d\n",
				  cur_blk, err);
			goto finish_process_fragment;
		}
	}

finish_process_fragment:
	up_read(&frag->lock);

	if (unlikely(err))
		return err;

	if (bitmap_intersects(portion->bmap,
			portion->table->lbmap.array[SSDFS_LBMAP_STATE_INDEX],
			portion->table->lbmap.bits_count)) {
		SSDFS_ERR("invalid translation extent: "
			  "logical_blk %u, offset_id %u, len %u\n",
			  logical_blk, offset_id, len);
		return -EIO;
	}

	bitmap_or(portion->table->lbmap.array[SSDFS_LBMAP_STATE_INDEX],
		  portion->bmap,
		  portion->table->lbmap.array[SSDFS_LBMAP_STATE_INDEX],
		  portion->table->lbmap.bits_count);

	SSDFS_DBG("init_bmap %lx, state_bmap %lx, modification_bmap %lx\n",
		  *portion->table->lbmap.array[SSDFS_LBMAP_INIT_INDEX],
		  *portion->table->lbmap.array[SSDFS_LBMAP_STATE_INDEX],
		  *portion->table->lbmap.array[SSDFS_LBMAP_MODIFICATION_INDEX]);

	if (is_partially_processed) {
		SSDFS_DBG("extent has been processed partially: "
			  "index %u\n", *extent_index);
		return -EAGAIN;
	}

	return 0;
}

/*
 * ssdfs_process_free_translation_extent() - process free translation extent
 * @portion: pointer on portion init environment [in | out]
 * @extent_index: index of extent
 *
 * This method checks translation extent, to set bitmap for
 * logical blocks in the extent and to fill portion of
 * offset position array by physical offsets id.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EIO        - corrupted translation extent.
 */
static
int ssdfs_process_free_translation_extent(struct ssdfs_blk2off_init *portion,
					  int *extent_index)
{
	struct ssdfs_sequence_array *sequence = NULL;
	struct ssdfs_phys_offset_table_fragment *frag = NULL;
	struct ssdfs_translation_extent *extent = NULL;
	struct ssdfs_dynamic_array *lblk2off;
	void *ptr;
	u16 peb_index;
	u16 sequence_id;
	u16 pos_array_items;
	size_t pos_size = sizeof(struct ssdfs_offset_position);
	u32 logical_blk;
	u16 len;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || !extent_index);
	BUG_ON(!portion->extent_array);
	BUG_ON(portion->cno == SSDFS_INVALID_CNO);
	BUG_ON(*extent_index >= portion->extents_count);
#endif /* CONFIG_SSDFS_DEBUG */

	lblk2off = &portion->table->lblk2off;

	peb_index = portion->peb_index;
	sequence_id = le16_to_cpu(portion->pot_hdr.sequence_id);

	sequence = portion->table->peb[peb_index].sequence;
	ptr = ssdfs_sequence_array_get_item(sequence, sequence_id);
	if (IS_ERR_OR_NULL(ptr)) {
		err = (ptr == NULL ? -ENOENT : PTR_ERR(ptr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  sequence_id, err);
		return err;
	}
	frag = (struct ssdfs_phys_offset_table_fragment *)ptr;

	extent = &portion->extent_array[*extent_index];
	logical_blk = le16_to_cpu(extent->logical_blk);
	len = le16_to_cpu(extent->len);

	SSDFS_DBG("logical_blk %u, len %u, "
		  "sequence_id %u, state %#x\n",
		  logical_blk, len,
		  extent->sequence_id, extent->state);

	pos_array_items = portion->capacity - logical_blk;

	if (pos_array_items < len) {
		SSDFS_ERR("array_items %u < len %u\n",
			  pos_array_items, len);
		return -EINVAL;
	}

	err = ssdfs_check_translation_extent(extent, portion->capacity,
					     *extent_index);
	if (err) {
		SSDFS_ERR("invalid translation extent: "
			  "sequence_id %u, err %d\n",
			  *extent_index, err);
		return err;
	}

	down_read(&frag->lock);

	for (i = 0; i < len; i++) {
		struct ssdfs_offset_position *pos;
		u32 cur_blk = logical_blk + i;

		pos = SSDFS_OFF_POS(ssdfs_dynamic_array_get_locked(lblk2off,
								   cur_blk));
		if (IS_ERR_OR_NULL(pos)) {
			err = (pos == NULL ? -ENOENT : PTR_ERR(pos));
			SSDFS_ERR("fail to get logical block: "
				  "cur_blk %u, err %d\n",
				  cur_blk, err);
			goto finish_process_fragment;
		}

		SSDFS_DBG("portion->cno %#llx, "
			  "pos (cno %#llx, id %u, peb_index %u, "
			  "sequence_id %u, offset_index %u)\n",
			  portion->cno,
			  pos->cno, pos->id, pos->peb_index,
			  pos->sequence_id, pos->offset_index);

		if (is_ssdfs_offset_position_older(pos, portion->cno)) {
			/* logical block has been initialized already */
			SSDFS_DBG("logical block %u has been initialized already\n",
				  cur_blk);
			err = ssdfs_dynamic_array_release(lblk2off,
							  cur_blk, pos);
			if (unlikely(err)) {
				SSDFS_ERR("fail to release: "
					  "cur_blk %u, err %d\n",
					  cur_blk, err);
				goto finish_process_fragment;
			} else
				continue;
		}

		err = ssdfs_blk2off_table_bmap_clear(&portion->table->lbmap,
						     SSDFS_LBMAP_STATE_INDEX,
						     cur_blk);
		if (unlikely(err)) {
			SSDFS_ERR("fail to clear state bitmap: "
				  "logical_blk %u, err %d\n",
				  cur_blk, err);
			goto finish_process_fragment;
		}

		memset(pos, 0xFF, pos_size);

		pos->cno = portion->cno;
		pos->peb_index = portion->peb_index;

		err = ssdfs_dynamic_array_release(lblk2off, cur_blk, pos);
		if (unlikely(err)) {
			SSDFS_ERR("fail to release: "
				  "cur_blk %u, err %d\n",
				  cur_blk, err);
			goto finish_process_fragment;
		}

		SSDFS_DBG("set init bitmap: cur_blk %u\n",
			  cur_blk);

		err = ssdfs_blk2off_table_bmap_set(&portion->table->lbmap,
						   SSDFS_LBMAP_INIT_INDEX,
						   cur_blk);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set init bitmap: "
				  "logical_blk %u, err %d\n",
				  cur_blk, err);
			goto finish_process_fragment;
		}

		/*
		 * Free block needs to be marked as modified
		 * with the goal not to lose the information
		 * about free blocks in the case of PEB migration.
		 * Because, offsets translation table's snapshot
		 * needs to contain information about free blocks.
		 */
		err = ssdfs_blk2off_table_bmap_set(&portion->table->lbmap,
						SSDFS_LBMAP_MODIFICATION_INDEX,
						cur_blk);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set modification bitmap: "
				  "logical_blk %u, err %d\n",
				  cur_blk, err);
			goto finish_process_fragment;
		}
	}

finish_process_fragment:
	up_read(&frag->lock);

	return err;
}

/*
 * ssdfs_blk2off_fragment_init() - initialize portion's fragment
 * @portion: pointer on portion init environment [in | out]
 * @fragment_index: index of fragment
 * @extent_index: pointer on extent index [in | out]
 */
static
int ssdfs_blk2off_fragment_init(struct ssdfs_blk2off_init *portion,
				int fragment_index,
				int *extent_index)
{
	struct ssdfs_sequence_array *sequence = NULL;
	struct ssdfs_translation_extent *extent = NULL;
	u16 logical_blk;
	u16 offset_id;
	u16 len;
	u16 start_id;
	u16 id_count;
	u16 processed_offset_ids = 0;
	int state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || !portion->table || !portion->blk2off_pvec);
	BUG_ON(!portion->bmap || !portion->extent_array);
	BUG_ON(!extent_index);
	BUG_ON(portion->peb_index >= portion->table->pebs_count);

	SSDFS_DBG("peb_index %u, fragment_index %d, "
		  "extent_index %u, extents_count %u\n",
		  portion->peb_index, fragment_index,
		  *extent_index, portion->extents_count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (fragment_index == 0) {
		portion->pot_hdr_off = portion->tbl_hdr_off +
				le16_to_cpu(portion->tbl_hdr.offset_table_off);
		err = ssdfs_get_fragment_header(portion, portion->pot_hdr_off);
	} else {
		portion->pot_hdr_off = portion->tbl_hdr_off +
				le16_to_cpu(portion->pot_hdr.next_fragment_off);
		err = ssdfs_get_fragment_header(portion, portion->pot_hdr_off);
	}

	if (err) {
		SSDFS_ERR("fail to get fragment header: err %d\n",
			  err);
		return err;
	}

	err = ssdfs_get_checked_fragment(portion);
	if (err == -EEXIST) {
		SSDFS_DBG("fragment has been initialized already: "
			  "peb_index %u, offset %u\n",
			  portion->peb_index,
			  portion->pot_hdr_off);
		return err;
	} else if (err) {
		SSDFS_ERR("fail to get checked fragment: "
			  "peb_index %u, offset %u, err %d\n",
			  portion->peb_index,
			  portion->pot_hdr_off, err);
		return err;
	}

	if (*extent_index >= portion->extents_count) {
		SSDFS_DBG("extent_index %u >= extents_count %u\n",
			  *extent_index, portion->extents_count);
	}

	start_id = le16_to_cpu(portion->pot_hdr.start_id);
	id_count = le16_to_cpu(portion->pot_hdr.id_count);

	SSDFS_DBG("start_id %u, id_count %u\n",
		  start_id, id_count);

	while (*extent_index < portion->extents_count) {
		extent = &portion->extent_array[*extent_index];
		logical_blk = le16_to_cpu(extent->logical_blk);
		offset_id = le16_to_cpu(extent->offset_id);
		len = le16_to_cpu(extent->len);
		state = extent->state;

		if (processed_offset_ids > id_count) {
			SSDFS_ERR("processed_offset_ids %u > id_count %u\n",
				  processed_offset_ids, id_count);
			return -ERANGE;
		} else if (processed_offset_ids == id_count) {
			SSDFS_DBG("fragment has been processed: "
				  "processed_offset_ids %u == id_count %u\n",
				  processed_offset_ids, id_count);
			goto finish_fragment_processing;
		}

		SSDFS_DBG("logical_blk %u, len %u, "
			  "state %#x, extent_index %d\n",
			  logical_blk, len, state, *extent_index);

		if (logical_blk >= portion->capacity) {
			err = -ERANGE;
			SSDFS_ERR("logical_blk %u >= capacity %u\n",
				  logical_blk, portion->capacity);
			return err;
		}

		if (state != SSDFS_LOGICAL_BLK_FREE) {
			if (offset_id >= (start_id + id_count)) {
				SSDFS_DBG("offset_id %u, start_id %u, "
					  "id_count %u\n",
					  offset_id, start_id, id_count);
				goto finish_fragment_processing;
			}
		}

		if (state == SSDFS_LOGICAL_BLK_USED) {
			err = ssdfs_process_used_translation_extent(portion,
								extent_index);
			if (err == -EAGAIN) {
				SSDFS_DBG("extent has been processed partially: "
					  "sequence_id %u, err %d\n",
					  *extent_index, err);
			} else if (unlikely(err)) {
				SSDFS_ERR("invalid translation extent: "
					  "sequence_id %u, err %d\n",
					  *extent_index, err);
				return err;
			}
		} else if (state == SSDFS_LOGICAL_BLK_FREE) {
			err = ssdfs_process_free_translation_extent(portion,
								extent_index);
			if (err) {
				SSDFS_ERR("invalid translation extent: "
					  "sequence_id %u, err %d\n",
					  *extent_index, err);
				return err;
			}
		} else
			BUG();

		if (err == -EAGAIN) {
			SSDFS_DBG("don't increment extent index\n");
			goto finish_fragment_processing;
		} else
			++*extent_index;

		processed_offset_ids += len;
	};

finish_fragment_processing:
	if (portion->table->init_cno == U64_MAX ||
	    portion->cno >= portion->table->init_cno) {
		u16 peb_index = portion->peb_index;
		u16 sequence_id = le16_to_cpu(portion->pot_hdr.sequence_id);

		sequence = portion->table->peb[peb_index].sequence;

		if (is_ssdfs_sequence_array_last_id_invalid(sequence) ||
		    ssdfs_sequence_array_last_id(sequence) <= sequence_id) {
			portion->table->init_cno = portion->cno;
			portion->table->used_logical_blks =
				le16_to_cpu(portion->pot_hdr.used_logical_blks);
			portion->table->free_logical_blks =
				le16_to_cpu(portion->pot_hdr.free_logical_blks);
			portion->table->last_allocated_blk =
				le16_to_cpu(portion->pot_hdr.last_allocated_blk);

			ssdfs_sequence_array_set_last_id(sequence, sequence_id);
		}
	}

	atomic_inc(&portion->table->peb[portion->peb_index].fragment_count);

	return err;
}

/*
 * ssdfs_define_peb_table_state() - define PEB's table state
 * @table: pointer on translation table object
 * @peb_index: PEB's index
 */
static inline
int ssdfs_define_peb_table_state(struct ssdfs_blk2off_table *table,
				 u16 peb_index)
{
	int state;
	u16 last_allocated_blk;
	u16 allocated_blks;
	int init_bits;
	int count;
	unsigned long last_id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(peb_index >= table->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	count = atomic_read(&table->peb[peb_index].fragment_count);
	last_id = ssdfs_sequence_array_last_id(table->peb[peb_index].sequence);
	last_allocated_blk = table->last_allocated_blk;

	if (last_allocated_blk >= U16_MAX)
		allocated_blks = 0;
	else
		allocated_blks = last_allocated_blk + 1;

	init_bits = bitmap_weight(table->lbmap.array[SSDFS_LBMAP_INIT_INDEX],
				  allocated_blks);

	SSDFS_DBG("table %p, peb_index %u, count %d, last_id %lu, "
		  "last_allocated_blk %u, init_bits %d, "
		  "allocated_blks %u\n",
		  table, peb_index, count, last_id,
		  last_allocated_blk, init_bits,
		  allocated_blks);

	if (init_bits < 0) {
		SSDFS_ERR("invalid init bmap: weight %d\n",
			  init_bits);
		return -ERANGE;
	}

	if (count == 0) {
		SSDFS_ERR("fragment_count == 0\n");
		return -ERANGE;
	}

	state = atomic_cmpxchg(&table->peb[peb_index].state,
				SSDFS_BLK2OFF_TABLE_CREATED,
				SSDFS_BLK2OFF_TABLE_PARTIAL_INIT);
	if (state <= SSDFS_BLK2OFF_TABLE_UNDEFINED ||
	    state > SSDFS_BLK2OFF_TABLE_DIRTY_PARTIAL_INIT) {
		SSDFS_WARN("unexpected state %#x\n",
			   state);
		return -ERANGE;
	}

	SSDFS_DBG("state %#x\n", state);

	if (init_bits > 0) {
		if (init_bits >= allocated_blks) {
			state = atomic_cmpxchg(&table->peb[peb_index].state,
					SSDFS_BLK2OFF_TABLE_PARTIAL_INIT,
					SSDFS_BLK2OFF_TABLE_COMPLETE_INIT);
			if (state == SSDFS_BLK2OFF_TABLE_PARTIAL_INIT) {
				/* table is completely initialized */
				goto finish_define_peb_table_state;
			}

			state = atomic_cmpxchg(&table->peb[peb_index].state,
					SSDFS_BLK2OFF_TABLE_DIRTY_PARTIAL_INIT,
					SSDFS_BLK2OFF_TABLE_DIRTY);
			if (state == SSDFS_BLK2OFF_TABLE_DIRTY_PARTIAL_INIT) {
				/* table is dirty already */
				goto finish_define_peb_table_state;
			}

			if (state < SSDFS_BLK2OFF_TABLE_PARTIAL_INIT ||
			    state > SSDFS_BLK2OFF_TABLE_COMPLETE_INIT) {
				SSDFS_WARN("unexpected state %#x\n",
					   state);
				return -ERANGE;
			}
		}
	} else {
		SSDFS_WARN("init_bits == 0\n");
		return -ERANGE;
	}

finish_define_peb_table_state:
	SSDFS_DBG("state %#x\n", atomic_read(&table->peb[peb_index].state));
	return 0;
}

/*
 * ssdfs_define_blk2off_table_object_state() - define table object state
 * @table: pointer on translation table object
 */
static inline
int ssdfs_define_blk2off_table_object_state(struct ssdfs_blk2off_table *table)
{
	int state;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
#endif /* CONFIG_SSDFS_DEBUG */

	state = SSDFS_BLK2OFF_TABLE_STATE_MAX;
	for (i = 0; i < table->pebs_count; i++) {
		int peb_tbl_state = atomic_read(&table->peb[i].state);

		if (peb_tbl_state < state)
			state = peb_tbl_state;
	}

	SSDFS_DBG("table %p, state %#x\n", table, state);

	switch (state) {
	case SSDFS_BLK2OFF_TABLE_CREATED:
		state = atomic_read(&table->state);
		if (state != SSDFS_BLK2OFF_OBJECT_CREATED) {
			SSDFS_WARN("unexpected state %#x\n",
				   state);
			return -ERANGE;
		}
		break;

	case SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT:
	case SSDFS_BLK2OFF_TABLE_DIRTY_PARTIAL_INIT:
		state = atomic_cmpxchg(&table->state,
					SSDFS_BLK2OFF_OBJECT_CREATED,
					SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT);
		complete_all(&table->partial_init_end);

		if (state <= SSDFS_BLK2OFF_OBJECT_UNKNOWN ||
		    state > SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
			SSDFS_WARN("unexpected state %#x\n",
				   state);
			return -ERANGE;
		}
		break;

	case SSDFS_BLK2OFF_TABLE_COMPLETE_INIT:
	case SSDFS_BLK2OFF_TABLE_DIRTY:
		state = atomic_cmpxchg(&table->state,
					SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT,
					SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT);
		if (state == SSDFS_BLK2OFF_OBJECT_CREATED) {
			state = atomic_cmpxchg(&table->state,
					SSDFS_BLK2OFF_OBJECT_CREATED,
					SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT);
		}
		complete_all(&table->partial_init_end);
		complete_all(&table->full_init_end);

		if (state < SSDFS_BLK2OFF_OBJECT_CREATED ||
		    state > SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT) {
			SSDFS_WARN("unexpected state %#x\n",
				   state);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", state);
		return -ERANGE;
	};

	SSDFS_DBG("state %#x\n", atomic_read(&table->state));

	return 0;
}

/*
 * ssdfs_blk2off_table_partial_init() - initialize PEB's table fragment
 * @table: pointer on translation table object
 * @blk2off_pvec: blk2off fragment
 * @blk_desc_pvec: blk desc fragment
 * @peb_index: PEB's index
 * @cno: fragment's checkpoint (log's checkpoint)
 *
 * This method tries to initialize PEB's table fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EIO        - corrupted translation extent.
 */
int ssdfs_blk2off_table_partial_init(struct ssdfs_blk2off_table *table,
				     struct pagevec *blk2off_pvec,
				     struct pagevec *blk_desc_pvec,
				     u16 peb_index,
				     u64 cno)
{
	struct ssdfs_blk2off_init portion;
	int extent_index = 0;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !blk2off_pvec || !blk_desc_pvec);
	BUG_ON(peb_index >= table->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("table %p, peb_index %u\n",
		  table, peb_index);
#else
	SSDFS_DBG("table %p, peb_index %u\n",
		  table, peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	memset(&portion, 0, sizeof(struct ssdfs_blk2off_init));

	if (pagevec_count(blk2off_pvec) == 0) {
		SSDFS_ERR("fail to init because of empty pagevec\n");
		return -EINVAL;
	}

	if (ssdfs_blk2off_table_initialized(table, peb_index)) {
		SSDFS_DBG("PEB's table has been initialized already: "
			   "peb_index %u\n",
			   peb_index);
		return 0;
	}

	portion.table = table;
	portion.blk2off_pvec = blk2off_pvec;
	portion.blk_desc_pvec = blk_desc_pvec;
	portion.peb_index = peb_index;
	portion.cno = cno;

	portion.tbl_hdr_off = 0;
	err = ssdfs_get_checked_table_header(&portion);
	if (err) {
		SSDFS_ERR("invalid table header\n");
		return err;
	}

	down_write(&table->translation_lock);

	portion.capacity = table->lblk2off_capacity;

	err = ssdfs_blk2off_prepare_temp_bmap(&portion);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate memory\n");
		goto unlock_translation_table;
	}

	err = ssdfs_blk2off_prepare_extent_array(&portion);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate memory\n");
		goto unlock_translation_table;
	}

	portion.pot_hdr_off = portion.tbl_hdr_off +
			le16_to_cpu(portion.tbl_hdr.offset_table_off);

	for (i = 0; i < portion.fragments_count; i++) {
		err = ssdfs_blk2off_fragment_init(&portion,
						  i,
						  &extent_index);
		if (err == -EAGAIN) {
			SSDFS_DBG("continue to process extent: "
				  "fragment %d, extent_index %d\n",
				  i, extent_index);
			continue;
		} else if (err == -EEXIST) {
			SSDFS_DBG("fragment has been initiliazed already: "
				  "fragment_index %d, extent_index %d\n",
				  i, extent_index);
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to initialize fragment: "
				  "fragment_index %d, extent_index %d, "
				  "err %d\n",
				  i, extent_index, err);
			goto unlock_translation_table;
		}
	}

	err = ssdfs_define_peb_table_state(table, peb_index);
	if (err) {
		SSDFS_ERR("fail to define PEB's table state: "
			  "peb_index %u, err %d\n",
			  peb_index, err);
		goto unlock_translation_table;
	}

	err = ssdfs_define_blk2off_table_object_state(table);
	if (err) {
		SSDFS_ERR("fail to define table object state: "
			  "err %d\n",
			  err);
		goto unlock_translation_table;
	}

unlock_translation_table:
	up_write(&table->translation_lock);

	ssdfs_blk2off_kvfree(portion.bmap);
	portion.bmap = NULL;
	ssdfs_blk2off_kfree(portion.extent_array);
	portion.extent_array = NULL;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

const u16 last_used_blk[U8_MAX + 1] = {
/* 00 - 0x00 */	U16_MAX, 0, 1, 1,
/* 01 - 0x04 */	2, 2, 2, 2,
/* 02 - 0x08 */	3, 3, 3, 3,
/* 03 - 0x0C */	3, 3, 3, 3,
/* 04 - 0x10 */	4, 4, 4, 4,
/* 05 - 0x14 */	4, 4, 4, 4,
/* 06 - 0x18 */	4, 4, 4, 4,
/* 07 - 0x1C */	4, 4, 4, 4,
/* 08 - 0x20 */	5, 5, 5, 5,
/* 09 - 0x24 */	5, 5, 5, 5,
/* 10 - 0x28 */	5, 5, 5, 5,
/* 11 - 0x2C */	5, 5, 5, 5,
/* 12 - 0x30 */	5, 5, 5, 5,
/* 13 - 0x34 */	5, 5, 5, 5,
/* 14 - 0x38 */	5, 5, 5, 5,
/* 15 - 0x3C */	5, 5, 5, 5,
/* 16 - 0x40 */	6, 6, 6, 6,
/* 17 - 0x44 */	6, 6, 6, 6,
/* 18 - 0x48 */	6, 6, 6, 6,
/* 19 - 0x4C */	6, 6, 6, 6,
/* 20 - 0x50 */	6, 6, 6, 6,
/* 21 - 0x54 */	6, 6, 6, 6,
/* 22 - 0x58 */	6, 6, 6, 6,
/* 23 - 0x5C */	6, 6, 6, 6,
/* 24 - 0x60 */	6, 6, 6, 6,
/* 25 - 0x64 */	6, 6, 6, 6,
/* 26 - 0x68 */	6, 6, 6, 6,
/* 27 - 0x6C */	6, 6, 6, 6,
/* 28 - 0x70 */	6, 6, 6, 6,
/* 29 - 0x74 */	6, 6, 6, 6,
/* 30 - 0x78 */	6, 6, 6, 6,
/* 31 - 0x7C */	6, 6, 6, 6,
/* 32 - 0x80 */	7, 7, 7, 7,
/* 33 - 0x84 */	7, 7, 7, 7,
/* 34 - 0x88 */	7, 7, 7, 7,
/* 35 - 0x8C */	7, 7, 7, 7,
/* 36 - 0x90 */	7, 7, 7, 7,
/* 37 - 0x94 */	7, 7, 7, 7,
/* 38 - 0x98 */	7, 7, 7, 7,
/* 39 - 0x9C */	7, 7, 7, 7,
/* 40 - 0xA0 */	7, 7, 7, 7,
/* 41 - 0xA4 */	7, 7, 7, 7,
/* 42 - 0xA8 */	7, 7, 7, 7,
/* 43 - 0xAC */	7, 7, 7, 7,
/* 44 - 0xB0 */	7, 7, 7, 7,
/* 45 - 0xB4 */	7, 7, 7, 7,
/* 46 - 0xB8 */	7, 7, 7, 7,
/* 47 - 0xBC */	7, 7, 7, 7,
/* 48 - 0xC0 */	7, 7, 7, 7,
/* 49 - 0xC4 */	7, 7, 7, 7,
/* 50 - 0xC8 */	7, 7, 7, 7,
/* 51 - 0xCC */	7, 7, 7, 7,
/* 52 - 0xD0 */	7, 7, 7, 7,
/* 53 - 0xD4 */	7, 7, 7, 7,
/* 54 - 0xD8 */	7, 7, 7, 7,
/* 55 - 0xDC */	7, 7, 7, 7,
/* 56 - 0xE0 */	7, 7, 7, 7,
/* 57 - 0xE4 */	7, 7, 7, 7,
/* 58 - 0xE8 */	7, 7, 7, 7,
/* 59 - 0xEC */	7, 7, 7, 7,
/* 60 - 0xF0 */	7, 7, 7, 7,
/* 61 - 0xF4 */	7, 7, 7, 7,
/* 62 - 0xF8 */	7, 7, 7, 7,
/* 63 - 0xFC */	7, 7, 7, 7
};

/*
 * ssdfs_blk2off_table_find_last_valid_block() - find last valid block
 * @table: pointer on translation table object
 *
 * RETURN:
 * [success] - last valid logical block number.
 * [failure] - U16_MAX.
 */
static
u16 ssdfs_blk2off_table_find_last_valid_block(struct ssdfs_blk2off_table *table)
{
	u16 logical_blk;
	unsigned long *lbmap;
	unsigned char *byte;
	int long_count, byte_count;
	int i, j;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	logical_blk = U16_MAX;
	long_count = BITS_TO_LONGS(table->lbmap.bits_count);
	lbmap = table->lbmap.array[SSDFS_LBMAP_STATE_INDEX];

	for (i = long_count - 1; i >= 0; i--) {
		if (lbmap[i] != 0) {
			byte_count = sizeof(unsigned long);
			for (j = byte_count - 1; j >= 0; j--) {
				byte = (unsigned char *)lbmap[i] + j;
				logical_blk = last_used_blk[*byte];
				if (logical_blk != U16_MAX)
					break;
			}
			goto calculate_logical_blk;
		}
	}

calculate_logical_blk:
	if (logical_blk != U16_MAX)
		logical_blk += i * BITS_PER_LONG;

	SSDFS_DBG("table %p, logical_blk %u\n",
		  table, logical_blk);

	return logical_blk;
}

/*
 * ssdfs_blk2off_table_resize() - resize table
 * @table: pointer on translation table object
 * @new_items_count: new table size
 *
 * This method tries to grow or to shrink table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - unable to shrink table.
 * %-ENOMEM     - unable to realloc table.
 */
int ssdfs_blk2off_table_resize(struct ssdfs_blk2off_table *table,
				u16 new_items_count)
{
	u16 last_blk;
	int diff;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, lblk2off_capacity %u, new_items_count %u\n",
		  table, table->lblk2off_capacity, new_items_count);

	down_write(&table->translation_lock);

	if (new_items_count == table->lblk2off_capacity) {
		SSDFS_WARN("new_items_count %u == lblk2off_capacity %u\n",
			   new_items_count, table->lblk2off_capacity);
		goto finish_table_resize;
	} else if (new_items_count < table->lblk2off_capacity) {
		last_blk = ssdfs_blk2off_table_find_last_valid_block(table);

		if (last_blk != U16_MAX && last_blk >= new_items_count) {
			err = -ERANGE;
			SSDFS_ERR("unable to shrink bitmap: "
				  "last_blk %u >= new_items_count %u\n",
				  last_blk, new_items_count);
			goto finish_table_resize;
		}
	}

	diff = (int)new_items_count - table->lblk2off_capacity;

	table->lblk2off_capacity = new_items_count;
	table->free_logical_blks += diff;

finish_table_resize:
	up_write(&table->translation_lock);

	return err;
}

/*
 * ssdfs_blk2off_table_dirtied() - check that PEB's table is dirty
 * @table: pointer on translation table object
 * @peb_index: PEB's index
 */
bool ssdfs_blk2off_table_dirtied(struct ssdfs_blk2off_table *table,
				 u16 peb_index)
{
	bool is_dirty = false;
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_sequence_array *sequence;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(!table->peb);
	BUG_ON(peb_index >= table->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, peb_index %u\n",
		  table, peb_index);

	phys_off_table = &table->peb[peb_index];
	sequence = phys_off_table->sequence;
	is_dirty = has_ssdfs_sequence_array_state(sequence,
				SSDFS_SEQUENCE_ITEM_DIRTY_TAG);

	switch (atomic_read(&phys_off_table->state)) {
	case SSDFS_BLK2OFF_TABLE_DIRTY:
	case SSDFS_BLK2OFF_TABLE_DIRTY_PARTIAL_INIT:
		if (!is_dirty) {
			/* table is dirty without dirty fragments */
			SSDFS_WARN("table is marked as dirty!\n");
		}
		break;

	default:
		if (is_dirty) {
			/* there are dirty fragments but table is clean */
			SSDFS_WARN("table is not dirty\n");
		}
		break;
	}

	return is_dirty;
}

/*
 * ssdfs_blk2off_table_initialized() - check that PEB's table is initialized
 * @table: pointer on translation table object
 * @peb_index: PEB's index
 */
bool ssdfs_blk2off_table_initialized(struct ssdfs_blk2off_table *table,
				     u16 peb_index)
{
	int state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(peb_index >= table->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, peb_index %u\n",
		  table, peb_index);

	BUG_ON(!table->peb);

	state = atomic_read(&table->peb[peb_index].state);

	return state >= SSDFS_BLK2OFF_TABLE_COMPLETE_INIT &&
		state < SSDFS_BLK2OFF_TABLE_STATE_MAX;
}

static
int ssdfs_change_fragment_state(void *item, int old_state, int new_state)
{
	struct ssdfs_phys_offset_table_fragment *fragment =
		(struct ssdfs_phys_offset_table_fragment *)item;
	int state;

	SSDFS_DBG("old_state %#x, new_state %#x\n",
		  old_state, new_state);

	if (!fragment) {
		SSDFS_ERR("pointer is NULL\n");
		return -ERANGE;
	}

	SSDFS_DBG("sequence_id %u, state %#x\n",
		  fragment->sequence_id,
		  atomic_read(&fragment->state));

	state = atomic_cmpxchg(&fragment->state, old_state, new_state);

	switch (new_state) {
	case SSDFS_BLK2OFF_FRAG_DIRTY:
		switch (state) {
		case SSDFS_BLK2OFF_FRAG_CREATED:
		case SSDFS_BLK2OFF_FRAG_INITIALIZED:
		case SSDFS_BLK2OFF_FRAG_DIRTY:
			/* expected old state */
			break;

		default:
			SSDFS_ERR("invalid old_state %#x\n",
				  old_state);
			return -ERANGE;
		}
		break;

	default:
		if (state != old_state) {
			SSDFS_ERR("state %#x != old_state %#x\n",
				  state, old_state);
			return -ERANGE;
		}
		break;
	}

	return 0;
}

static inline
int ssdfs_calculate_start_sequence_id(u16 last_sequence_id,
				      u16 dirty_fragments,
				      u16 *start_sequence_id)
{
	u16 upper_bound;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!start_sequence_id);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("last_sequence_id %u, dirty_fragments %u\n",
		  last_sequence_id, dirty_fragments);

	*start_sequence_id = U16_MAX;

	if (last_sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		SSDFS_ERR("invalid last_sequence_id %u\n",
			  last_sequence_id);
		return -ERANGE;
	}

	if (dirty_fragments > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		SSDFS_ERR("invalid dirty_fragments %u\n",
			  dirty_fragments);
		return -ERANGE;
	}

	upper_bound = last_sequence_id + 1;

	if (upper_bound >= dirty_fragments)
		*start_sequence_id = upper_bound - dirty_fragments;
	else {
		*start_sequence_id = SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD -
					(dirty_fragments - upper_bound);
	}

	return 0;
}

/*
 * ssdfs_blk2off_table_snapshot() - get table's snapshot
 * @table: pointer on translation table object
 * @peb_index: PEB's index
 * @snapshot: pointer on table's snapshot object
 *
 * This method tries to get table's snapshot. The @bmap_copy
 * and @tbl_copy fields of snapshot object are allocated during
 * getting snapshot by this method. Freeing of allocated
 * memory SHOULD BE MADE by caller.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENODATA    - PEB hasn't dirty fragments.
 */
int ssdfs_blk2off_table_snapshot(struct ssdfs_blk2off_table *table,
				 u16 peb_index,
				 struct ssdfs_blk2off_table_snapshot *snapshot)
{
	struct ssdfs_phys_offset_table_array *pot_table;
	struct ssdfs_sequence_array *sequence;
	u32 capacity;
	size_t bmap_bytes, tbl_bytes;
	u16 last_sequence_id;
	unsigned long dirty_fragments;
	int state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !snapshot);
	BUG_ON(peb_index >= table->pebs_count);

	SSDFS_DBG("table %p, peb_index %u, snapshot %p\n",
		  table, peb_index, snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(snapshot, 0, sizeof(struct ssdfs_blk2off_table_snapshot));
	snapshot->bmap_copy = NULL;
	snapshot->tbl_copy = NULL;

	down_write(&table->translation_lock);

	if (!ssdfs_blk2off_table_dirtied(table, peb_index)) {
		err = -ENODATA;
		SSDFS_DBG("table isn't dirty for peb_index %u\n",
			  peb_index);
		goto finish_snapshoting;
	}

	capacity = ssdfs_dynamic_array_items_count(&table->lblk2off);
	if (capacity == 0) {
		err = -ERANGE;
		SSDFS_ERR("invalid capacity %u\n", capacity);
		goto finish_snapshoting;
	}

	bmap_bytes = ssdfs_blk2off_table_bmap_bytes(table->lbmap.bits_count);
	snapshot->bmap_copy = ssdfs_blk2off_kvzalloc(bmap_bytes, GFP_KERNEL);
	if (!snapshot->bmap_copy) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocated bytes %zu\n",
			  bmap_bytes);
		goto finish_snapshoting;
	}

	tbl_bytes = ssdfs_dynamic_array_allocated_bytes(&table->lblk2off);
	if (tbl_bytes == 0) {
		err = -ERANGE;
		SSDFS_ERR("invalid bytes count %zu\n", tbl_bytes);
		goto finish_snapshoting;
	}

	snapshot->tbl_copy = ssdfs_blk2off_kvzalloc(tbl_bytes, GFP_KERNEL);
	if (!snapshot->tbl_copy) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocated bytes %zu\n",
			  tbl_bytes);
		goto finish_snapshoting;
	}

	SSDFS_DBG("capacity %u, bits_count %u, "
		  "bmap_bytes %zu, tbl_bytes %zu, "
		  "last_allocated_blk %u\n",
		  capacity, table->lbmap.bits_count,
		  bmap_bytes, tbl_bytes,
		  table->last_allocated_blk);

	SSDFS_DBG("init_bmap %lx, state_bmap %lx, bmap_copy %lx\n",
		  *table->lbmap.array[SSDFS_LBMAP_INIT_INDEX],
		  *table->lbmap.array[SSDFS_LBMAP_STATE_INDEX],
		  *snapshot->bmap_copy);

	bitmap_or(snapshot->bmap_copy,
		   snapshot->bmap_copy,
		   table->lbmap.array[SSDFS_LBMAP_MODIFICATION_INDEX],
		   table->lbmap.bits_count);

	SSDFS_DBG("modification_bmap %lx, bmap_copy %lx\n",
		  *table->lbmap.array[SSDFS_LBMAP_MODIFICATION_INDEX],
		  *snapshot->bmap_copy);

	err = ssdfs_dynamic_array_copy_content(&table->lblk2off,
						snapshot->tbl_copy,
						tbl_bytes);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy position array: "
			  "err %d\n", err);
		goto finish_snapshoting;
	}

	snapshot->capacity = capacity;

	snapshot->used_logical_blks = table->used_logical_blks;
	snapshot->free_logical_blks = table->free_logical_blks;
	snapshot->last_allocated_blk = table->last_allocated_blk;

	snapshot->peb_index = peb_index;
	snapshot->start_sequence_id = SSDFS_INVALID_FRAG_ID;

	sequence = table->peb[peb_index].sequence;
	err = ssdfs_sequence_array_change_all_states(sequence,
					SSDFS_SEQUENCE_ITEM_DIRTY_TAG,
					SSDFS_SEQUENCE_ITEM_UNDER_COMMIT_TAG,
					ssdfs_change_fragment_state,
					SSDFS_BLK2OFF_FRAG_DIRTY,
					SSDFS_BLK2OFF_FRAG_UNDER_COMMIT,
					&dirty_fragments);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change from dirty to under_commit: "
			  "err %d\n", err);
		goto finish_snapshoting;
	} else if (dirty_fragments >= U16_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid dirty_fragments %lu\n",
			  dirty_fragments);
		goto finish_snapshoting;
	}

#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
	snapshot->start_sequence_id = 0;
	snapshot->dirty_fragments = dirty_fragments;
	snapshot->fragments_count =
			atomic_read(&table->peb[peb_index].fragment_count);
#else
	snapshot->dirty_fragments = dirty_fragments;

	last_sequence_id =
		ssdfs_sequence_array_last_id(table->peb[peb_index].sequence);
	err = ssdfs_calculate_start_sequence_id(last_sequence_id,
						snapshot->dirty_fragments,
						&snapshot->start_sequence_id);
	if (unlikely(err)) {
		SSDFS_ERR("fail to calculate start sequence ID: "
			  "err %d\n", err);
		goto finish_snapshoting;
	}

	snapshot->fragments_count =
			atomic_read(&table->peb[peb_index].fragment_count);
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

	SSDFS_DBG("start_sequence_id %u, dirty_fragments %u\n",
		  snapshot->start_sequence_id,
		  snapshot->dirty_fragments);

	if (snapshot->dirty_fragments == 0) {
		err = -ERANGE;
		SSDFS_ERR("PEB hasn't dirty fragments\n");
		goto finish_snapshoting;
	}

	snapshot->cno = ssdfs_current_cno(table->fsi->sb);

	pot_table = &table->peb[peb_index];
	state = atomic_cmpxchg(&pot_table->state,
				SSDFS_BLK2OFF_TABLE_DIRTY_PARTIAL_INIT,
				SSDFS_BLK2OFF_TABLE_PARTIAL_INIT);
	if (state != SSDFS_BLK2OFF_TABLE_DIRTY_PARTIAL_INIT) {
		state = atomic_cmpxchg(&pot_table->state,
					SSDFS_BLK2OFF_TABLE_DIRTY,
					SSDFS_BLK2OFF_TABLE_COMPLETE_INIT);
		if (state != SSDFS_BLK2OFF_TABLE_DIRTY) {
			err = -ERANGE;
			SSDFS_ERR("table isn't dirty: "
				  "state %#x\n",
				  state);
			goto finish_snapshoting;
		}
	}

finish_snapshoting:
	up_write(&table->translation_lock);

	if (err) {
		if (snapshot->bmap_copy) {
			ssdfs_blk2off_kvfree(snapshot->bmap_copy);
			snapshot->bmap_copy = NULL;
		}

		if (snapshot->tbl_copy) {
			ssdfs_blk2off_kvfree(snapshot->tbl_copy);
			snapshot->tbl_copy = NULL;
		}
	}

	SSDFS_DBG("finished\n");

	return err;
}

/*
 * ssdfs_blk2off_table_free_snapshot() - free snapshot's resources
 * @sp: pointer on tabls's snapshot
 */
void ssdfs_blk2off_table_free_snapshot(struct ssdfs_blk2off_table_snapshot *sp)
{
	if (!sp)
		return;

	if (sp->bmap_copy) {
		ssdfs_blk2off_kvfree(sp->bmap_copy);
		sp->bmap_copy = NULL;
	}

	if (sp->tbl_copy) {
		ssdfs_blk2off_kvfree(sp->tbl_copy);
		sp->tbl_copy = NULL;
	}

	memset(sp, 0, sizeof(struct ssdfs_blk2off_table_snapshot));
}

/*
 * ssdfs_find_changed_area() - find changed area
 * @sp: table's snapshot
 * @start: starting bit for search
 * @found: found range of set bits
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 * %-ENODATA    - nothing was found.
 */
static inline
int ssdfs_find_changed_area(struct ssdfs_blk2off_table_snapshot *sp,
			    unsigned long start,
			    struct ssdfs_blk2off_range *found)
{
	unsigned long modified_bits;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sp || !found);
#endif /* CONFIG_SSDFS_DEBUG */

	modified_bits = bitmap_weight(sp->bmap_copy, sp->capacity);

	SSDFS_DBG("snapshot %p, peb_index %u, start %lu, found %p\n",
		  sp, sp->peb_index, start, found);
	SSDFS_DBG("modified_bits %lu, capacity %u\n",
		  modified_bits, sp->capacity);

	start = find_next_bit(sp->bmap_copy, sp->capacity, start);
	if (start >= sp->capacity) {
		SSDFS_DBG("nothing found\n");
		return -ENODATA;
	}

	found->start_lblk = (u16)start;

	start = find_next_zero_bit(sp->bmap_copy, sp->capacity, start);
	start = (unsigned long)min_t(u16, (u16)start, sp->capacity);

	found->len = (u16)(start - found->start_lblk);

	SSDFS_DBG("found_start %lu, found_end %lu, len %lu\n",
		  (unsigned long)found->start_lblk,
		  start,
		  (unsigned long)found->len);

	if (found->len == 0) {
		SSDFS_ERR("found empty extent\n");
		return -ERANGE;
	}

	return 0;
}

/*
 * struct ssdfs_blk2off_found_range - found range
 * @range: range descriptor
 * @start_id: starting offset ID
 * @state: state of logical blocks in extent (used, free and so on)
 */
struct ssdfs_blk2off_found_range {
	struct ssdfs_blk2off_range range;
	u16 start_id;
	u8 state;
};

/*
 * ssdfs_translation_extent_init() - init translation extent
 * @found: range of changed logical blocks
 * @sequence_id: sequence ID of extent
 * @extent: pointer on initialized extent [out]
 */
static inline
void ssdfs_translation_extent_init(struct ssdfs_blk2off_found_range *found,
				   u8 sequence_id,
				   struct ssdfs_translation_extent *extent)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!found || !extent);
	BUG_ON(found->state <= SSDFS_LOGICAL_BLK_UNKNOWN_STATE ||
		found->state >= SSDFS_LOGICAL_BLK_STATE_MAX);

	SSDFS_DBG("start %u, len %u, id %u, sequence_id %u, state %#x\n",
		  found->range.start_lblk, found->range.len,
		  found->start_id, sequence_id, found->state);
#endif /* CONFIG_SSDFS_DEBUG */

	extent->logical_blk = cpu_to_le16(found->range.start_lblk);
	extent->offset_id = cpu_to_le16(found->start_id);
	extent->len = cpu_to_le16(found->range.len);
	extent->sequence_id = sequence_id;
	extent->state = found->state;
}

/*
 * can_translation_extent_be_merged() - check opportunity to merge extents
 * @extent: extent for checking
 * @found: range of changed logical blocks
 */
static inline
bool can_translation_extent_be_merged(struct ssdfs_translation_extent *extent,
				      struct ssdfs_blk2off_found_range *found)
{
	u16 logical_blk;
	u16 offset_id;
	u16 len;
	u16 found_blk;
	u16 found_len;
	u16 found_id;
	u8 found_state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extent || !found);
	BUG_ON(found->start_id == SSDFS_BLK2OFF_TABLE_INVALID_ID);
	BUG_ON(found->state <= SSDFS_LOGICAL_BLK_UNKNOWN_STATE ||
		found->state >= SSDFS_LOGICAL_BLK_STATE_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	logical_blk = le16_to_cpu(extent->logical_blk);
	offset_id = le16_to_cpu(extent->offset_id);
	len = le16_to_cpu(extent->len);

	found_blk = found->range.start_lblk;
	found_len = found->range.len;
	found_id = found->start_id;
	found_state = found->state;

	SSDFS_DBG("EXTENT: logical_blk %u, offset_id %u, len %u, "
		  "sequence_id %u, state %#x; "
		  "FOUND: logical_blk %u, start_id %u, "
		  "len %u, state %#x\n",
		  logical_blk, offset_id, len,
		  extent->sequence_id, extent->state,
		  found->range.start_lblk, found->start_id,
		  found->range.len, found->state);

	if (extent->state != found->state)
		return false;

	if (found_id == offset_id) {
		SSDFS_ERR("start_id %u == offset_id %u\n",
			  found_id, offset_id);
		return false;
	} else if (found_id > offset_id &&
			(offset_id + len) == found_id) {
		if ((logical_blk + len) == found_blk)
			return true;
		else if ((found_blk + found_len) == logical_blk)
			return true;
	} else if (found_id < offset_id &&
			(found_id + found_len) == offset_id) {
		if ((logical_blk + len) == found_blk)
			return true;
		else if ((found_blk + found_len) == logical_blk)
			return true;
	}

	return false;
}

/*
 * ssdfs_merge_translation_extent() - merge translation extents
 * @extent: extent for checking
 * @found: range of changed logical blocks
 */
static inline
int ssdfs_merge_translation_extent(struct ssdfs_translation_extent *extent,
				   struct ssdfs_blk2off_found_range *found)
{
	u16 logical_blk;
	u16 offset_id;
	u16 len;
	u16 found_blk;
	u16 found_len;
	u16 found_id;
	u8 found_state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extent || !found);
	BUG_ON(found->start_id == SSDFS_BLK2OFF_TABLE_INVALID_ID);
	BUG_ON(found->state <= SSDFS_LOGICAL_BLK_UNKNOWN_STATE ||
		found->state >= SSDFS_LOGICAL_BLK_STATE_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	logical_blk = le16_to_cpu(extent->logical_blk);
	offset_id = le16_to_cpu(extent->offset_id);
	len = le16_to_cpu(extent->len);

	found_blk = found->range.start_lblk;
	found_len = found->range.len;
	found_id = found->start_id;
	found_state = found->state;

	SSDFS_DBG("EXTENT: logical_blk %u, offset_id %u, len %u, "
		  "sequence_id %u, state %#x; "
		  "FOUND: logical_blk %u, start_id %u, "
		  "len %u, state %#x\n",
		  logical_blk, offset_id, len,
		  extent->sequence_id, extent->state,
		  found_blk, found_id, found_len,
		  found_state);

	if (extent->state != found_state) {
		SSDFS_ERR("extent->state %#x != state %#x\n",
			  extent->state, found_state);
		return -EINVAL;
	}

	if (found_id == offset_id) {
		SSDFS_ERR("start_id %u == offset_id %u\n",
			  found_id, offset_id);
		return -ERANGE;
	}

	if (found_id > offset_id &&
			(offset_id + len) == found_id) {
		if ((logical_blk + len) == found_blk) {
			extent->len = cpu_to_le16(len + found_len);
		} else if ((found_blk + found_len) == logical_blk) {
			extent->logical_blk = cpu_to_le16(found_blk);
			extent->len = cpu_to_le16(len + found_len);
		}
	} else if (found_id < offset_id &&
			(found_id + found_len) == offset_id) {
		if ((logical_blk + len) == found_blk) {
			extent->offset_id = cpu_to_le16(found_id);
			extent->len = cpu_to_le16(len + found_len);
		} else if ((found_blk + found_len) == logical_blk) {
			extent->logical_blk = cpu_to_le16(found_blk);
			extent->offset_id = cpu_to_le16(found_id);
			extent->len = cpu_to_le16(len + found_len);
		}
	} else {
		SSDFS_ERR("fail to merge the translation extent\n");
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_insert_translation_extent() - insert translation extent into the queue
 * @found: range of changed logical blocks
 * @array: extents array [in|out]
 * @capacity: capacity of extents array
 * @extent_count: pointer on extents count value [out]
 */
static inline
int ssdfs_insert_translation_extent(struct ssdfs_blk2off_found_range *found,
				    struct ssdfs_translation_extent *array,
				    u16 capacity, u16 *extent_count)
{
	struct ssdfs_translation_extent *extent;
	size_t extent_size = sizeof(struct ssdfs_translation_extent);
	size_t array_bytes = extent_size * capacity;
	u16 logical_blk;
	u16 offset_id;
	u16 len;
	int i, j;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!found || !extent_count);
	BUG_ON(found->state <= SSDFS_LOGICAL_BLK_UNKNOWN_STATE ||
		found->state >= SSDFS_LOGICAL_BLK_STATE_MAX);

	SSDFS_DBG("start_id %u, state %#x, extent_count %u\n",
		  found->start_id, found->state, *extent_count);
#endif /* CONFIG_SSDFS_DEBUG */

	BUG_ON(*extent_count >= capacity);

	if (found->start_id == SSDFS_BLK2OFF_TABLE_INVALID_ID) {
		extent = &array[*extent_count];
		ssdfs_translation_extent_init(found, *extent_count, extent);
		(*extent_count)++;

		return 0;
	}

	for (i = 0; i < *extent_count; i++) {
		extent = &array[i];

		logical_blk = le16_to_cpu(extent->logical_blk);
		offset_id = le16_to_cpu(extent->offset_id);
		len = le16_to_cpu(extent->len);

		if (offset_id >= SSDFS_BLK2OFF_TABLE_INVALID_ID)
			continue;

		if (found->start_id == offset_id) {
			SSDFS_ERR("start_id %u == offset_id %u\n",
				  found->start_id, offset_id);
			return -ERANGE;
		} else if (found->start_id > offset_id &&
			   can_translation_extent_be_merged(extent, found)) {
			err = ssdfs_merge_translation_extent(extent, found);
			if (unlikely(err)) {
				SSDFS_ERR("fail to merge extent: "
					  "err %d\n", err);
				return err;
			} else
				return 0;
		} else if (found->start_id < offset_id) {
			if (can_translation_extent_be_merged(extent, found)) {
				err = ssdfs_merge_translation_extent(extent,
								     found);
				if (unlikely(err)) {
					SSDFS_ERR("fail to merge extent: "
						  "err %d\n", err);
					return err;
				} else
					return 0;
			} else {
				i++;
				SSDFS_DBG("unable to merge: index %d\n", i);
				break;
			}
		}
	}

	if (i < *extent_count) {
#ifdef CONFIG_SSDFS_DEBUG
		if (((i + 1) + (*extent_count - i)) > capacity) {
			SSDFS_WARN("value is out capacity\n");
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		SSDFS_DBG("extent_count %u, index %d, extent_size %zu\n",
			  *extent_count, i, extent_size);

		err = ssdfs_memmove(array, (i + 1) * extent_size, array_bytes,
				    array, i * extent_size, array_bytes,
				    (*extent_count - i) * extent_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move: err %d\n", err);
			return err;
		}

		for (j = i + 1; j <= *extent_count; j++) {
			extent = &array[j];
			extent->sequence_id = j;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("extent_count %u, index %d, extent_size %zu\n",
		  *extent_count, i, extent_size);
#endif /* CONFIG_SSDFS_DEBUG */

	extent = &array[i];
	ssdfs_translation_extent_init(found, i, extent);

	(*extent_count)++;

#ifdef CONFIG_SSDFS_DEBUG
	for (i = 0; i < *extent_count; i++) {
		extent = &array[i];

		SSDFS_DBG("index %d, logical_blk %u, offset_id %u, "
			  "len %u, sequence_id %u, state %u\n",
			  i,
			  le16_to_cpu(extent->logical_blk),
			  le16_to_cpu(extent->offset_id),
			  le16_to_cpu(extent->len),
			  extent->sequence_id,
			  extent->state);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

static inline
bool is_found_logical_block_free(struct ssdfs_blk2off_table_snapshot *sp,
				 u16 blk)
{
	struct ssdfs_offset_position *pos;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sp);

	SSDFS_DBG("blk %u\n", blk);
#endif /* CONFIG_SSDFS_DEBUG */

	pos = &sp->tbl_copy[blk];

	return pos->id == SSDFS_BLK2OFF_TABLE_INVALID_ID &&
		pos->offset_index >= U16_MAX;
}

static inline
bool is_found_extent_ended(struct ssdfs_blk2off_table_snapshot *sp,
			   u16 blk,
			   struct ssdfs_blk2off_found_range *found)
{
	struct ssdfs_offset_position *pos;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sp || !found);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk %u\n", blk);

	pos = &sp->tbl_copy[blk];

	if (pos->peb_index != sp->peb_index) {
		/* changes of another PEB */
		return true;
	} else if (pos->id != SSDFS_BLK2OFF_TABLE_INVALID_ID) {
		if (found->start_id == SSDFS_BLK2OFF_TABLE_INVALID_ID)
			found->start_id = pos->id;
		else if ((found->start_id + found->range.len) != pos->id)
			return true;
	} else if (pos->id == SSDFS_BLK2OFF_TABLE_INVALID_ID &&
		   found->state != SSDFS_LOGICAL_BLK_FREE) {
		if (found->range.start_lblk != U16_MAX) {
			/* state is changed */
			return true;
		}
	}

	return false;
}

/*
 * ssdfs_blk2off_table_extract_extents() - extract changed extents
 * @sp: table's snapshot
 * @array: extents array [in|out]
 * @capacity: capacity of extents array
 * @extent_count: pointer on extents count value [out]
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 */
int ssdfs_blk2off_table_extract_extents(struct ssdfs_blk2off_table_snapshot *sp,
					struct ssdfs_translation_extent *array,
					u16 capacity, u16 *extent_count)
{
	unsigned long start = 0;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sp || !array || !extent_count);
	BUG_ON(capacity == 0);

	SSDFS_DBG("snapshot %p, peb_index %u, extents %p, "
		  "capacity %u, extent_count %p\n",
		  sp, sp->peb_index, array,
		  capacity, extent_count);
#endif /* CONFIG_SSDFS_DEBUG */

	*extent_count = 0;

	do {
		struct ssdfs_blk2off_range changed_area = {0};
		struct ssdfs_blk2off_found_range found = {
			.range.start_lblk = U16_MAX,
			.range.len = 0,
			.start_id = SSDFS_BLK2OFF_TABLE_INVALID_ID,
			.state = SSDFS_LOGICAL_BLK_UNKNOWN_STATE,
		};
		struct ssdfs_offset_position *pos;

		err = ssdfs_find_changed_area(sp, start, &changed_area);
		if (err == -ENODATA) {
			err = 0;
			SSDFS_DBG("nothing found\n");
			goto finish_extract_extents;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find changed area: err %d\n",
				  err);
			return err;
		}

		SSDFS_DBG("changed area: start %u, len %u\n",
			  changed_area.start_lblk, changed_area.len);

		for (i = 0; i < changed_area.len; i++) {
			u16 blk = changed_area.start_lblk + i;
			bool is_extent_ended = false;

			pos = &sp->tbl_copy[blk];

			SSDFS_DBG("cno %llx, id %u, peb_index %u, "
				  "sequence_id %u, offset_index %u\n",
				  pos->cno, pos->id, pos->peb_index,
				  pos->sequence_id, pos->offset_index);

			if (pos->peb_index == U16_MAX) {
				SSDFS_WARN("invalid peb_index: "
					   "logical_blk %u\n",
					   blk);
				return -ERANGE;
			}

			if (is_found_logical_block_free(sp, blk)) {
				/* free block */

				switch (found.state) {
				case SSDFS_LOGICAL_BLK_UNKNOWN_STATE:
					found.range.start_lblk = blk;
					found.range.len = 1;
					found.state = SSDFS_LOGICAL_BLK_FREE;
					break;

				case SSDFS_LOGICAL_BLK_FREE:
					found.range.len++;
					break;

				case SSDFS_LOGICAL_BLK_USED:
					is_extent_ended = true;
					break;

				default:
					SSDFS_ERR("unexpected blk state %#x\n",
						  found.state);
					return -ERANGE;
				}

				SSDFS_DBG("free block: start_lblk %u, "
					  "len %u, state %#x, "
					  "is_extent_ended %#x\n",
					  found.range.start_lblk,
					  found.range.len,
					  found.state,
					  is_extent_ended);
			} else {
				/* used block */

				switch (found.state) {
				case SSDFS_LOGICAL_BLK_UNKNOWN_STATE:
					found.range.start_lblk = blk;
					found.range.len = 1;
					found.start_id = pos->id;
					found.state = SSDFS_LOGICAL_BLK_USED;
					break;

				case SSDFS_LOGICAL_BLK_USED:
					is_extent_ended =
						is_found_extent_ended(sp, blk,
									&found);
					if (!is_extent_ended)
						found.range.len++;
					break;

				case SSDFS_LOGICAL_BLK_FREE:
					is_extent_ended = true;
					break;

				default:
					SSDFS_ERR("unexpected blk state %#x\n",
						  found.state);
					return -ERANGE;
				}

				SSDFS_DBG("used block: start_lblk %u, "
					  "len %u, state %#x, "
					  "is_extent_ended %#x\n",
					  found.range.start_lblk,
					  found.range.len,
					  found.state,
					  is_extent_ended);
			}

			if (is_extent_ended) {
				if (found.range.start_lblk == U16_MAX) {
					SSDFS_ERR("invalid start_lblk %u\n",
						  found.range.start_lblk);
					return -ERANGE;
				}

				err = ssdfs_insert_translation_extent(&found,
								array,
								capacity,
								extent_count);
				if (unlikely(err)) {
					SSDFS_ERR("fail to insert extent: "
						  "start_id %u, state %#x, "
						  "err %d\n",
						  found.start_id, found.state,
						  err);
					return err;
				}

				pos = &sp->tbl_copy[blk];

				if (pos->id == SSDFS_BLK2OFF_TABLE_INVALID_ID)
					found.state = SSDFS_LOGICAL_BLK_FREE;
				else
					found.state = SSDFS_LOGICAL_BLK_USED;

				found.range.start_lblk = blk;
				found.range.len = 1;
				found.start_id = pos->id;
			}
		}

		if (found.range.start_lblk != U16_MAX) {
			err = ssdfs_insert_translation_extent(&found,
								array,
								capacity,
								extent_count);
			if (unlikely(err)) {
				SSDFS_ERR("fail to insert extent: "
					  "start_id %u, state %#x, "
					  "err %d\n",
					  found.start_id, found.state, err);
				return err;
			}

			start = found.range.start_lblk + found.range.len;

			found.range.start_lblk = U16_MAX;
			found.range.len = 0;
			found.state = SSDFS_LOGICAL_BLK_UNKNOWN_STATE;
		} else
			start = changed_area.start_lblk + changed_area.len;
	} while (start < sp->capacity);

finish_extract_extents:
	SSDFS_DBG("extents_count %u\n", *extent_count);

	if (*extent_count == 0) {
		err = -ERANGE;
		SSDFS_ERR("invalid state of change bitmap\n");
		return err;
	}

	return 0;
}

/*
 * ssdfs_blk2off_table_prepare_for_commit() - prepare fragment for commit
 * @table: pointer on table object
 * @peb_index: PEB's index
 * @sequence_id: fragment's sequence ID
 * @offset_table_off: pointer on current offset to offset table header [in|out]
 * @sp: pointer on snapshot
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 */
int
ssdfs_blk2off_table_prepare_for_commit(struct ssdfs_blk2off_table *table,
				       u16 peb_index, u16 sequence_id,
				       u32 *offset_table_off,
				       struct ssdfs_blk2off_table_snapshot *sp)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_phys_offset_table_array *pot_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment;
	void *ptr;
	u16 id_count;
	u32 byte_size;
	u16 flags = 0;
	int last_sequence_id;
	bool has_next_fragment = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !sp || !table->fsi || !offset_table_off);
	BUG_ON(peb_index >= table->pebs_count);
	BUG_ON(peb_index != sp->peb_index);

	SSDFS_DBG("table %p, peb_index %u, sequence_id %u, "
		  "offset_table_off %p, sp %p\n",
		  table, peb_index, sequence_id,
		  offset_table_off, sp);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = table->fsi;

	down_read(&table->translation_lock);

	pot_table = &table->peb[peb_index];

	sequence = pot_table->sequence;
	ptr = ssdfs_sequence_array_get_item(sequence, sequence_id);
	if (IS_ERR_OR_NULL(ptr)) {
		err = (ptr == NULL ? -ENOENT : PTR_ERR(ptr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  sequence_id, err);
		goto finish_prepare_for_commit;
	}
	fragment = (struct ssdfs_phys_offset_table_fragment *)ptr;

	if (atomic_read(&fragment->state) != SSDFS_BLK2OFF_FRAG_UNDER_COMMIT) {
		err = -ERANGE;
		SSDFS_ERR("fragment isn't under commit: "
			  "state %#x\n",
			  atomic_read(&fragment->state));
		goto finish_prepare_for_commit;
	}

	down_write(&fragment->lock);

	fragment->hdr->magic = cpu_to_le32(SSDFS_PHYS_OFF_TABLE_MAGIC);
	fragment->hdr->checksum = 0;

	fragment->hdr->start_id = cpu_to_le16(fragment->start_id);
	id_count = (u16)atomic_read(&fragment->id_count);
	fragment->hdr->id_count = cpu_to_le16(id_count);
	byte_size = sizeof(struct ssdfs_phys_offset_table_header);
	byte_size += id_count * sizeof(struct ssdfs_phys_offset_descriptor);
	fragment->hdr->byte_size = cpu_to_le32(byte_size);

	SSDFS_DBG("fragment: start_id %u, id_count %u\n",
		  le16_to_cpu(fragment->hdr->start_id),
		  le16_to_cpu(fragment->hdr->id_count));

	fragment->hdr->peb_index = cpu_to_le16(peb_index);
	fragment->hdr->sequence_id = cpu_to_le16(fragment->sequence_id);
	fragment->hdr->type = cpu_to_le16(table->type);

	SSDFS_DBG("sequence_id %u, start_sequence_id %u, "
		  "dirty_fragments %u, fragment->sequence_id %u\n",
		  sequence_id, sp->start_sequence_id,
		  sp->dirty_fragments,
		  fragment->sequence_id);

	last_sequence_id = ssdfs_sequence_array_last_id(pot_table->sequence);
	has_next_fragment = sequence_id != last_sequence_id;

	flags |= SSDFS_OFF_TABLE_HAS_CSUM;
	if (has_next_fragment)
		flags |= SSDFS_OFF_TABLE_HAS_NEXT_FRAGMENT;

	switch (fsi->metadata_options.blk2off_tbl.compression) {
	case SSDFS_BLK2OFF_TBL_ZLIB_COMPR_TYPE:
	case SSDFS_BLK2OFF_TBL_LZO_COMPR_TYPE:
		flags |= SSDFS_BLK_DESC_TBL_COMPRESSED;
		break;
	default:
		/* do nothing */
		break;
	}

	fragment->hdr->flags = cpu_to_le16(flags);

	fragment->hdr->used_logical_blks = cpu_to_le16(sp->used_logical_blks);
	fragment->hdr->free_logical_blks = cpu_to_le16(sp->free_logical_blks);
	fragment->hdr->last_allocated_blk = cpu_to_le16(sp->last_allocated_blk);

	BUG_ON(byte_size >= U16_MAX);

	*offset_table_off += byte_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("offset_table_off %u\n", *offset_table_off);

	BUG_ON(*offset_table_off > U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if (has_next_fragment) {
		fragment->hdr->next_fragment_off =
				cpu_to_le16((u16)*offset_table_off);
	} else {
		fragment->hdr->next_fragment_off =
				cpu_to_le16(U16_MAX);
	}

	fragment->hdr->checksum = ssdfs_crc32_le(fragment->hdr, byte_size);

	up_write(&fragment->lock);

finish_prepare_for_commit:
	up_read(&table->translation_lock);

	return err;
}

/*
 * ssdfs_blk2off_table_forget_snapshot() - undirty PEB's table
 * @table: pointer on table object
 * @sp: pointer on snapshot
 * @array: extents array
 * @extent_count: count of extents in array
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal logic error.
 */
int
ssdfs_blk2off_table_forget_snapshot(struct ssdfs_blk2off_table *table,
				    struct ssdfs_blk2off_table_snapshot *sp,
				    struct ssdfs_translation_extent *array,
				    u16 extent_count)
{
	struct ssdfs_phys_offset_table_array *pot_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_offset_position *pos;
	u16 last_sequence_id;
	unsigned long commited_fragments = 0;
	int i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !sp || !array);
	BUG_ON(sp->peb_index >= table->pebs_count);
	BUG_ON(extent_count == 0);

	SSDFS_DBG("table %p, peb_index %u, sp %p, "
		  "extents %p, extents_count %u\n",
		  table, sp->peb_index, sp,
		  array, extent_count);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&table->translation_lock);

	pot_table = &table->peb[sp->peb_index];
	last_sequence_id = ssdfs_sequence_array_last_id(pot_table->sequence);

	if (sp->dirty_fragments == 0) {
		err = -EINVAL;
		SSDFS_ERR("dirty_fragments == 0\n");
		goto finish_forget_snapshot;
	}

	sequence = table->peb[sp->peb_index].sequence;
	err = ssdfs_sequence_array_change_all_states(sequence,
					SSDFS_SEQUENCE_ITEM_UNDER_COMMIT_TAG,
					SSDFS_SEQUENCE_ITEM_COMMITED_TAG,
					ssdfs_change_fragment_state,
					SSDFS_BLK2OFF_FRAG_UNDER_COMMIT,
					SSDFS_BLK2OFF_FRAG_COMMITED,
					&commited_fragments);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set fragments as commited: "
			  "err %d\n", err);
		goto finish_forget_snapshot;
	}

	if (sp->dirty_fragments != commited_fragments) {
		err = -ERANGE;
		SSDFS_ERR("dirty_fragments %u != commited_fragments %lu\n",
			  sp->dirty_fragments, commited_fragments);
		goto finish_forget_snapshot;
	}

	for (i = 0; i < extent_count; i++) {
		u16 start_blk = le16_to_cpu(array[i].logical_blk);
		u16 len = le16_to_cpu(array[i].len);

		for (j = 0; j < len; j++) {
			u16 blk = start_blk + j;
			u64 cno1, cno2;
			void *kaddr;

			kaddr = ssdfs_dynamic_array_get_locked(&table->lblk2off,
								blk);
			if (IS_ERR_OR_NULL(kaddr)) {
				err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
				SSDFS_ERR("fail to get logical block: "
					  "blk %u, err %d\n",
					  blk, err);
				goto finish_forget_snapshot;
			}

			pos = SSDFS_OFF_POS(kaddr);
			cno1 = pos->cno;
			cno2 = sp->tbl_copy[blk].cno;

			err = ssdfs_dynamic_array_release(&table->lblk2off,
							  blk, pos);
			if (unlikely(err)) {
				SSDFS_ERR("fail to release: "
					  "blk %u, err %d\n",
					  blk, err);
				goto finish_forget_snapshot;
			}

			if (cno1 < cno2) {
				SSDFS_WARN("cno1 %llu < cno2 %llu\n",
					   cno1, cno2);
			} else if (cno1 > cno2)
				continue;

			/*
			 * Don't clear information about free blocks
			 * in the modification bitmap. Otherwise,
			 * this information will be lost during
			 * the PEBs migration.
			 */
			if (array[i].state != SSDFS_LOGICAL_BLK_FREE) {
				err =
				   ssdfs_blk2off_table_bmap_clear(&table->lbmap,
					   SSDFS_LBMAP_MODIFICATION_INDEX, blk);
				if (unlikely(err)) {
					SSDFS_ERR("fail to clear bitmap: "
						  "blk %u, err %d\n",
						  blk, err);
					goto finish_forget_snapshot;
				}
			}

			err = ssdfs_blk2off_table_bmap_set(&table->lbmap,
						SSDFS_LBMAP_INIT_INDEX, blk);
			if (unlikely(err)) {
				SSDFS_ERR("fail to set bitmap: "
					  "blk %u, err %d\n",
					  blk, err);
				goto finish_forget_snapshot;
			}
		}
	}

finish_forget_snapshot:
	up_write(&table->translation_lock);

	SSDFS_DBG("finished\n");

	return err;
}

/*
 * ssdfs_peb_store_offsets_table_header() - store offsets table header
 * @pebi: pointer on PEB object
 * @hdr: table header
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
 *
 * This function tries to store table header into log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to find memory page.
 */
int ssdfs_peb_store_offsets_table_header(struct ssdfs_peb_info *pebi,
					 struct ssdfs_blk2off_table_header *hdr,
					 pgoff_t *cur_page,
					 u32 *write_offset)
{
	size_t hdr_sz = sizeof(struct ssdfs_blk2off_table_header);
	struct page *page;
	u32 page_off, cur_offset;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!hdr || !cur_page || !write_offset);

	SSDFS_DBG("peb %llu, current_log.start_page %u, "
		  "hdr %p, cur_page %lu, write_offset %u\n",
		  pebi->peb_id,
		  pebi->current_log.start_page,
		  hdr, *cur_page, *write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	page_off = *write_offset % PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON((PAGE_SIZE - page_off) < hdr_sz);
#endif /* CONFIG_SSDFS_DEBUG */

	page = ssdfs_page_array_grab_page(&pebi->cache, *cur_page);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get cache page: index %lu\n",
			  *cur_page);
		return -ENOMEM;
	}

	err = ssdfs_memcpy_to_page(page, page_off, PAGE_SIZE,
				   hdr, 0, hdr_sz,
				   hdr_sz);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		goto finish_copy;
	}

	ssdfs_set_page_private(page, 0);
	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(&pebi->cache, *cur_page);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page %lu as dirty: err %d\n",
			  *cur_page, err);
	}

finish_copy:
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));

	if (unlikely(err))
		return err;

	*write_offset += hdr_sz;

	cur_offset = (*cur_page << PAGE_SHIFT) + page_off + hdr_sz;
	*cur_page = cur_offset >> PAGE_SHIFT;

	return 0;
}

/*
 * ssdfs_peb_store_offsets_table_extents() - store translation extents
 * @pebi: pointer on PEB object
 * @array: translation extents array
 * @extent_count: count of extents in the array
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
 *
 * This function tries to store translation extents into log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to find memory page.
 */
int
ssdfs_peb_store_offsets_table_extents(struct ssdfs_peb_info *pebi,
				      struct ssdfs_translation_extent *array,
				      u16 extent_count,
				      pgoff_t *cur_page,
				      u32 *write_offset)
{
	struct page *page;
	size_t extent_size = sizeof(struct ssdfs_translation_extent);
	size_t array_size = extent_size * extent_count;
	u32 rest_bytes, written_bytes = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!array || !cur_page || !write_offset);
	BUG_ON(extent_count == 0 || extent_count == U16_MAX);

	SSDFS_DBG("peb %llu, current_log.start_page %u, "
		  "array %p, extent_count %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->peb_id,
		  pebi->current_log.start_page,
		  array, extent_count,
		  *cur_page, *write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	rest_bytes = extent_count * extent_size;

	while (rest_bytes > 0) {
		u32 bytes;
		u32 cur_off = *write_offset % PAGE_SIZE;
		u32 new_off;

		bytes = min_t(u32, rest_bytes, PAGE_SIZE - cur_off);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(bytes < extent_size);
		BUG_ON(written_bytes > (extent_count * extent_size));
#endif /* CONFIG_SSDFS_DEBUG */

		page = ssdfs_page_array_grab_page(&pebi->cache,
						  *cur_page);
		if (IS_ERR_OR_NULL(page)) {
			SSDFS_ERR("fail to get cache page: index %lu\n",
				  *cur_page);
			return -ENOMEM;
		}

		SSDFS_DBG("cur_off %u, written_bytes %u, bytes %u\n",
			  cur_off, written_bytes, bytes);

		err = ssdfs_memcpy_to_page(page, cur_off, PAGE_SIZE,
					   array, written_bytes, array_size,
					   bytes);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n", err);
			goto finish_copy;
		}

		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);

		err = ssdfs_page_array_set_page_dirty(&pebi->cache,
						      *cur_page);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu as dirty: err %d\n",
				  *cur_page, err);
		}

finish_copy:
		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));

		if (unlikely(err))
			return err;

		*write_offset += bytes;

		new_off = (*cur_page << PAGE_SHIFT) + cur_off + bytes;
		*cur_page = new_off >> PAGE_SHIFT;

		rest_bytes -= bytes;
		written_bytes += bytes;
	};

	return 0;
}

/*
 * ssdfs_peb_store_offsets_table_fragment() - store fragment of offsets table
 * @pebi: pointer on PEB object
 * @table: pointer on translation table object
 * @peb_index: PEB's index
 * @sequence_id: sequence ID of fragment
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
 *
 * This function tries to store table's fragment into log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to find memory page.
 */
int ssdfs_peb_store_offsets_table_fragment(struct ssdfs_peb_info *pebi,
					   struct ssdfs_blk2off_table *table,
					   u16 peb_index, u16 sequence_id,
					   pgoff_t *cur_page,
					   u32 *write_offset)
{
	struct ssdfs_phys_offset_table_array *pot_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment;
	struct ssdfs_phys_offset_table_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_phys_offset_table_header);
	struct page *page;
	void *kaddr;
	u32 fragment_size;
	u32 rest_bytes, written_bytes = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!table || !cur_page || !write_offset);
	BUG_ON(peb_index >= table->pebs_count);

	SSDFS_DBG("peb %llu, current_log.start_page %u, "
		  "peb_index %u, sequence_id %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->peb_id,
		  pebi->current_log.start_page,
		  peb_index, sequence_id,
		  *cur_page, *write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&table->translation_lock);

	pot_table = &table->peb[peb_index];

	sequence = pot_table->sequence;
	kaddr = ssdfs_sequence_array_get_item(sequence, sequence_id);
	if (IS_ERR_OR_NULL(kaddr)) {
		err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  sequence_id, err);
		goto finish_store_fragment;
	}
	fragment = (struct ssdfs_phys_offset_table_fragment *)kaddr;

	down_write(&fragment->lock);

	if (atomic_read(&fragment->state) != SSDFS_BLK2OFF_FRAG_UNDER_COMMIT) {
		err = -ERANGE;
		SSDFS_ERR("invalid fragment state %#x\n",
			  atomic_read(&fragment->state));
		goto finish_fragment_copy;
	}

	hdr = fragment->hdr;

	if (!hdr) {
		err = -ERANGE;
		SSDFS_ERR("header pointer is NULL\n");
		goto finish_fragment_copy;
	}

	fragment_size = le32_to_cpu(hdr->byte_size);
	rest_bytes = fragment_size;

	if (fragment_size < hdr_size || fragment_size > fragment->buf_size) {
		err = -ERANGE;
		SSDFS_ERR("invalid fragment size %u\n",
			  fragment_size);
		goto finish_fragment_copy;
	}

	while (rest_bytes > 0) {
		u32 bytes;
		u32 cur_off = *write_offset % PAGE_SIZE;
		u32 new_off;

		bytes = min_t(u32, rest_bytes, PAGE_SIZE - cur_off);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(written_bytes > fragment_size);
#endif /* CONFIG_SSDFS_DEBUG */

		page = ssdfs_page_array_grab_page(&pebi->cache,
						  *cur_page);
		if (IS_ERR_OR_NULL(page)) {
			err = -ENOMEM;
			SSDFS_ERR("fail to get cache page: index %lu\n",
				  *cur_page);
			goto finish_fragment_copy;
		}

		err = ssdfs_memcpy_to_page(page, cur_off, PAGE_SIZE,
					   hdr, written_bytes, fragment_size,
					   bytes);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n", err);
			goto finish_cur_copy;
		}

		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);

		err = ssdfs_page_array_set_page_dirty(&pebi->cache,
						      *cur_page);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu as dirty: err %d\n",
				  *cur_page, err);
		}

finish_cur_copy:
		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));

		if (unlikely(err))
			goto finish_fragment_copy;

		*write_offset += bytes;

		new_off = (*cur_page << PAGE_SHIFT) + cur_off + bytes;
		*cur_page = new_off >> PAGE_SHIFT;

		rest_bytes -= bytes;
		written_bytes += bytes;
	};

finish_fragment_copy:
	up_write(&fragment->lock);

finish_store_fragment:
	up_read(&table->translation_lock);

	return err;
}

static inline
u16 ssdfs_next_sequence_id(u16 sequence_id)
{
	u16 next_sequence_id = U16_MAX;

	SSDFS_DBG("sequence_id %u\n", sequence_id);

	if (sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		SSDFS_ERR("invalid sequence_id %u\n",
			  sequence_id);
		return U16_MAX;
	} else if (sequence_id < SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		/* increment value */
		next_sequence_id = sequence_id + 1;
	} else
		next_sequence_id = 0;

	return next_sequence_id;
}

/*
 * ssdfs_peb_store_offsets_table() - store offsets table
 * @pebi: pointer on PEB object
 * @desc: offsets table descriptor [out]
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
 *
 * This function tries to store the offsets table into log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to find memory page.
 */
int ssdfs_peb_store_offsets_table(struct ssdfs_peb_info *pebi,
				  struct ssdfs_metadata_descriptor *desc,
				  pgoff_t *cur_page,
				  u32 *write_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_blk2off_table_snapshot snapshot = {0};
	struct ssdfs_blk2off_table_header hdr;
	struct ssdfs_translation_extent *extents = NULL;
	size_t tbl_hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	u16 extents_off = offsetof(struct ssdfs_blk2off_table_header, sequence);
	u16 extent_count = 0;
	u32 offset_table_off;
	u16 peb_index;
	u32 table_start_offset;
	u16 sequence_id;
	u32 fragments_count = 0;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!pebi->pebc->parent_si->blk2off_table);
	BUG_ON(!desc || !cur_page || !write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  *cur_page, *write_offset);
#else
	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  *cur_page, *write_offset);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi = pebi->pebc->parent_si->fsi;
	peb_index = pebi->peb_index;
	table = pebi->pebc->parent_si->blk2off_table;

	memset(desc, 0, sizeof(struct ssdfs_metadata_descriptor));
	memset(&hdr, 0, tbl_hdr_size);

	err = ssdfs_blk2off_table_snapshot(table, peb_index, &snapshot);
	if (err == -ENODATA) {
		SSDFS_DBG("table hasn't dirty fragments: peb_index %u\n",
			  peb_index);
		return 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to get snapshot: peb_index %u, err %d\n",
			  peb_index, err);
		return err;
	}

	if (unlikely(peb_index != snapshot.peb_index)) {
		err = -ERANGE;
		SSDFS_ERR("peb_index %u != snapshot.peb_index %u\n",
			  peb_index, snapshot.peb_index);
		goto fail_store_off_table;
	}

	if (unlikely(!snapshot.bmap_copy || !snapshot.tbl_copy)) {
		err = -ERANGE;
		SSDFS_ERR("invalid snapshot: "
			  "peb_index %u, bmap_copy %p, tbl_copy %p\n",
			  peb_index,
			  snapshot.bmap_copy,
			  snapshot.tbl_copy);
		goto fail_store_off_table;
	}

	extents = ssdfs_blk2off_kcalloc(snapshot.capacity,
				sizeof(struct ssdfs_translation_extent),
				GFP_KERNEL);
	if (unlikely(!extents)) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate extent array\n");
		goto fail_store_off_table;
	}

	hdr.magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	hdr.magic.key = cpu_to_le16(SSDFS_BLK2OFF_TABLE_HDR_MAGIC);
	hdr.magic.version.major = SSDFS_MAJOR_REVISION;
	hdr.magic.version.minor = SSDFS_MINOR_REVISION;

	err = ssdfs_blk2off_table_extract_extents(&snapshot, extents,
						  snapshot.capacity,
						  &extent_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract the extent array: "
			  "peb_index %u, err %d\n",
			  peb_index, err);
		goto fail_store_off_table;
	} else if (extent_count == 0) {
		err = -ERANGE;
		SSDFS_ERR("invalid extent count\n");
		goto fail_store_off_table;
	}

	hdr.extents_off = cpu_to_le16(extents_off);
	hdr.extents_count = cpu_to_le16(extent_count);

#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
	fragments_count = snapshot.fragments_count;
#else
	fragments_count = snapshot.dirty_fragments;
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

	offset_table_off = tbl_hdr_size +
			   ((extent_count - 1) *
			    sizeof(struct ssdfs_translation_extent));

	hdr.offset_table_off = cpu_to_le16((u16)offset_table_off);

	sequence_id = snapshot.start_sequence_id;
	for (i = 0; i < fragments_count; i++) {
		err = ssdfs_blk2off_table_prepare_for_commit(table, peb_index,
							     sequence_id,
							     &offset_table_off,
							     &snapshot);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare fragment for commit: "
				  "peb_index %u, sequence_id %u, err %d\n",
				  peb_index, sequence_id, err);
			goto fail_store_off_table;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(offset_table_off >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		sequence_id = ssdfs_next_sequence_id(sequence_id);
		if (sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
			err = -ERANGE;
			SSDFS_ERR("invalid next sequence_id %u\n",
				  sequence_id);
			goto fail_store_off_table;
		}
	}

	hdr.fragments_count = cpu_to_le16(snapshot.dirty_fragments);

	ssdfs_memcpy(hdr.sequence, 0, sizeof(struct ssdfs_translation_extent),
		     extents, 0, sizeof(struct ssdfs_translation_extent),
		     sizeof(struct ssdfs_translation_extent));

	hdr.check.bytes = cpu_to_le16(tbl_hdr_size);
	hdr.check.flags = cpu_to_le16(SSDFS_CRC32);

	err = ssdfs_calculate_csum(&hdr.check, &hdr, tbl_hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("unable to calculate checksum: err %d\n", err);
		goto fail_store_off_table;
	}

	*write_offset = ssdfs_peb_correct_area_write_offset(*write_offset,
							    tbl_hdr_size);
	table_start_offset = *write_offset;

	desc->offset = cpu_to_le32(*write_offset +
				(pebi->current_log.start_page * fsi->pagesize));

	err = ssdfs_peb_store_offsets_table_header(pebi, &hdr,
						   cur_page, write_offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store offsets table's header: "
			  "cur_page %lu, write_offset %u, err %d\n",
			  *cur_page, *write_offset, err);
		goto fail_store_off_table;
	}

	if (extent_count > 1) {
		err = ssdfs_peb_store_offsets_table_extents(pebi, &extents[1],
							    extent_count - 1,
							    cur_page,
							    write_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store offsets table's extents: "
				  "cur_page %lu, write_offset %u, err %d\n",
				  *cur_page, *write_offset, err);
			goto fail_store_off_table;
		}
	}

	sequence_id = snapshot.start_sequence_id;
	for (i = 0; i < fragments_count; i++) {
		err = ssdfs_peb_store_offsets_table_fragment(pebi, table,
							     peb_index,
							     sequence_id,
							     cur_page,
							     write_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store offsets table's fragment: "
				  "sequence_id %u, cur_page %lu, "
				  "write_offset %u, err %d\n",
				  sequence_id, *cur_page,
				  *write_offset, err);
			goto fail_store_off_table;
		}

		sequence_id = ssdfs_next_sequence_id(sequence_id);
		if (sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
			err = -ERANGE;
			SSDFS_ERR("invalid next sequence_id %u\n",
				  sequence_id);
			goto fail_store_off_table;
		}
	}

	err = ssdfs_blk2off_table_forget_snapshot(table, &snapshot,
						  extents, extent_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to forget snapshot state: "
			  "peb_index %u, err %d\n",
			  peb_index, err);
		goto fail_store_off_table;
	}

	BUG_ON(*write_offset <= table_start_offset);
	desc->size = cpu_to_le32(*write_offset - table_start_offset);

	pebi->current_log.seg_flags |= SSDFS_SEG_HDR_HAS_OFFSET_TABLE;

fail_store_off_table:
	ssdfs_blk2off_table_free_snapshot(&snapshot);

	ssdfs_blk2off_kfree(extents);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_blk2off_table_get_used_logical_blks() - get used logical blocks count
 * @tbl: pointer on table object
 * @used_blks: pointer on used logical blocks count [out]
 *
 * This method tries to get used logical blocks count.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EAGAIN     - table doesn't initialized yet.
 */
int ssdfs_blk2off_table_get_used_logical_blks(struct ssdfs_blk2off_table *tbl,
						u16 *used_blks)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !used_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, used_blks %p\n",
		  tbl, used_blks);

	*used_blks = U16_MAX;

	if (atomic_read(&tbl->state) < SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
		SSDFS_DBG("table is not initialized yet\n");
		return -EAGAIN;
	}

	down_read(&tbl->translation_lock);
	*used_blks = tbl->used_logical_blks;
	up_read(&tbl->translation_lock);

	return 0;
}

/*
 * ssdfs_blk2off_table_blk_desc_init() - init block descriptor for offset
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @pos: pointer of offset's position [in]
 *
 * This method tries to init block descriptor for offset.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 * %-ENODATA    - table doesn't contain logical block or corresponding ID.
 */
int ssdfs_blk2off_table_blk_desc_init(struct ssdfs_blk2off_table *table,
					u16 logical_blk,
					struct ssdfs_offset_position *pos)
{
	struct ssdfs_offset_position *old_pos = NULL;
	struct ssdfs_blk_state_offset *state_off;
	size_t desc_size = sizeof(struct ssdfs_block_descriptor_state);
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !pos);

	SSDFS_DBG("table %p, logical_blk %u, pos %p\n",
		  table, logical_blk, pos);
#endif /* CONFIG_SSDFS_DEBUG */

	if (logical_blk >= table->lblk2off_capacity) {
		SSDFS_ERR("logical_blk %u >= lblk2off_capacity %u\n",
			  logical_blk, table->lblk2off_capacity);
		return -ERANGE;
	}

	down_write(&table->translation_lock);

	if (ssdfs_blk2off_table_bmap_vacant(&table->lbmap,
					    SSDFS_LBMAP_STATE_INDEX,
					    table->lblk2off_capacity,
					    logical_blk)) {
		err = -ENODATA;
		SSDFS_ERR("requested block %u hasn't been allocated\n",
			  logical_blk);
		goto finish_init;
	}

	old_pos = SSDFS_OFF_POS(ssdfs_dynamic_array_get_locked(&table->lblk2off,
								logical_blk));
	if (IS_ERR_OR_NULL(old_pos)) {
		err = (old_pos == NULL ? -ENOENT : PTR_ERR(old_pos));
		SSDFS_ERR("fail to get logical block: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		goto finish_init;
	}

	switch (old_pos->blk_desc.status) {
	case SSDFS_BLK_DESC_BUF_UNKNOWN_STATE:
	case SSDFS_BLK_DESC_BUF_ALLOCATED:
		/* continue logic */
		break;

	case SSDFS_BLK_DESC_BUF_INITIALIZED:
		err = 0;
		SSDFS_DBG("logical block %u has been initialized\n",
			  logical_blk);
		goto finish_init;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid state %#x of blk desc buffer\n",
			  old_pos->blk_desc.status);
		goto finish_init;
	}

	state_off = &pos->blk_desc.buf.state[0];

	if (IS_SSDFS_BLK_STATE_OFFSET_INVALID(state_off)) {
		err = -ERANGE;
		SSDFS_ERR("block state offset invalid\n");
		SSDFS_ERR("log_start_page %u, log_area %u, "
			  "peb_migration_id %u, byte_offset %u\n",
			  le16_to_cpu(state_off->log_start_page),
			  state_off->log_area,
			  state_off->peb_migration_id,
			  le32_to_cpu(state_off->byte_offset));
		goto finish_init;
	}

	ssdfs_memcpy(&old_pos->blk_desc, 0, desc_size,
		     &pos->blk_desc.buf, 0, desc_size,
		     desc_size);

finish_init:
	ssdfs_dynamic_array_release(&table->lblk2off, logical_blk, old_pos);
	up_write(&table->translation_lock);

	return err;
}

/*
 * ssdfs_blk2off_table_get_checked_position() - get checked offset's position
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @pos: pointer of offset's position [out]
 *
 * This method tries to get and to check offset's position for
 * requested logical block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 * %-ENODATA    - table doesn't contain logical block or corresponding ID.
 * %-ENOENT     - table's fragment for requested logical block not initialized.
 * %-EBUSY      - logical block hasn't ID yet.
 */
static
int ssdfs_blk2off_table_get_checked_position(struct ssdfs_blk2off_table *table,
					     u16 logical_blk,
					     struct ssdfs_offset_position *pos)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment;
	void *ptr;
	size_t off_pos_size = sizeof(struct ssdfs_offset_position);
	int state;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !pos);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));

	SSDFS_DBG("table %p, logical_blk %u, pos %p\n",
		  table, logical_blk, pos);

	ssdfs_debug_blk2off_table_object(table);
#endif /* CONFIG_SSDFS_DEBUG */

	if (logical_blk >= table->lblk2off_capacity) {
		SSDFS_ERR("logical_blk %u >= lblk2off_capacity %u\n",
			  logical_blk, table->lblk2off_capacity);
		return -ERANGE;
	}

	SSDFS_DBG("init_bmap %lx, state_bmap %lx, modification_bmap %lx\n",
		  *table->lbmap.array[SSDFS_LBMAP_INIT_INDEX],
		  *table->lbmap.array[SSDFS_LBMAP_STATE_INDEX],
		  *table->lbmap.array[SSDFS_LBMAP_MODIFICATION_INDEX]);

	if (ssdfs_blk2off_table_bmap_vacant(&table->lbmap,
					    SSDFS_LBMAP_STATE_INDEX,
					    table->lblk2off_capacity,
					    logical_blk)) {
		SSDFS_ERR("requested block %u hasn't been allocated\n",
			  logical_blk);
		return -ENODATA;
	}

	ptr = ssdfs_dynamic_array_get_locked(&table->lblk2off, logical_blk);
	if (IS_ERR_OR_NULL(ptr)) {
		err = (ptr == NULL ? -ENOENT : PTR_ERR(ptr));
		SSDFS_ERR("fail to get logical block: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		return err;
	}

	ssdfs_memcpy(pos, 0, off_pos_size,
		     ptr, 0, off_pos_size,
		     off_pos_size);

	err = ssdfs_dynamic_array_release(&table->lblk2off, logical_blk, ptr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to release: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		return err;
	}

	if (pos->id == SSDFS_INVALID_OFFSET_ID) {
		SSDFS_DBG("logical block %u hasn't ID yet\n",
			  logical_blk);
		return -EBUSY;
	}

	if (pos->peb_index >= table->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  pos->peb_index, table->pebs_count);
		return -ERANGE;
	}

	if (pos->sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		SSDFS_ERR("sequence_id %u is out of order\n",
			  pos->sequence_id);
		return -ERANGE;
	}

	phys_off_table = &table->peb[pos->peb_index];

	sequence = phys_off_table->sequence;
	ptr = ssdfs_sequence_array_get_item(sequence, pos->sequence_id);
	if (IS_ERR_OR_NULL(ptr)) {
		err = (ptr == NULL ? -ENOENT : PTR_ERR(ptr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  pos->sequence_id, err);
		return err;
	}
	fragment = (struct ssdfs_phys_offset_table_fragment *)ptr;

	state = atomic_read(&fragment->state);
	if (state < SSDFS_BLK2OFF_FRAG_INITIALIZED) {
		SSDFS_DBG("fragment %u is not initialized yet\n",
			  pos->sequence_id);
		return -ENOENT;
	} else if (state >= SSDFS_BLK2OFF_FRAG_STATE_MAX) {
		SSDFS_ERR("unknown fragment's state\n");
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_blk2off_table_check_fragment_desc() - check fragment's description
 * @table: pointer on table object
 * @frag: pointer on fragment
 * @pos: pointer of offset's position
 *
 * This method tries to check fragment's description.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 */
static
int ssdfs_blk2off_table_check_fragment_desc(struct ssdfs_blk2off_table *table,
				struct ssdfs_phys_offset_table_fragment *frag,
				struct ssdfs_offset_position *pos)
{
	u16 start_id;
	int id_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !frag || !pos);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, id %u, peb_index %u, "
		  "sequence_id %u, offset_index %u\n",
		  table, pos->id, pos->peb_index,
		  pos->sequence_id, pos->offset_index);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rwsem_is_locked(&frag->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	start_id = frag->start_id;
	id_count = atomic_read(&frag->id_count);

	if (pos->id < start_id || pos->id >= (start_id + id_count)) {
		SSDFS_ERR("id %u out of range (start %u, len %u)\n",
			  pos->id, start_id, id_count);
		return -ERANGE;
	}

	if (pos->offset_index >= id_count) {
		SSDFS_ERR("offset_index %u >= id_count %u\n",
			  pos->offset_index, id_count);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (!frag->phys_offs) {
		SSDFS_ERR("offsets table pointer is NULL\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

bool has_logical_block_id_assigned(struct ssdfs_blk2off_table *table,
				   u16 logical_blk)
{
	u16 capacity;
	bool has_assigned = false;

	down_read(&table->translation_lock);
	capacity = table->lblk2off_capacity;
	has_assigned = !ssdfs_blk2off_table_bmap_vacant(&table->lbmap,
						SSDFS_LBMAP_MODIFICATION_INDEX,
						capacity,
						logical_blk);
	up_read(&table->translation_lock);

	return has_assigned;
}

/*
 * ssdfs_blk2off_table_convert() - convert logical block into offset
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @peb_index: pointer on PEB index value [out]
 * @migration_state: migration state of the block [out]
 * @pos: offset position [out]
 *
 * This method tries to convert logical block number into offset.
 *
 * RETURN:
 * [success] - pointer on found offset.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for conversion yet.
 * %-ENODATA    - table doesn't contain logical block.
 * %-ENOENT     - table's fragment for requested logical block not initialized
 */
struct ssdfs_phys_offset_descriptor *
ssdfs_blk2off_table_convert(struct ssdfs_blk2off_table *table,
			    u16 logical_blk,
			    u16 *peb_index,
			    int *migration_state,
			    struct ssdfs_offset_position *pos)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment;
	struct ssdfs_phys_offset_descriptor *ptr = NULL;
	struct ssdfs_migrating_block *blk = NULL;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !peb_index || !pos);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, logical_blk %u\n",
		  table, logical_blk);

	*peb_index = U16_MAX;

	down_read(&table->translation_lock);

	if (logical_blk >= table->lblk2off_capacity) {
		err = -EINVAL;
		SSDFS_ERR("fail to convert logical block: "
			  "block %u >= capacity %u\n",
			  logical_blk,
			  table->lblk2off_capacity);
		goto finish_translation;
	}

	if (atomic_read(&table->state) <= SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
		u16 capacity = table->lblk2off_capacity;

		if (ssdfs_blk2off_table_bmap_vacant(&table->lbmap,
						    SSDFS_LBMAP_INIT_INDEX,
						    capacity,
						    logical_blk)) {
			err = -EAGAIN;
			SSDFS_DBG("table is not initialized yet: "
				  "logical_blk %u\n",
				  logical_blk);
			goto finish_translation;
		}
	}

	if (migration_state) {
		blk = ssdfs_get_migrating_block(table, logical_blk, false);
		if (IS_ERR_OR_NULL(blk))
			*migration_state = SSDFS_LBLOCK_UNKNOWN_STATE;
		else
			*migration_state = blk->state;

		SSDFS_DBG("logical_blk %u, migration_state %#x\n",
			  logical_blk, *migration_state);
	}

	err = ssdfs_blk2off_table_get_checked_position(table, logical_blk,
							pos);
	if (err == -EBUSY) {
		SSDFS_DBG("unable to get checked position: logical_blk %u\n",
		          logical_blk);

		up_read(&table->translation_lock);
		wait_event_interruptible_timeout(table->wait_queue,
				has_logical_block_id_assigned(table,
							logical_blk),
				SSDFS_DEFAULT_TIMEOUT);
		down_read(&table->translation_lock);

		err = ssdfs_blk2off_table_get_checked_position(table,
								logical_blk,
								pos);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get checked offset's position: "
				  "logical_block %u, err %d\n",
				  logical_blk, err);
			goto finish_translation;
		}
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to get checked offset's position: "
			  "logical_block %u, err %d\n",
			  logical_blk, err);
		goto finish_translation;
	}

	*peb_index = pos->peb_index;
	phys_off_table = &table->peb[pos->peb_index];

	sequence = phys_off_table->sequence;
	kaddr = ssdfs_sequence_array_get_item(sequence, pos->sequence_id);
	if (IS_ERR_OR_NULL(kaddr)) {
		err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  pos->sequence_id, err);
		goto finish_translation;
	}
	fragment = (struct ssdfs_phys_offset_table_fragment *)kaddr;

	down_read(&fragment->lock);

	err = ssdfs_blk2off_table_check_fragment_desc(table, fragment, pos);
	if (unlikely(err)) {
		SSDFS_ERR("invalid fragment description: err %d\n", err);
		goto finish_fragment_lookup;
	}

	ptr = &fragment->phys_offs[pos->offset_index];

finish_fragment_lookup:
	up_read(&fragment->lock);

finish_translation:
	up_read(&table->translation_lock);

	if (err)
		return ERR_PTR(err);

	SSDFS_DBG("logical_blk %u, "
		  "logical_offset %u, peb_index %u, peb_page %u, "
		  "log_start_page %u, log_area %u, "
		  "peb_migration_id %u, byte_offset %u\n",
		  logical_blk,
		  le32_to_cpu(ptr->page_desc.logical_offset),
		  pos->peb_index,
		  le16_to_cpu(ptr->page_desc.peb_page),
		  le16_to_cpu(ptr->blk_state.log_start_page),
		  ptr->blk_state.log_area,
		  ptr->blk_state.peb_migration_id,
		  le32_to_cpu(ptr->blk_state.byte_offset));

	return ptr;
}

/*
 * ssdfs_blk2off_table_get_offset_position() - get offset position
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @pos: offset position
 *
 * This method tries to get offset position.
 *
 * RETURN:
 * [success] - pointer on found offset.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for conversion yet.
 * %-ENODATA    - table doesn't contain logical block.
 */
int ssdfs_blk2off_table_get_offset_position(struct ssdfs_blk2off_table *table,
					    u16 logical_blk,
					    struct ssdfs_offset_position *pos)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !pos);

	SSDFS_DBG("table %p, logical_blk %u\n",
		  table, logical_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&table->translation_lock);

	if (logical_blk >= table->lblk2off_capacity) {
		err = -EINVAL;
		SSDFS_ERR("fail to convert logical block: "
			  "block %u >= capacity %u\n",
			  logical_blk,
			  table->lblk2off_capacity);
		goto finish_extract_position;
	}

	if (atomic_read(&table->state) <= SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
		u16 capacity = table->lblk2off_capacity;

		if (ssdfs_blk2off_table_bmap_vacant(&table->lbmap,
						    SSDFS_LBMAP_INIT_INDEX,
						    capacity,
						    logical_blk)) {
			err = -EAGAIN;
			SSDFS_DBG("table is not initialized yet: "
				  "logical_blk %u\n",
				  logical_blk);
			goto finish_extract_position;
		}
	}

	err = ssdfs_blk2off_table_get_checked_position(table, logical_blk,
							pos);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get checked offset's position: "
			  "logical_block %u, err %d\n",
			  logical_blk, err);
		goto finish_extract_position;
	}

finish_extract_position:
	up_read(&table->translation_lock);

	if (err)
		return err;

	SSDFS_DBG("logical_blk %u, "
		  "pos->cno %llu, pos->id %u, pos->peb_index %u, "
		  "pos->sequence_id %u, pos->offset_index %u\n",
		  logical_blk, pos->cno, pos->id,
		  pos->peb_index, pos->sequence_id,
		  pos->offset_index);

	return 0;
}

/*
 * calculate_rest_range_id_count() - get rest range's IDs
 * @ptr: pointer on fragment object
 *
 * This method calculates the rest count of IDs.
 */
static inline
int calculate_rest_range_id_count(struct ssdfs_phys_offset_table_fragment *ptr)
{
	int id_count = atomic_read(&ptr->id_count);
	size_t blk2off_tbl_hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	size_t hdr_size = sizeof(struct ssdfs_phys_offset_table_header);
	size_t off_size = sizeof(struct ssdfs_phys_offset_descriptor);
	size_t metadata_size = blk2off_tbl_hdr_size + hdr_size;
	int id_capacity;
	int start_id = ptr->start_id;
	int rest_range_ids;

	if ((start_id + id_count) > SSDFS_INVALID_OFFSET_ID) {
		SSDFS_DBG("start_id %d, id_count %d\n",
			  start_id, id_count);
		return 0;
	}

	id_capacity = (ptr->buf_size - metadata_size) / off_size;

	if (id_count >= id_capacity) {
		SSDFS_DBG("id_count %d, id_capacity %d\n",
			  id_count, id_capacity);
		return 0;
	}

	rest_range_ids = id_capacity - id_count;

	SSDFS_DBG("id_count %d, id_capacity %d, rest_range_ids %d\n",
		  id_count, id_capacity, rest_range_ids);

	return rest_range_ids;
}

/*
 * is_id_valid_for_assignment() - check ID validity
 * @table: pointer on table object
 * @ptr: pointer on fragment object
 * @id: ID value
 */
static
bool is_id_valid_for_assignment(struct ssdfs_blk2off_table *table,
				struct ssdfs_phys_offset_table_fragment *ptr,
				int id)
{
	int id_count = atomic_read(&ptr->id_count);
	int rest_range_ids;

	if (id < ptr->start_id) {
		SSDFS_WARN("id %d < start_id %u\n",
			   id, ptr->start_id);
		return false;
	}

	if (id > (ptr->start_id + id_count)) {
		SSDFS_WARN("id %d > (ptr->start_id %u + id_count %d)",
			   id, ptr->start_id, id_count);
		return false;
	}

	rest_range_ids = calculate_rest_range_id_count(ptr);

	SSDFS_DBG("id %d, rest_range_ids %d\n",
		  id, rest_range_ids);

	return rest_range_ids > 0;
}

/*
 * ssdfs_blk2off_table_assign_id() - assign ID for logical block
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @peb_index: PEB's index
 * @blk_desc: block descriptor
 * @last_sequence_id: pointer on last fragment index [out]
 *
 * This method tries to define physical offset's ID value for
 * requested logical block number in last actual PEB's fragment.
 * If the last actual fragment hasn't vacant ID then the method
 * returns error and found last fragment index in
 * @last_sequence_id.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - internal logic error.
 * %-ENOENT     - table's fragment for requested logical block not initialized
 * %-ENOSPC     - fragment hasn't vacant IDs and it needs to initialize next one
 */
static
int ssdfs_blk2off_table_assign_id(struct ssdfs_blk2off_table *table,
				  u16 logical_blk, u16 peb_index,
				  struct ssdfs_block_descriptor *blk_desc,
				  u16 *last_sequence_id)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment;
	struct ssdfs_offset_position *pos;
	int state;
	int id = -1;
	u16 offset_index = U16_MAX;
	u16 capacity;
	void *kaddr;
	unsigned long last_id;
#ifdef CONFIG_SSDFS_DEBUG
	int i;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !last_sequence_id);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));

	SSDFS_DBG("table %p, logical_blk %u, peb_index %u\n",
		  table, logical_blk, peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (peb_index >= table->pebs_count) {
		SSDFS_ERR("fail to change offset value: "
			  "peb_index %u >= pebs_count %u\n",
			  peb_index, table->pebs_count);
		return -EINVAL;
	}

	capacity = table->lblk2off_capacity;
	phys_off_table = &table->peb[peb_index];

	state = atomic_read(&phys_off_table->state);
	if (state < SSDFS_BLK2OFF_TABLE_PARTIAL_INIT) {
		SSDFS_DBG("table doesn't initialized for peb %u\n",
			  peb_index);
		return -ENOENT;
	} else if (state >= SSDFS_BLK2OFF_TABLE_STATE_MAX) {
		SSDFS_DBG("unknown table state %#x\n",
			  state);
		return -ERANGE;
	}

	sequence = phys_off_table->sequence;

	if (is_ssdfs_sequence_array_last_id_invalid(sequence)) {
		/* first creation */
		return -ENOSPC;
	}

	last_id = ssdfs_sequence_array_last_id(sequence);
	if (last_id >= U16_MAX) {
		SSDFS_ERR("invalid last_id %lu\n", last_id);
		return -ERANGE;
	} else
		*last_sequence_id = (u16)last_id;

	if (*last_sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		SSDFS_ERR("invalid last_sequence_id %d\n",
			  *last_sequence_id);
		return -ERANGE;
	}

	kaddr = ssdfs_sequence_array_get_item(sequence, *last_sequence_id);
	if (IS_ERR_OR_NULL(kaddr)) {
		err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  *last_sequence_id, err);
		return err;
	}
	fragment = (struct ssdfs_phys_offset_table_fragment *)kaddr;

	state = atomic_read(&fragment->state);
	if (state < SSDFS_BLK2OFF_FRAG_CREATED) {
		SSDFS_DBG("fragment %u isn't created\n",
			  *last_sequence_id);
		return -ENOENT;
	} else if (state == SSDFS_BLK2OFF_FRAG_UNDER_COMMIT ||
		   state == SSDFS_BLK2OFF_FRAG_COMMITED) {
		SSDFS_DBG("fragment %d is under commit\n",
			  *last_sequence_id);
		return -ENOSPC;
	} else if (state >= SSDFS_BLK2OFF_FRAG_STATE_MAX) {
		SSDFS_DBG("unknown fragment state %#x\n",
			  state);
		return -ERANGE;
	}

	pos = SSDFS_OFF_POS(ssdfs_dynamic_array_get_locked(&table->lblk2off,
							   logical_blk));
	if (IS_ERR_OR_NULL(pos)) {
		err = (pos == NULL ? -ENOENT : PTR_ERR(pos));
		SSDFS_ERR("fail to get logical block: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("POS BEFORE: cno %llu, id %u, peb_index %u, "
		  "sequence_id %u, offset_index %u\n",
		  pos->cno, pos->id, pos->peb_index,
		  pos->sequence_id, pos->offset_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!ssdfs_blk2off_table_bmap_vacant(&table->lbmap,
					     SSDFS_LBMAP_MODIFICATION_INDEX,
					     capacity,
					     logical_blk)) {
		if (pos->sequence_id == *last_sequence_id) {
			pos->cno = ssdfs_current_cno(table->fsi->sb);
			pos->peb_index = peb_index;
			id = pos->id;
			offset_index = pos->offset_index;
		} else if (pos->sequence_id < *last_sequence_id) {
			offset_index =
				atomic_inc_return(&fragment->id_count) - 1;
			id = fragment->start_id + offset_index;

			if (!is_id_valid_for_assignment(table, fragment, id)) {
				err = -ENOSPC;
				SSDFS_DBG("id %d cannot be assign "
					  "for fragment %d\n",
					  id, *last_sequence_id);
				atomic_dec(&fragment->id_count);
				goto finish_assign_id;
			}

			pos->cno = ssdfs_current_cno(table->fsi->sb);
			pos->id = (u16)id;
			pos->peb_index = peb_index;
			pos->sequence_id = *last_sequence_id;
			pos->offset_index = offset_index;
		} else if (pos->sequence_id >= SSDFS_INVALID_FRAG_ID) {
			offset_index =
				atomic_inc_return(&fragment->id_count) - 1;
			id = fragment->start_id + offset_index;

			if (!is_id_valid_for_assignment(table, fragment, id)) {
				err = -ENOSPC;
				SSDFS_DBG("id %d cannot be assign "
					  "for fragment %d\n",
					  id, *last_sequence_id);
				atomic_dec(&fragment->id_count);
				goto finish_assign_id;
			}

			pos->cno = ssdfs_current_cno(table->fsi->sb);
			pos->id = (u16)id;
			pos->peb_index = peb_index;
			pos->sequence_id = *last_sequence_id;
			pos->offset_index = offset_index;
		} else if (pos->sequence_id > *last_sequence_id) {
			err = -ERANGE;
			SSDFS_WARN("sequence_id %u > last_sequence_id %d\n",
				  pos->sequence_id,
				  *last_sequence_id);
			goto finish_assign_id;
		}
	} else {
		offset_index = atomic_inc_return(&fragment->id_count) - 1;
		id = fragment->start_id + offset_index;

		if (!is_id_valid_for_assignment(table, fragment, id)) {
			err = -ENOSPC;
			SSDFS_DBG("id %d cannot be assign for fragment %d\n",
				  id, *last_sequence_id);
			atomic_dec(&fragment->id_count);
			goto finish_assign_id;
		}

		pos->cno = ssdfs_current_cno(table->fsi->sb);
		pos->id = (u16)id;
		pos->peb_index = peb_index;
		pos->sequence_id = *last_sequence_id;
		pos->offset_index = offset_index;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("POS AFTER: cno %llu, id %u, peb_index %u, "
		  "sequence_id %u, offset_index %u\n",
		  pos->cno, pos->id, pos->peb_index,
		  pos->sequence_id, pos->offset_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (blk_desc) {
		ssdfs_memcpy(&pos->blk_desc.buf,
			     0, sizeof(struct ssdfs_block_descriptor),
			     blk_desc,
			     0, sizeof(struct ssdfs_block_descriptor),
			     sizeof(struct ssdfs_block_descriptor));

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("logical_blk %u, id %d, "
			  "peb_index %u, sequence_id %u, offset_index %u\n",
			  logical_blk, id, peb_index,
			  *last_sequence_id, offset_index);

		for (i = 0; i < SSDFS_BLK_STATE_OFF_MAX; i++) {
			struct ssdfs_blk_state_offset *offset = NULL;

			offset = &blk_desc->state[i];

			SSDFS_DBG("BLK STATE OFFSET %d: "
				  "log_start_page %u, log_area %#x, "
				  "byte_offset %u, "
				  "peb_migration_id %u\n",
				  i,
				  le16_to_cpu(offset->log_start_page),
				  offset->log_area,
				  le32_to_cpu(offset->byte_offset),
				  offset->peb_migration_id);
		}
#endif /* CONFIG_SSDFS_DEBUG */
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("DONE: logical_blk %u, id %d, "
		  "peb_index %u, sequence_id %u, offset_index %u\n",
		  logical_blk, id, peb_index,
		  *last_sequence_id, offset_index);
#endif /* CONFIG_SSDFS_DEBUG */

finish_assign_id:
	ssdfs_dynamic_array_release(&table->lblk2off, logical_blk, pos);
	return err;
}

/*
 * ssdfs_blk2off_table_add_fragment() - add fragment into PEB's table
 * @table: pointer on table object
 * @peb_index: PEB's index
 * @old_sequence_id: old last sequence id
 *
 * This method tries to initialize additional fragment into
 * PEB's table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - PEB's fragment count isn't equal to @old_fragment_count
 * %-ENOSPC     - table hasn't space for new fragments
 */
static
int ssdfs_blk2off_table_add_fragment(struct ssdfs_blk2off_table *table,
					u16 peb_index,
					u16 old_sequence_id)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment, *prev_fragment;
	unsigned long last_sequence_id = ULONG_MAX;
	u16 start_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));

	SSDFS_DBG("table %p,  peb_index %u, old_sequence_id %d\n",
		  table, peb_index, old_sequence_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (peb_index >= table->pebs_count) {
		SSDFS_ERR("fail to change offset value: "
			  "peb_index %u >= pebs_count %u\n",
			  peb_index, table->pebs_count);
		return -EINVAL;
	}

	phys_off_table = &table->peb[peb_index];
	sequence = phys_off_table->sequence;

	if (is_ssdfs_sequence_array_last_id_invalid(sequence)) {
		/*
		 * first creation
		 */
	} else {
		last_sequence_id = ssdfs_sequence_array_last_id(sequence);
		if (last_sequence_id != old_sequence_id) {
			SSDFS_DBG("last_id %lu != old_id %u\n",
				  last_sequence_id, old_sequence_id);
			return -EAGAIN;
		}
	}

	fragment = ssdfs_blk2off_frag_alloc();
	if (IS_ERR_OR_NULL(fragment)) {
		err = (fragment == NULL ? -ENOMEM : PTR_ERR(fragment));
		SSDFS_ERR("fail to allocate fragment: "
			  "err %d\n", err);
		return err;
	}

	err = ssdfs_sequence_array_add_item(sequence, fragment,
					    &last_sequence_id);
	if (unlikely(err)) {
		ssdfs_blk2off_frag_free(fragment);
		SSDFS_ERR("fail to add fragment: "
			  "err %d\n", err);
		return err;
	}

	if (last_sequence_id == 0) {
		start_id = 0;
	} else {
		int prev_id_count;
		void *kaddr;

		kaddr = ssdfs_sequence_array_get_item(sequence,
						      last_sequence_id - 1);
		if (IS_ERR_OR_NULL(kaddr)) {
			err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
			SSDFS_ERR("fail to get fragment: "
				  "sequence_id %lu, err %d\n",
				  last_sequence_id - 1, err);
			return err;
		}
		prev_fragment =
			(struct ssdfs_phys_offset_table_fragment *)kaddr;

		start_id = prev_fragment->start_id;
		prev_id_count = atomic_read(&prev_fragment->id_count);

		if ((start_id + prev_id_count + 1) >= SSDFS_INVALID_OFFSET_ID)
			start_id = 0;
		else
			start_id += prev_id_count;
	}

	err = ssdfs_blk2off_table_init_fragment(fragment, last_sequence_id,
						start_id, table->pages_per_peb,
						SSDFS_BLK2OFF_FRAG_INITIALIZED,
						NULL);
	if (err) {
		SSDFS_ERR("fail to init fragment %lu: err %d\n",
			  last_sequence_id, err);
		return err;
	}

	atomic_inc(&phys_off_table->fragment_count);

	return 0;
}

/*
 * ssdfs_table_fragment_set_dirty() - set fragment dirty
 * @table: pointer on table object
 * @peb_index: PEB's index value
 * @sequence_id: fragment's sequence_id
 */
static inline
int ssdfs_table_fragment_set_dirty(struct ssdfs_blk2off_table *table,
				    u16 peb_index, u16 sequence_id)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	int new_state = SSDFS_BLK2OFF_TABLE_UNDEFINED;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));

	SSDFS_DBG("table %p,  peb_index %u, sequence_id %u\n",
		  table, peb_index, sequence_id);
#endif /* CONFIG_SSDFS_DEBUG */

	phys_off_table = &table->peb[peb_index];

	err = ssdfs_sequence_array_change_state(phys_off_table->sequence,
						sequence_id,
						SSDFS_SEQUENCE_ITEM_NO_TAG,
						SSDFS_SEQUENCE_ITEM_DIRTY_TAG,
						ssdfs_change_fragment_state,
						SSDFS_BLK2OFF_FRAG_INITIALIZED,
						SSDFS_BLK2OFF_FRAG_DIRTY);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set fragment dirty: "
			  "sequence_id %u, err %d\n",
			  sequence_id, err);
		return err;
	}

	switch (atomic_read(&phys_off_table->state)) {
	case SSDFS_BLK2OFF_TABLE_COMPLETE_INIT:
		new_state = SSDFS_BLK2OFF_TABLE_DIRTY;
		break;

	case SSDFS_BLK2OFF_TABLE_PARTIAL_INIT:
		new_state = SSDFS_BLK2OFF_TABLE_DIRTY_PARTIAL_INIT;
		break;

	case SSDFS_BLK2OFF_TABLE_DIRTY_PARTIAL_INIT:
		SSDFS_DBG("blk2off table is dirty already\n");
		new_state = SSDFS_BLK2OFF_TABLE_DIRTY_PARTIAL_INIT;
		break;

	case SSDFS_BLK2OFF_TABLE_DIRTY:
		SSDFS_DBG("blk2off table is dirty already\n");
		new_state = SSDFS_BLK2OFF_TABLE_DIRTY;
		break;

	default:
		SSDFS_WARN("unexpected blk2off state %#x\n",
			   atomic_read(&phys_off_table->state));
		new_state = SSDFS_BLK2OFF_TABLE_DIRTY;
		break;
	}

	atomic_set(&phys_off_table->state,
		   new_state);

	return 0;
}

/*
 * ssdfs_blk2off_table_fragment_set_clean() - set fragment clean
 * @table: pointer on table object
 * @peb_index: PEB's index value
 * @sequence_id: fragment's sequence_id
 */
#ifdef CONFIG_SSDFS_TESTING
int ssdfs_blk2off_table_fragment_set_clean(struct ssdfs_blk2off_table *table,
					   u16 peb_index, u16 sequence_id)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	int new_state = SSDFS_BLK2OFF_TABLE_COMPLETE_INIT;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p,  peb_index %u, sequence_id %u\n",
		  table, peb_index, sequence_id);

	phys_off_table = &table->peb[peb_index];

	err = ssdfs_sequence_array_change_state(phys_off_table->sequence,
						sequence_id,
						SSDFS_SEQUENCE_ITEM_DIRTY_TAG,
						SSDFS_SEQUENCE_ITEM_NO_TAG,
						ssdfs_change_fragment_state,
						SSDFS_BLK2OFF_FRAG_DIRTY,
						SSDFS_BLK2OFF_FRAG_INITIALIZED);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set fragment clean: "
			  "sequence_id %u, err %d\n",
			  sequence_id, err);
		return err;
	}

	atomic_set(&phys_off_table->state, new_state);

	return 0;
}
#endif /* CONFIG_SSDFS_TESTING */

/*
 * ssdfs_blk2off_table_change_offset() - update logical block's offset
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @peb_index: PEB's index value
 * @blk_desc: block descriptor
 * @off: new value of offset [in]
 *
 * This method tries to update offset value for logical block.
 * Firstly, logical blocks' state bitmap is set when allocation
 * takes place. But table->lblk2off array contains U16_MAX for
 * this logical block number. It means that logical block was
 * allocated but it doesn't correspond to any physical offset
 * ID. Secondly, it needs to provide every call of
 * ssdfs_blk2off_table_change_offset() with peb_index value.
 * In such situation the method sets correspondence between
 * logical block and physical offset ID.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for this change yet.
 * %-ENODATA    - table doesn't contain logical block.
 * %-ENOENT     - table's fragment for requested logical block not initialized
 */
int ssdfs_blk2off_table_change_offset(struct ssdfs_blk2off_table *table,
				      u16 logical_blk,
				      u16 peb_index,
				      struct ssdfs_block_descriptor *blk_desc,
				      struct ssdfs_phys_offset_descriptor *off)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment;
	struct ssdfs_offset_position pos = {0};
	u16 last_sequence_id = SSDFS_INVALID_FRAG_ID;
	void *kaddr;
	u16 capacity;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !off);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("table %p, logical_blk %u, peb_index %u, "
		  "off->page_desc.logical_offset %u, "
		  "off->page_desc.logical_blk %u, "
		  "off->page_desc.peb_page %u, "
		  "off->blk_state.log_start_page %u, "
		  "off->blk_state.log_area %u, "
		  "off->blk_state.peb_migration_id %u, "
		  "off->blk_state.byte_offset %u\n",
		  table, logical_blk, peb_index,
		  le32_to_cpu(off->page_desc.logical_offset),
		  le16_to_cpu(off->page_desc.logical_blk),
		  le16_to_cpu(off->page_desc.peb_page),
		  le16_to_cpu(off->blk_state.log_start_page),
		  off->blk_state.log_area,
		  off->blk_state.peb_migration_id,
		  le32_to_cpu(off->blk_state.byte_offset));
#else
	SSDFS_DBG("table %p, logical_blk %u, peb_index %u, "
		  "off->page_desc.logical_offset %u, "
		  "off->page_desc.logical_blk %u, "
		  "off->page_desc.peb_page %u, "
		  "off->blk_state.log_start_page %u, "
		  "off->blk_state.log_area %u, "
		  "off->blk_state.peb_migration_id %u, "
		  "off->blk_state.byte_offset %u\n",
		  table, logical_blk, peb_index,
		  le32_to_cpu(off->page_desc.logical_offset),
		  le16_to_cpu(off->page_desc.logical_blk),
		  le16_to_cpu(off->page_desc.peb_page),
		  le16_to_cpu(off->blk_state.log_start_page),
		  off->blk_state.log_area,
		  off->blk_state.peb_migration_id,
		  le32_to_cpu(off->blk_state.byte_offset));
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (peb_index >= table->pebs_count) {
		SSDFS_ERR("fail to change offset value: "
			  "peb_index %u >= pebs_count %u\n",
			  peb_index, table->pebs_count);
		return -EINVAL;
	}

	down_write(&table->translation_lock);

	if (logical_blk >= table->lblk2off_capacity) {
		err = -EINVAL;
		SSDFS_ERR("fail to convert logical block: "
			  "block %u >= capacity %u\n",
			  logical_blk,
			  table->lblk2off_capacity);
		goto finish_table_modification;
	}

	capacity = table->lblk2off_capacity;

	if (atomic_read(&table->state) <= SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
		if (ssdfs_blk2off_table_bmap_vacant(&table->lbmap,
						    SSDFS_LBMAP_INIT_INDEX,
						    capacity,
						    logical_blk)) {
			err = -EAGAIN;
			SSDFS_DBG("table is not initialized yet: "
				  "logical_blk %u\n",
				  logical_blk);
			goto finish_table_modification;
		}
	}

	if (ssdfs_blk2off_table_bmap_vacant(&table->lbmap,
					    SSDFS_LBMAP_STATE_INDEX,
					    capacity,
					    logical_blk)) {
		err = -ENODATA;
		SSDFS_ERR("logical block is not allocated yet: "
			  "logical_blk %u\n",
			  logical_blk);
		goto finish_table_modification;
	}

	err = ssdfs_blk2off_table_assign_id(table, logical_blk,
					    peb_index, blk_desc,
					    &last_sequence_id);
	if (err == -ENOSPC) {
		err = ssdfs_blk2off_table_add_fragment(table, peb_index,
							last_sequence_id);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add fragment: "
				  "peb_index %u, err %d\n",
				  peb_index, err);
			goto finish_table_modification;
		}

		err = ssdfs_blk2off_table_assign_id(table, logical_blk,
						    peb_index, blk_desc,
						    &last_sequence_id);
		if (unlikely(err)) {
			SSDFS_ERR("fail to assign id: "
				  "peb_index %u, logical_blk %u, err %d\n",
				  peb_index, logical_blk, err);
			goto finish_table_modification;
		}
	} else if (err == -ENOENT) {
		SSDFS_DBG("meet unintialized fragment: "
			  "peb_index %u, logical_blk %u\n",
			  peb_index, logical_blk);
		goto finish_table_modification;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to assign id: "
			  "peb_index %u, logical_blk %u, err %d\n",
			  peb_index, logical_blk, err);
		goto finish_table_modification;
	}

	err = ssdfs_blk2off_table_get_checked_position(table, logical_blk,
							&pos);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get checked offset's position: "
			  "logical_block %u, err %d\n",
			  logical_blk, err);
		goto finish_table_modification;
	}

	phys_off_table = &table->peb[peb_index];

	sequence = phys_off_table->sequence;
	kaddr = ssdfs_sequence_array_get_item(sequence, pos.sequence_id);
	if (IS_ERR_OR_NULL(kaddr)) {
		err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  pos.sequence_id, err);
		goto finish_table_modification;
	}
	fragment = (struct ssdfs_phys_offset_table_fragment *)kaddr;

	down_write(&fragment->lock);

	err = ssdfs_blk2off_table_check_fragment_desc(table, fragment, &pos);
	if (unlikely(err)) {
		SSDFS_ERR("invalid fragment description: err %d\n", err);
		goto finish_fragment_modification;
	}

	err = ssdfs_blk2off_table_bmap_set(&table->lbmap,
					   SSDFS_LBMAP_MODIFICATION_INDEX,
					   logical_blk);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set bitmap: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		goto finish_fragment_modification;
	}

	downgrade_write(&table->translation_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("logical_blk %u, POS: cno %llu, id %u, "
		  "peb_index %u, sequence_id %u, offset_index %u\n",
		  logical_blk, pos.cno, pos.id, pos.peb_index,
		  pos.sequence_id, pos.offset_index);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_memcpy(&fragment->phys_offs[pos.offset_index],
		     0, sizeof(struct ssdfs_phys_offset_descriptor),
		     off, 0, sizeof(struct ssdfs_phys_offset_descriptor),
		     sizeof(struct ssdfs_phys_offset_descriptor));

	ssdfs_table_fragment_set_dirty(table, peb_index, pos.sequence_id);

	up_write(&fragment->lock);
	up_read(&table->translation_lock);

	wake_up_all(&table->wait_queue);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;

finish_fragment_modification:
	up_write(&fragment->lock);

finish_table_modification:
	up_write(&table->translation_lock);

	wake_up_all(&table->wait_queue);

	return err;
}

/*
 * ssdfs_blk2off_table_bmap_allocate() - find vacant and set logical block
 * @lbmap: bitmap array pointer
 * @bitmap_index: index of bitmap in array
 * @start_blk: start block for search
 * @len: requested length
 * @max_blks: upper bound for search
 * @extent: pointer on found extent of logical blocks [out]
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EAGAIN     - allocated extent hasn't requested length.
 * %-ENODATA    - unable to allocate.
 */
static inline
int ssdfs_blk2off_table_bmap_allocate(struct ssdfs_bitmap_array *lbmap,
					int bitmap_index,
					u16 start_blk, u16 len,
					u16 max_blks,
					struct ssdfs_blk2off_range *extent)
{
	unsigned long found, end;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap || !extent);

	SSDFS_DBG("lbmap %p, bitmap_index %d, "
		  "start_blk %u, len %u, "
		  "max_blks %u, extent %p\n",
		  lbmap, bitmap_index,
		  start_blk, len, max_blks, extent);
#endif /* CONFIG_SSDFS_DEBUG */

	if (bitmap_index >= SSDFS_LBMAP_ARRAY_MAX) {
		SSDFS_ERR("invalid bitmap index %d\n",
			  bitmap_index);
		return -EINVAL;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap->array[bitmap_index]);
#endif /* CONFIG_SSDFS_DEBUG */

	len = min_t(u16, len, max_blks);

	found = find_next_zero_bit(lbmap->array[bitmap_index],
				   lbmap->bits_count, start_blk);
	if (found >= lbmap->bits_count) {
		if (lbmap->bits_count >= max_blks) {
			SSDFS_DBG("unable to allocate\n");
			return -ENODATA;
		}

		err = ssdfs_blk2off_table_resize_bitmap_array(lbmap,
							lbmap->bits_count);
		if (unlikely(err)) {
			SSDFS_ERR("fail to realloc bitmap array: "
				  "err %d\n", err);
			return err;
		}

		found = find_next_zero_bit(lbmap->array[bitmap_index],
					   lbmap->bits_count, start_blk);
		if (found >= lbmap->bits_count) {
			SSDFS_ERR("unable to allocate\n");
			return -ENODATA;
		}
	}
	BUG_ON(found >= U16_MAX);

	if (found >= max_blks) {
		SSDFS_DBG("unable to allocate\n");
		return -ENODATA;
	}

	end = min_t(unsigned long, found + len, (unsigned long)max_blks);

	SSDFS_DBG("found %lu, len %u, max_blks %u, end %lu\n",
		  found, len, max_blks, end);

	end = find_next_bit(lbmap->array[bitmap_index],
			    end, found);

	SSDFS_DBG("found %lu, end %lu\n",
		  found, end);

	extent->start_lblk = (u16)found;
	extent->len = (u16)(end - found);

	if (extent->len < len && lbmap->bits_count < max_blks) {
		err = ssdfs_blk2off_table_resize_bitmap_array(lbmap, end);
		if (unlikely(err)) {
			SSDFS_ERR("fail to realloc bitmap array: "
				  "err %d\n", err);
			return err;
		}

		end = find_next_bit(lbmap->array[bitmap_index],
				    end, found);
	}

	extent->start_lblk = (u16)found;
	extent->len = (u16)(end - found);

	bitmap_set(lbmap->array[bitmap_index], extent->start_lblk, extent->len);

	SSDFS_DBG("found extent (start %u, len %u)\n",
		  extent->start_lblk, extent->len);

	if (extent->len < len)
		return -EAGAIN;

	return 0;
}

/*
 * ssdfs_blk2off_table_allocate_extent() - allocate vacant extent
 * @table: pointer on table object
 * @len: requested length
 * @extent: pointer on found extent [out]
 *
 * This method tries to allocate vacant extent.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for this change yet.
 * %-ENODATA    - bitmap hasn't vacant logical blocks.
 */
int ssdfs_blk2off_table_allocate_extent(struct ssdfs_blk2off_table *table,
					u16 len,
					struct ssdfs_blk2off_range *extent)
{
	void *kaddr;
	size_t off_pos_size = sizeof(struct ssdfs_offset_position);
	u16 start_blk = 0;
	u16 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !extent);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("table %p, len %u, extent %p, "
		  "used_logical_blks %u, free_logical_blks %u, "
		  "last_allocated_blk %u\n",
		  table, len, extent,
		  table->used_logical_blks,
		  table->free_logical_blks,
		  table->last_allocated_blk);
#else
	SSDFS_DBG("table %p, len %u, extent %p, "
		  "used_logical_blks %u, free_logical_blks %u, "
		  "last_allocated_blk %u\n",
		  table, len, extent,
		  table->used_logical_blks,
		  table->free_logical_blks,
		  table->last_allocated_blk);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (atomic_read(&table->state) <= SSDFS_BLK2OFF_OBJECT_CREATED) {
		SSDFS_DBG("unable to allocate before initialization\n");
		return -EAGAIN;
	}

	down_write(&table->translation_lock);

	if (table->free_logical_blks == 0) {
		if (table->used_logical_blks != table->lblk2off_capacity) {
			err = -ERANGE;
			SSDFS_ERR("used_logical_blks %u != capacity %u\n",
				  table->used_logical_blks,
				  table->lblk2off_capacity);
		} else {
			err = -ENODATA;
			SSDFS_DBG("bitmap hasn't vacant logical blocks\n");
		}
		goto finish_allocation;
	}

	if (atomic_read(&table->state) == SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
		u16 capacity = table->lblk2off_capacity;
		bool is_vacant;

		start_blk = table->last_allocated_blk;
		is_vacant = ssdfs_blk2off_table_bmap_vacant(&table->lbmap,
							SSDFS_LBMAP_INIT_INDEX,
							capacity,
							start_blk);

		if (is_vacant) {
			start_blk = table->used_logical_blks;
			if (start_blk > 0)
				start_blk--;

			is_vacant =
			    ssdfs_blk2off_table_bmap_vacant(&table->lbmap,
							SSDFS_LBMAP_INIT_INDEX,
							capacity,
							start_blk);
		}

		if (is_vacant) {
			err = -EAGAIN;
			SSDFS_DBG("table is not initialized yet\n");
			goto finish_allocation;
		}
	}

	err = ssdfs_blk2off_table_bmap_allocate(&table->lbmap,
						SSDFS_LBMAP_STATE_INDEX,
						start_blk, len,
						table->lblk2off_capacity,
						extent);
	if (err == -EAGAIN) {
		err = 0;
		SSDFS_DBG("requested extent doesn't allocated fully\n");
		goto finish_allocation;
	} else if (err == -ENODATA)
		goto try_next_range;
	else if (unlikely(err)) {
		SSDFS_ERR("fail to find vacant extent: err %d\n",
			  err);
		goto finish_allocation;
	} else
		goto save_found_extent;

try_next_range:
	if (atomic_read(&table->state) < SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT) {
		err = -EAGAIN;
		SSDFS_DBG("table is not initialized yet\n");
		goto finish_allocation;
	}

	err = ssdfs_blk2off_table_bmap_allocate(&table->lbmap,
						SSDFS_LBMAP_STATE_INDEX,
						0, len, start_blk,
						extent);
	if (err == -EAGAIN) {
		err = 0;
		SSDFS_DBG("requested extent doesn't allocated fully\n");
		goto finish_allocation;
	} else if (err == -ENODATA) {
		SSDFS_DBG("bitmap hasn't vacant logical blocks\n");
		goto finish_allocation;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find vacant extent: err %d\n",
			  err);
		goto finish_allocation;
	}

save_found_extent:
	for (i = 0; i < extent->len; i++) {
		u16 blk = extent->start_lblk + i;

		kaddr = ssdfs_dynamic_array_get_locked(&table->lblk2off, blk);
		if (IS_ERR_OR_NULL(kaddr)) {
			err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
			SSDFS_ERR("fail to get logical block: "
				  "blk %u, extent (start %u, len %u), "
				  "err %d\n",
				  blk, extent->start_lblk,
				  extent->len, err);
			goto finish_allocation;
		}

		memset(kaddr, 0xFF, off_pos_size);

		err = ssdfs_dynamic_array_release(&table->lblk2off,
						  blk, kaddr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to release: "
				  "blk %u, extent (start %u, len %u), "
				  "err %d\n",
				  blk, extent->start_lblk,
				  extent->len, err);
			goto finish_allocation;
		}
	}

	BUG_ON(table->used_logical_blks > (U16_MAX - extent->len));
	BUG_ON((table->used_logical_blks + extent->len) >
		table->lblk2off_capacity);
	table->used_logical_blks += extent->len;

	BUG_ON(extent->len > table->free_logical_blks);
	table->free_logical_blks -= extent->len;

	BUG_ON(extent->len == 0);
	table->last_allocated_blk = extent->start_lblk + extent->len - 1;

finish_allocation:
	up_write(&table->translation_lock);

	if (!err) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("extent (start %u, len %u) has been allocated\n",
			  extent->start_lblk, extent->len);
#endif /* CONFIG_SSDFS_DEBUG */
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_debug_blk2off_table_object(table);

	return err;
}

/*
 * ssdfs_blk2off_table_allocate_block() - allocate vacant logical block
 * @table: pointer on table object
 * @logical_blk: pointer on found logical block value [out]
 *
 * This method tries to allocate vacant logical block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for this change yet.
 * %-ENODATA    - bitmap hasn't vacant logical blocks.
 */
int ssdfs_blk2off_table_allocate_block(struct ssdfs_blk2off_table *table,
					u16 *logical_blk)
{
	struct ssdfs_blk2off_range extent = {0};
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !logical_blk);

	SSDFS_DBG("table %p, logical_blk %p, "
		  "used_logical_blks %u, free_logical_blks %u, "
		  "last_allocated_blk %u\n",
		  table, logical_blk,
		  table->used_logical_blks,
		  table->free_logical_blks,
		  table->last_allocated_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_blk2off_table_allocate_extent(table, 1, &extent);
	if (err) {
		SSDFS_ERR("fail to allocate logical block: err %d\n",
			  err);
		SSDFS_ERR("used_logical_blks %u, free_logical_blks %u, "
			  "last_allocated_blk %u\n",
			  table->used_logical_blks,
			  table->free_logical_blks,
			  table->last_allocated_blk);
		return err;
	} else if (extent.start_lblk >= table->lblk2off_capacity ||
		   extent.len != 1) {
		SSDFS_ERR("invalid extent (start %u, len %u)\n",
			  extent.start_lblk, extent.len);
		return -ERANGE;
	}

	*logical_blk = extent.start_lblk;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("logical block %u has been allocated\n",
		  *logical_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_blk2off_table_free_extent() - free extent
 * @table: pointer on table object
 * @peb_index: PEB's index
 * @extent: pointer on extent
 *
 * This method tries to free extent of logical blocks.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for this change yet.
 * %-ENOENT     - logical block isn't allocated yet.
 */
int ssdfs_blk2off_table_free_extent(struct ssdfs_blk2off_table *table,
				    u16 peb_index,
				    struct ssdfs_blk2off_range *extent)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment;
	struct ssdfs_phys_offset_descriptor off;
	u16 last_sequence_id = SSDFS_INVALID_FRAG_ID;
	struct ssdfs_offset_position pos = {0};
	void *old_pos;
	size_t desc_size = sizeof(struct ssdfs_offset_position);
	struct ssdfs_block_descriptor blk_desc = {0};
	bool is_vacant;
	u16 end_lblk;
	int state;
	void *kaddr;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !extent);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("table %p, extent (start %u, len %u)\n",
		  table, extent->start_lblk, extent->len);
#else
	SSDFS_DBG("table %p, extent (start %u, len %u)\n",
		  table, extent->start_lblk, extent->len);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (atomic_read(&table->state) <= SSDFS_BLK2OFF_OBJECT_CREATED) {
		SSDFS_DBG("unable to free before initialization: "
			  "extent (start %u, len %u)\n",
			  extent->start_lblk, extent->len);
		return -EAGAIN;
	}

	memset(&blk_desc, 0xFF, sizeof(struct ssdfs_block_descriptor));

	down_write(&table->translation_lock);

	BUG_ON(table->lblk2off_capacity > (U16_MAX - extent->len));
	BUG_ON(table->used_logical_blks > table->lblk2off_capacity);

	if ((extent->start_lblk + extent->len) > table->lblk2off_capacity) {
		err = -EINVAL;
		SSDFS_ERR("fail to free extent (start %u, len %u)\n",
			  extent->start_lblk, extent->len);
		goto finish_freeing;
	}

	state = atomic_read(&table->state);
	if (state == SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
		is_vacant = ssdfs_blk2off_table_extent_vacant(&table->lbmap,
						      SSDFS_LBMAP_INIT_INDEX,
						      table->lblk2off_capacity,
						      extent);

		if (is_vacant) {
			err = -EAGAIN;
			SSDFS_DBG("unable to free before initialization: "
				  "extent (start %u, len %u)\n",
				  extent->start_lblk, extent->len);
			goto finish_freeing;
		}
	}

	is_vacant = ssdfs_blk2off_table_extent_vacant(&table->lbmap,
						      SSDFS_LBMAP_STATE_INDEX,
						      table->lblk2off_capacity,
						      extent);
	if (is_vacant) {
		err = -ENOENT;
		SSDFS_WARN("extent (start %u, len %u) "
			   "doesn't allocated yet\n",
			   extent->start_lblk, extent->len);
		goto finish_freeing;
	}

	end_lblk = extent->start_lblk + extent->len;
	for (i = extent->start_lblk; i < end_lblk; i++) {
		old_pos = ssdfs_dynamic_array_get_locked(&table->lblk2off, i);
		if (IS_ERR_OR_NULL(old_pos)) {
			err = (old_pos == NULL ? -ENOENT : PTR_ERR(old_pos));
			SSDFS_ERR("fail to get logical block: "
				  "blk %u, err %d\n",
				  i, err);
			goto finish_freeing;
		}

		if (SSDFS_OFF_POS(old_pos)->id == U16_MAX) {
			SSDFS_WARN("logical block %d hasn't associated ID\n",
				   i);
		}

		err = ssdfs_dynamic_array_release(&table->lblk2off,
						  i, old_pos);
		if (unlikely(err)) {
			SSDFS_ERR("fail to release: "
				  "blk %u, err %d\n",
				  i, err);
			goto finish_freeing;
		}

		err = ssdfs_blk2off_table_assign_id(table, i, peb_index,
						    &blk_desc,
						    &last_sequence_id);
		if (err == -ENOSPC) {
			err = ssdfs_blk2off_table_add_fragment(table, peb_index,
							last_sequence_id);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add fragment: "
					  "peb_index %u, err %d\n",
					  peb_index, err);
				goto finish_freeing;
			}

			err = ssdfs_blk2off_table_assign_id(table, i,
							    peb_index,
							    &blk_desc,
							    &last_sequence_id);
			if (unlikely(err)) {
				SSDFS_ERR("fail to assign id: "
					  "peb_index %u, logical_blk %u, "
					  "err %d\n",
					  peb_index, i, err);
				goto finish_freeing;
			}
		} else if (err == -ENOENT) {
			SSDFS_DBG("meet unintialized fragment: "
				  "peb_index %u, logical_blk %u\n",
				  peb_index, i);
			goto finish_freeing;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to assign id: "
				  "peb_index %u, logical_blk %u, err %d\n",
				  peb_index, i, err);
			goto finish_freeing;
		}

		err = ssdfs_blk2off_table_get_checked_position(table, (u16)i,
								&pos);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get checked offset's position: "
				  "logical_block %d, err %d\n",
				  i, err);
			goto finish_freeing;
		}

		phys_off_table = &table->peb[peb_index];

		sequence = phys_off_table->sequence;
		kaddr = ssdfs_sequence_array_get_item(sequence,
							pos.sequence_id);
		if (IS_ERR_OR_NULL(kaddr)) {
			err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
			SSDFS_ERR("fail to get fragment: "
				  "sequence_id %u, err %d\n",
				  pos.sequence_id, err);
			goto finish_freeing;
		}
		fragment = (struct ssdfs_phys_offset_table_fragment *)kaddr;

		down_write(&fragment->lock);

		err = ssdfs_blk2off_table_check_fragment_desc(table, fragment,
								&pos);
		if (unlikely(err)) {
			SSDFS_ERR("invalid fragment description: err %d\n",
				  err);
			goto finish_fragment_modification;
		}

		ssdfs_blk2off_table_bmap_clear(&table->lbmap,
						SSDFS_LBMAP_STATE_INDEX,
						(u16)i);
		ssdfs_blk2off_table_bmap_set(&table->lbmap,
					     SSDFS_LBMAP_MODIFICATION_INDEX,
					     (u16)i);

		off.page_desc.logical_offset = cpu_to_le32(U32_MAX);
		off.page_desc.logical_blk = cpu_to_le16((u16)i);
		off.page_desc.peb_page = cpu_to_le16(U16_MAX);
		off.blk_state.log_start_page = cpu_to_le16(U16_MAX);
		off.blk_state.log_area = U8_MAX;
		off.blk_state.peb_migration_id = U8_MAX;
		off.blk_state.byte_offset = cpu_to_le32(U32_MAX);

		ssdfs_memcpy(&fragment->phys_offs[pos.offset_index],
			     0, sizeof(struct ssdfs_phys_offset_descriptor),
			     &off,
			     0, sizeof(struct ssdfs_phys_offset_descriptor),
			     sizeof(struct ssdfs_phys_offset_descriptor));

		ssdfs_table_fragment_set_dirty(table, peb_index,
						pos.sequence_id);

finish_fragment_modification:
		up_write(&fragment->lock);

		if (unlikely(err))
			goto finish_freeing;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("BEFORE: logical_blk %d, pos (cno %llx, id %u, "
			  "sequence_id %u, offset_index %u)\n",
			  i, pos.cno, pos.id, pos.sequence_id,
			  pos.offset_index);
#endif /* CONFIG_SSDFS_DEBUG */

		pos.cno = ssdfs_current_cno(table->fsi->sb);
		pos.id = SSDFS_BLK2OFF_TABLE_INVALID_ID;
		pos.offset_index = U16_MAX;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("AFTER: logical_blk %d, pos (cno %llx, id %u, "
			  "sequence_id %u, offset_index %u)\n",
			  i, pos.cno, pos.id, pos.sequence_id,
			  pos.offset_index);
#endif /* CONFIG_SSDFS_DEBUG */

		old_pos = ssdfs_dynamic_array_get_locked(&table->lblk2off, i);
		if (IS_ERR_OR_NULL(kaddr)) {
			err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
			SSDFS_ERR("fail to get logical block: "
				  "blk %u, err %d\n",
				  i, err);
			goto finish_freeing;
		}

		err = ssdfs_memcpy(old_pos, 0, desc_size,
				   &pos, 0, desc_size,
				   desc_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n",
				  err);
			goto finish_freeing;
		}

		err = ssdfs_dynamic_array_release(&table->lblk2off,
						  i, kaddr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to release: "
				  "blk %u, err %d\n",
				  i, err);
			goto finish_freeing;
		}

		BUG_ON(table->used_logical_blks == 0);
		table->used_logical_blks--;
		BUG_ON(table->free_logical_blks == U16_MAX);
		table->free_logical_blks++;
	}

finish_freeing:
	up_write(&table->translation_lock);

	if (!err) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("extent (start %u, len %u) has been freed\n",
			  extent->start_lblk, extent->len);
#endif /* CONFIG_SSDFS_DEBUG */
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	wake_up_all(&table->wait_queue);

	return err;
}

/*
 * ssdfs_blk2off_table_free_block() - free logical block
 * @table: pointer on table object
 * @peb_index: PEB's index
 * @logical_blk: logical block number
 *
 * This method tries to free logical block number.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for this change yet.
 * %-ENOENT     - logical block isn't allocated yet.
 */
int ssdfs_blk2off_table_free_block(struct ssdfs_blk2off_table *table,
				   u16 peb_index,
				   u16 logical_blk)
{
	struct ssdfs_blk2off_range extent = {
		.start_lblk = logical_blk,
		.len = 1,
	};
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);

	SSDFS_DBG("table %p, logical_blk %u\n",
		  table, logical_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_blk2off_table_free_extent(table, peb_index, &extent);
	if (err) {
		SSDFS_ERR("fail to free logical block %u: err %d\n",
			  logical_blk, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("logical block %u has been freed\n",
		  logical_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_blk2off_table_set_block_migration() - set block migration
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @peb_index: PEB index in the segment
 * @req: request's result with block's content
 *
 * This method tries to set migration state for logical block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for this change yet.
 */
int ssdfs_blk2off_table_set_block_migration(struct ssdfs_blk2off_table *table,
					    u16 logical_blk,
					    u16 peb_index,
					    struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_migrating_block *blk = NULL;
	u32 pages_per_lblk;
	u32 start_page;
	u32 count;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, logical_blk %u, peb_index %u, req %p\n",
		  table, logical_blk, peb_index, req);

	fsi = table->fsi;
	pages_per_lblk = fsi->pagesize >> PAGE_SHIFT;

	if (peb_index >= table->pebs_count) {
		SSDFS_ERR("fail to set block migration: "
			  "peb_index %u >= pebs_count %u\n",
			  peb_index, table->pebs_count);
		return -EINVAL;
	}

	if (logical_blk < req->place.start.blk_index ||
	    logical_blk >= (req->place.start.blk_index + req->place.len)) {
		SSDFS_ERR("inconsistent request: "
			  "logical_blk %u, "
			  "request (start_blk %u, len %u)\n",
			  logical_blk,
			  req->place.start.blk_index,
			  req->place.len);
		return -EINVAL;
	}

	count = pagevec_count(&req->result.pvec);
	if (count % pages_per_lblk) {
		SSDFS_ERR("inconsistent request: "
			  "pagevec count %u, "
			  "pages_per_lblk %u, req->place.len %u\n",
			  count, pages_per_lblk, req->place.len);
		return -EINVAL;
	}

	down_write(&table->translation_lock);

	if (logical_blk > table->last_allocated_blk) {
		err = -EINVAL;
		SSDFS_ERR("fail to set block migrating: "
			  "block %u > last_allocated_block %u\n",
			  logical_blk,
			  table->last_allocated_blk);
		goto finish_set_block_migration;
	}

	if (atomic_read(&table->state) <= SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
		u16 capacity = table->lblk2off_capacity;

		if (ssdfs_blk2off_table_bmap_vacant(&table->lbmap,
						    SSDFS_LBMAP_INIT_INDEX,
						    capacity,
						    logical_blk)) {
			err = -EAGAIN;
			SSDFS_DBG("table is not initialized yet: "
				  "logical_blk %u\n",
				  logical_blk);
			goto finish_set_block_migration;
		}
	}

	blk = ssdfs_get_migrating_block(table, logical_blk, true);
	if (IS_ERR_OR_NULL(blk)) {
		err = (blk == NULL ? -ENOENT : PTR_ERR(blk));
		SSDFS_ERR("fail to get migrating block: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		goto finish_set_block_migration;
	}

	switch (blk->state) {
	case SSDFS_LBLOCK_UNKNOWN_STATE:
		/* expected state */
		break;

	case SSDFS_LBLOCK_UNDER_MIGRATION:
	case SSDFS_LBLOCK_UNDER_COMMIT:
		err = -ERANGE;
		SSDFS_WARN("logical_blk %u is under migration already\n",
			  logical_blk);
		goto finish_set_block_migration;

	default:
		err = -ERANGE;
		SSDFS_ERR("unexpected state %#x\n",
			  blk->state);
		goto finish_set_block_migration;
	}

	pagevec_init(&blk->pvec);

	start_page = logical_blk - req->place.start.blk_index;
	for (i = start_page; i < (start_page + pages_per_lblk); i++) {
		struct page *page;
#ifdef CONFIG_SSDFS_DEBUG
		void *kaddr;

		SSDFS_DBG("start_page %u, logical_blk %u, "
			  "blk_index %u, i %d, "
			  "pagevec_count %u\n",
			  start_page, logical_blk,
			  req->place.start.blk_index,
			  i,
			  pagevec_count(&req->result.pvec));
#endif /* CONFIG_SSDFS_DEBUG */

		page = ssdfs_blk2off_alloc_page(GFP_KERNEL);
		if (IS_ERR_OR_NULL(page)) {
			err = (page == NULL ? -ENOMEM : PTR_ERR(page));
			SSDFS_ERR("unable to allocate #%d memory page\n", i);
			ssdfs_blk2off_pagevec_release(&blk->pvec);
			goto finish_set_block_migration;
		}

		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(i >= pagevec_count(&req->result.pvec));
		BUG_ON(!req->result.pvec.pages[i]);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_memcpy_page(page, 0, PAGE_SIZE,
				  req->result.pvec.pages[i], 0, PAGE_SIZE,
				  PAGE_SIZE);

#ifdef CONFIG_SSDFS_DEBUG
		kaddr = kmap_local_page(req->result.pvec.pages[i]);
		SSDFS_DBG("BLOCK STATE DUMP: page_index %d\n", i);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr, PAGE_SIZE);
		SSDFS_DBG("\n");
		kunmap_local(kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

		pagevec_add(&blk->pvec, page);
	}

	blk->state = SSDFS_LBLOCK_UNDER_MIGRATION;
	blk->peb_index = peb_index;

finish_set_block_migration:
	up_write(&table->translation_lock);

	if (!err) {
		SSDFS_DBG("logical_blk %u is under migration: "
			  "(peb_index %u, state %#x)\n",
			  logical_blk, peb_index, blk->state);
	}

	return err;
}

/*
 * ssdfs_blk2off_table_get_block_migration() - get block's migration state
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @peb_index: PEB index
 *
 * This method tries to get the migration state of logical block.
 *
 */
int ssdfs_blk2off_table_get_block_migration(struct ssdfs_blk2off_table *table,
					    u16 logical_blk,
					    u16 peb_index)
{
	struct ssdfs_migrating_block *blk = NULL;
	int migration_state = SSDFS_LBLOCK_UNKNOWN_STATE;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, logical_blk %u, peb_index %u\n",
		  table, logical_blk, peb_index);

	blk = ssdfs_get_migrating_block(table, logical_blk, false);
	if (IS_ERR_OR_NULL(blk))
		migration_state = SSDFS_LBLOCK_UNKNOWN_STATE;
	else
		migration_state = blk->state;

	SSDFS_DBG("logical_blk %u, migration_state %#x\n",
		  logical_blk, migration_state);

	return migration_state;
}

/*
 * ssdfs_blk2off_table_get_block_state() - get state migrating block
 * @table: pointer on table object
 * @req: segment request [in|out]
 *
 * This method tries to get the state of logical block under migration.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - logical block is not migrating.
 * %-ENOMEM     - fail to allocate memory.
 */
int ssdfs_blk2off_table_get_block_state(struct ssdfs_blk2off_table *table,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	u16 logical_blk;
	struct ssdfs_migrating_block *blk = NULL;
	u32 read_bytes;
	int start_page;
	u32 data_bytes = 0;
	int processed_blks;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, req %p\n",
		  table, req);

	fsi = table->fsi;
	read_bytes = req->result.processed_blks * fsi->pagesize;
	start_page = (int)(read_bytes >> PAGE_SHIFT);
	BUG_ON(start_page >= U16_MAX);

	if (pagevec_count(&req->result.pvec) <= start_page) {
		SSDFS_ERR("page_index %d >= pagevec_count %u\n",
			  start_page,
			  pagevec_count(&req->result.pvec));
		return -ERANGE;
	}

	logical_blk = req->place.start.blk_index + req->result.processed_blks;

	down_read(&table->translation_lock);

	if (logical_blk > table->last_allocated_blk) {
		err = -EINVAL;
		SSDFS_ERR("fail to get migrating block: "
			  "block %u > last_allocated_block %u\n",
			  logical_blk,
			  table->last_allocated_blk);
		goto finish_get_block_state;
	}

	blk = ssdfs_get_migrating_block(table, logical_blk, false);
	if (IS_ERR_OR_NULL(blk)) {
		err = -EAGAIN;
		goto finish_get_block_state;
	}

	switch (blk->state) {
	case SSDFS_LBLOCK_UNDER_MIGRATION:
	case SSDFS_LBLOCK_UNDER_COMMIT:
		/* expected state */
		break;

	case SSDFS_LBLOCK_UNKNOWN_STATE:
		err = -EAGAIN;
		goto finish_get_block_state;

	default:
		err = -ERANGE;
		SSDFS_ERR("unexpected state %#x\n",
			  blk->state);
		goto finish_get_block_state;
	}

	SSDFS_DBG("logical_blk %u, state %#x\n",
		  logical_blk, blk->state);

	if (pagevec_count(&blk->pvec) == (fsi->pagesize >> PAGE_SHIFT)) {
		SSDFS_DBG("logical_blk %u, blk pagevec count %u\n",
			  logical_blk, pagevec_count(&blk->pvec));
	} else {
		SSDFS_WARN("logical_blk %u, blk pagevec count %u\n",
			  logical_blk, pagevec_count(&blk->pvec));
	}

	for (i = 0; i < pagevec_count(&blk->pvec); i++) {
		int page_index = start_page + i;
		struct page *page;
#ifdef CONFIG_SSDFS_DEBUG
		void *kaddr;

		SSDFS_DBG("index %d, read_bytes %u, "
			  "start_page %u, page_index %d\n",
			  i, read_bytes, start_page, page_index);
#endif /* CONFIG_SSDFS_DEBUG */

		if (page_index >= pagevec_count(&req->result.pvec)) {
			err = -ERANGE;
			SSDFS_ERR("page_index %d >= count %d\n",
				  page_index,
				  pagevec_count(&req->result.pvec));
			goto finish_get_block_state;
		}

		page = req->result.pvec.pages[page_index];
		ssdfs_lock_page(blk->pvec.pages[i]);

		ssdfs_memcpy_page(page, 0, PAGE_SIZE,
				  blk->pvec.pages[i], 0, PAGE_SIZE,
				  PAGE_SIZE);

#ifdef CONFIG_SSDFS_DEBUG
		kaddr = kmap_local_page(blk->pvec.pages[i]);
		SSDFS_DBG("BLOCK STATE DUMP: page_index %d\n", i);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr, PAGE_SIZE);
		SSDFS_DBG("\n");
		kunmap_local(kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_unlock_page(blk->pvec.pages[i]);
		SetPageUptodate(page);

		data_bytes += PAGE_SIZE;
	}

finish_get_block_state:
	up_read(&table->translation_lock);

	if (!err) {
		processed_blks =
			(data_bytes + fsi->pagesize - 1) >> fsi->log_pagesize;
		req->result.processed_blks += processed_blks;
	}

	return err;
}

/*
 * ssdfs_blk2off_table_update_block_state() - update state migrating block
 * @table: pointer on table object
 * @req: segment request [in|out]
 *
 * This method tries to update the state of logical block under migration.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal logic error.
 * %-ENOENT     - logical block is not migrating.
 * %-ENOMEM     - fail to allocate memory.
 */
int ssdfs_blk2off_table_update_block_state(struct ssdfs_blk2off_table *table,
					   struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	u16 logical_blk;
	struct ssdfs_migrating_block *blk = NULL;
	u32 read_bytes;
	int start_page;
	u32 data_bytes = 0;
	int processed_blks;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !req);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, req %p\n",
		  table, req);

	fsi = table->fsi;
	read_bytes = req->result.processed_blks * fsi->pagesize;
	start_page = (int)(read_bytes >> PAGE_SHIFT);
	BUG_ON(start_page >= U16_MAX);

	if (pagevec_count(&req->result.pvec) <= start_page) {
		SSDFS_ERR("page_index %d >= pagevec_count %u\n",
			  start_page,
			  pagevec_count(&req->result.pvec));
		return -ERANGE;
	}

	logical_blk = req->place.start.blk_index + req->result.processed_blks;

	if (logical_blk > table->last_allocated_blk) {
		err = -EINVAL;
		SSDFS_ERR("fail to get migrating block: "
			  "block %u > last_allocated_block %u\n",
			  logical_blk,
			  table->last_allocated_blk);
		goto finish_update_block_state;
	}

	blk = ssdfs_get_migrating_block(table, logical_blk, false);
	if (IS_ERR_OR_NULL(blk)) {
		err = -ENOENT;
		goto finish_update_block_state;
	}

	switch (blk->state) {
	case SSDFS_LBLOCK_UNDER_MIGRATION:
		/* expected state */
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("unexpected state %#x\n",
			  blk->state);
		goto finish_update_block_state;
	}

	SSDFS_DBG("logical_blk %u, state %#x\n",
		  logical_blk, blk->state);

	if (pagevec_count(&blk->pvec) == (fsi->pagesize >> PAGE_SHIFT)) {
		SSDFS_DBG("logical_blk %u, blk pagevec count %u\n",
			  logical_blk, pagevec_count(&blk->pvec));
	} else {
		SSDFS_WARN("logical_blk %u, blk pagevec count %u\n",
			  logical_blk, pagevec_count(&blk->pvec));
	}

	for (i = 0; i < pagevec_count(&blk->pvec); i++) {
		int page_index = start_page + i;
		struct page *page;
#ifdef CONFIG_SSDFS_DEBUG
		void *kaddr;

		SSDFS_DBG("index %d, read_bytes %u, "
			  "start_page %u, page_index %d\n",
			  i, read_bytes, start_page, page_index);
#endif /* CONFIG_SSDFS_DEBUG */

		if (page_index >= pagevec_count(&req->result.pvec)) {
			err = -ERANGE;
			SSDFS_ERR("page_index %d >= count %d\n",
				  page_index,
				  pagevec_count(&req->result.pvec));
			goto finish_update_block_state;
		}

		page = req->result.pvec.pages[page_index];
		ssdfs_lock_page(blk->pvec.pages[i]);

		ssdfs_memcpy_page(blk->pvec.pages[i], 0, PAGE_SIZE,
				  page, 0, PAGE_SIZE,
				  PAGE_SIZE);

#ifdef CONFIG_SSDFS_DEBUG
		kaddr = kmap_local_page(blk->pvec.pages[i]);
		SSDFS_DBG("BLOCK STATE DUMP: page_index %d\n", i);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr, PAGE_SIZE);
		SSDFS_DBG("\n");
		kunmap_local(kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_unlock_page(blk->pvec.pages[i]);

		data_bytes += PAGE_SIZE;
	}

finish_update_block_state:
	if (!err) {
		processed_blks =
			(data_bytes + fsi->pagesize - 1) >> fsi->log_pagesize;
		req->result.processed_blks += processed_blks;
	}

	return err;
}

/*
 * ssdfs_blk2off_table_set_block_commit() - set block commit
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @peb_index: PEB index in the segment
 *
 * This method tries to set commit state for logical block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input
 * %-ERANGE     - internal logic error
 */
int ssdfs_blk2off_table_set_block_commit(struct ssdfs_blk2off_table *table,
					 u16 logical_blk,
					 u16 peb_index)
{
	struct ssdfs_migrating_block *blk = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, logical_blk %u, peb_index %u\n",
		  table, logical_blk, peb_index);

	if (peb_index >= table->pebs_count) {
		SSDFS_ERR("fail to set block commit: "
			  "peb_index %u >= pebs_count %u\n",
			  peb_index, table->pebs_count);
		return -EINVAL;
	}

	down_write(&table->translation_lock);

	if (logical_blk > table->last_allocated_blk) {
		err = -EINVAL;
		SSDFS_ERR("fail to set block commit: "
			  "block %u > last_allocated_block %u\n",
			  logical_blk,
			  table->last_allocated_blk);
		goto finish_set_block_commit;
	}

	blk = ssdfs_get_migrating_block(table, logical_blk, false);
	if (IS_ERR_OR_NULL(blk)) {
		err = (blk == NULL ? -ENOENT : PTR_ERR(blk));
		SSDFS_ERR("fail to get migrating block: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		goto finish_set_block_commit;
	}

	switch (blk->state) {
	case SSDFS_LBLOCK_UNDER_MIGRATION:
		/* expected state */
		break;

	case SSDFS_LBLOCK_UNDER_COMMIT:
		err = -ERANGE;
		SSDFS_ERR("logical_blk %u is under commit already\n",
			  logical_blk);
		goto finish_set_block_commit;

	default:
		err = -ERANGE;
		SSDFS_ERR("unexpected state %#x\n",
			  blk->state);
		goto finish_set_block_commit;
	}

	if (blk->peb_index != peb_index) {
		err = -ERANGE;
		SSDFS_ERR("blk->peb_index %u != peb_index %u\n",
			  blk->peb_index, peb_index);
		goto finish_set_block_commit;
	}

	blk->state = SSDFS_LBLOCK_UNDER_COMMIT;

finish_set_block_commit:
	up_write(&table->translation_lock);

	if (!err) {
		SSDFS_DBG("logical_blk %u is under commit: "
			  "(peb_index %u, state %#x)\n",
			  logical_blk, peb_index, blk->state);
	}

	return err;
}

/*
 * ssdfs_blk2off_table_revert_migration_state() - revert migration state
 * @table: pointer on table object
 * @peb_index: PEB index in the segment
 *
 * This method tries to revert migration state for logical block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input
 */
int ssdfs_blk2off_table_revert_migration_state(struct ssdfs_blk2off_table *tbl,
						u16 peb_index)
{
	struct ssdfs_migrating_block *blk = NULL;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);

	SSDFS_DBG("table %p, peb_index %u\n",
		  tbl, peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (peb_index >= tbl->pebs_count) {
		SSDFS_ERR("fail to revert migration state: "
			  "peb_index %u >= pebs_count %u\n",
			  peb_index, tbl->pebs_count);
		return -EINVAL;
	}

	down_write(&tbl->translation_lock);

	for (i = 0; i <= tbl->last_allocated_blk; i++) {
		blk = ssdfs_get_migrating_block(tbl, i, false);
		if (IS_ERR_OR_NULL(blk))
			continue;

		SSDFS_DBG("blk->peb_index %u, peb_index %u\n",
			  blk->peb_index, peb_index);

		if (blk->peb_index != peb_index)
			continue;

		if (blk->state == SSDFS_LBLOCK_UNDER_COMMIT) {
			SSDFS_DBG("reverting migration state: blk %d\n",
				  i);

			blk->state = SSDFS_LBLOCK_UNKNOWN_STATE;
			ssdfs_blk2off_pagevec_release(&blk->pvec);

			ssdfs_blk2off_kfree(blk);
			blk = NULL;

			err = ssdfs_dynamic_array_set(&tbl->migrating_blks,
							i, &blk);
			if (unlikely(err)) {
				SSDFS_ERR("fail to zero pointer: "
					  "logical_blk %d, err %d\n",
					  i, err);
				goto finish_revert_migration_state;
			}
		}
	}

finish_revert_migration_state:
	up_write(&tbl->translation_lock);

	if (!err) {
		SSDFS_DBG("migration state was reverted for peb_index %u\n",
			  peb_index);
	}

	return err;
}

static inline
int ssdfs_show_fragment_details(void *ptr)
{
	struct ssdfs_phys_offset_table_fragment *fragment;

	fragment = (struct ssdfs_phys_offset_table_fragment *)ptr;
	if (!fragment) {
		SSDFS_ERR("empty pointer on fragment\n");
		return -ERANGE;
	}

	SSDFS_DBG("fragment: "
		  "start_id %u, sequence_id %u, "
		  "id_count %d, state %#x, "
		  "hdr %p, phys_offs %p, "
		  "buf_size %zu\n",
		  fragment->start_id,
		  fragment->sequence_id,
		  atomic_read(&fragment->id_count),
		  atomic_read(&fragment->state),
		  fragment->hdr,
		  fragment->phys_offs,
		  fragment->buf_size);

	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				fragment->buf,
				fragment->buf_size);

	return 0;
}

static
void ssdfs_debug_blk2off_table_object(struct ssdfs_blk2off_table *tbl)
{
#ifdef CONFIG_SSDFS_DEBUG
	u32 items_count;
	int i;

	BUG_ON(!tbl);

	SSDFS_DBG("flags %#x, state %#x, pages_per_peb %u, "
		  "pages_per_seg %u, type %#x\n",
		  atomic_read(&tbl->flags),
		  atomic_read(&tbl->state),
		  tbl->pages_per_peb,
		  tbl->pages_per_seg,
		  tbl->type);

	SSDFS_DBG("init_cno %llu, used_logical_blks %u, "
		  "free_logical_blks %u, last_allocated_blk %u\n",
		  tbl->init_cno, tbl->used_logical_blks,
		  tbl->free_logical_blks, tbl->last_allocated_blk);

	for (i = 0; i < SSDFS_LBMAP_ARRAY_MAX; i++) {
		unsigned long *bmap = tbl->lbmap.array[i];

		SSDFS_DBG("lbmap: index %d, bmap %p\n", i, bmap);
		if (bmap) {
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
						bmap,
						tbl->lbmap.bytes_count);
		}
	}

	SSDFS_DBG("lblk2off_capacity %u, capacity %u\n",
		  tbl->lblk2off_capacity,
		  ssdfs_dynamic_array_items_count(&tbl->lblk2off));

	items_count = tbl->last_allocated_blk + 1;

	for (i = 0; i < items_count; i++) {
		void *kaddr;

		kaddr = ssdfs_dynamic_array_get_locked(&tbl->lblk2off, i);
		if (IS_ERR_OR_NULL(kaddr))
			continue;

		SSDFS_DBG("lbk2off: index %d, "
			  "cno %llu, id %u, peb_index %u, "
			  "sequence_id %u, offset_index %u\n",
			  i,
			  SSDFS_OFF_POS(kaddr)->cno,
			  SSDFS_OFF_POS(kaddr)->id,
			  SSDFS_OFF_POS(kaddr)->peb_index,
			  SSDFS_OFF_POS(kaddr)->sequence_id,
			  SSDFS_OFF_POS(kaddr)->offset_index);

		ssdfs_dynamic_array_release(&tbl->lblk2off, i, kaddr);
	}

	SSDFS_DBG("pebs_count %u\n", tbl->pebs_count);

	for (i = 0; i < tbl->pebs_count; i++) {
		struct ssdfs_phys_offset_table_array *peb = &tbl->peb[i];
		int fragments_count = atomic_read(&peb->fragment_count);

		SSDFS_DBG("peb: index %d, state %#x, "
			  "fragment_count %d, last_sequence_id %lu\n",
			  i, atomic_read(&peb->state),
			  fragments_count,
			  ssdfs_sequence_array_last_id(peb->sequence));

		ssdfs_sequence_array_apply_for_all(peb->sequence,
						ssdfs_show_fragment_details);
	}
#endif /* CONFIG_SSDFS_DEBUG */
}
