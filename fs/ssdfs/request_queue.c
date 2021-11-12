//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/request_queue.c - request queue implementation.
 *
 * Copyright (c) 2014-2021 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2021, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "request_queue.h"
#include "segment_bitmap.h"
#include "offset_translation_table.h"
#include "page_array.h"
#include "segment.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_req_queue_page_leaks;
atomic64_t ssdfs_req_queue_memory_leaks;
atomic64_t ssdfs_req_queue_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_req_queue_cache_leaks_increment(void *kaddr)
 * void ssdfs_req_queue_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_req_queue_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_req_queue_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_req_queue_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_req_queue_kfree(void *kaddr)
 * struct page *ssdfs_req_queue_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_req_queue_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_req_queue_free_page(struct page *page)
 * void ssdfs_req_queue_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(req_queue)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(req_queue)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_req_queue_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_req_queue_page_leaks, 0);
	atomic64_set(&ssdfs_req_queue_memory_leaks, 0);
	atomic64_set(&ssdfs_req_queue_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_req_queue_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_req_queue_page_leaks) != 0) {
		SSDFS_ERR("REQUESTS QUEUE: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_req_queue_page_leaks));
	}

	if (atomic64_read(&ssdfs_req_queue_memory_leaks) != 0) {
		SSDFS_ERR("REQUESTS QUEUE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_req_queue_memory_leaks));
	}

	if (atomic64_read(&ssdfs_req_queue_cache_leaks) != 0) {
		SSDFS_ERR("REQUESTS QUEUE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_req_queue_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static struct kmem_cache *ssdfs_seg_req_obj_cachep;

void ssdfs_zero_seg_req_obj_cache_ptr(void)
{
	ssdfs_seg_req_obj_cachep = NULL;
}

static
void ssdfs_init_seg_req_object_once(void *obj)
{
	struct ssdfs_segment_request *req_obj = obj;

	memset(req_obj, 0, sizeof(struct ssdfs_segment_request));
}

void ssdfs_shrink_seg_req_obj_cache(void)
{
	if (ssdfs_seg_req_obj_cachep)
		kmem_cache_shrink(ssdfs_seg_req_obj_cachep);
}

void ssdfs_destroy_seg_req_obj_cache(void)
{
	if (ssdfs_seg_req_obj_cachep)
		kmem_cache_destroy(ssdfs_seg_req_obj_cachep);
}

int ssdfs_init_seg_req_obj_cache(void)
{
	ssdfs_seg_req_obj_cachep = kmem_cache_create("ssdfs_seg_req_obj_cache",
					sizeof(struct ssdfs_segment_request), 0,
					SLAB_RECLAIM_ACCOUNT |
					SLAB_MEM_SPREAD |
					SLAB_ACCOUNT,
					ssdfs_init_seg_req_object_once);
	if (!ssdfs_seg_req_obj_cachep) {
		SSDFS_ERR("unable to create segment request objects cache\n");
		return -ENOMEM;
	}

	return 0;
}

/*
 * ssdfs_requests_queue_init() - initialize request queue
 * @rq: initialized request queue
 */
void ssdfs_requests_queue_init(struct ssdfs_requests_queue *rq)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock_init(&rq->lock);
	INIT_LIST_HEAD(&rq->list);
}

/*
 * is_ssdfs_requests_queue_empty() - check that requests queue is empty
 * @rq: requests queue
 */
bool is_ssdfs_requests_queue_empty(struct ssdfs_requests_queue *rq)
{
	bool is_empty;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&rq->lock);
	is_empty = list_empty_careful(&rq->list);
	spin_unlock(&rq->lock);

	return is_empty;
}

/*
 * ssdfs_requests_queue_add_head() - add request at the head of queue
 * @rq: requests queue
 * @req: request
 */
void ssdfs_requests_queue_add_head(struct ssdfs_requests_queue *rq,
				   struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rq || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, class %#x, cmd %#x\n",
		  req->place.start.seg_id,
		  req->private.class,
		  req->private.cmd);

	spin_lock(&rq->lock);
	list_add(&req->list, &rq->list);
	spin_unlock(&rq->lock);
}

/*
 * ssdfs_requests_queue_add_head_inc() - add request at the head of queue
 * @fsi: pointer on shared file system object
 * @rq: requests queue
 * @req: request
 */
void ssdfs_requests_queue_add_head_inc(struct ssdfs_fs_info *fsi,
					struct ssdfs_requests_queue *rq,
					struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !rq || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, class %#x, cmd %#x\n",
		  req->place.start.seg_id,
		  req->private.class,
		  req->private.cmd);

	ssdfs_requests_queue_add_head(rq, req);
	atomic64_inc(&fsi->flush_reqs);

	SSDFS_DBG("flush_reqs %lld\n",
		  atomic64_read(&fsi->flush_reqs));
}

/*
 * ssdfs_requests_queue_add_tail() - add request at the tail of queue
 * @rq: requests queue
 * @req: request
 */
void ssdfs_requests_queue_add_tail(struct ssdfs_requests_queue *rq,
				   struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rq || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, class %#x, cmd %#x\n",
		  req->place.start.seg_id,
		  req->private.class,
		  req->private.cmd);

	spin_lock(&rq->lock);
	list_add_tail(&req->list, &rq->list);
	spin_unlock(&rq->lock);
}

/*
 * ssdfs_requests_queue_add_tail_inc() - add request at the tail of queue
 * @fsi: pointer on shared file system object
 * @rq: requests queue
 * @req: request
 */
void ssdfs_requests_queue_add_tail_inc(struct ssdfs_fs_info *fsi,
					struct ssdfs_requests_queue *rq,
					struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !rq || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, class %#x, cmd %#x\n",
		  req->place.start.seg_id,
		  req->private.class,
		  req->private.cmd);

	ssdfs_requests_queue_add_tail(rq, req);
	atomic64_inc(&fsi->flush_reqs);

	SSDFS_DBG("flush_reqs %lld\n",
		  atomic64_read(&fsi->flush_reqs));
}

/*
 * is_request_command_valid() - check request's command validity
 * @class: request's class
 * @cmd: request's command
 */
static inline
bool is_request_command_valid(int class, int cmd)
{
	bool is_valid = false;

	switch (class) {
	case SSDFS_PEB_READ_REQ:
		is_valid = cmd > SSDFS_UNKNOWN_CMD &&
				cmd < SSDFS_READ_CMD_MAX;
		break;

	case SSDFS_PEB_PRE_ALLOCATE_DATA_REQ:
	case SSDFS_PEB_CREATE_DATA_REQ:
	case SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ:
	case SSDFS_PEB_CREATE_LNODE_REQ:
	case SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ:
	case SSDFS_PEB_CREATE_HNODE_REQ:
	case SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ:
	case SSDFS_PEB_CREATE_IDXNODE_REQ:
		is_valid = cmd > SSDFS_READ_CMD_MAX &&
				cmd < SSDFS_CREATE_CMD_MAX;
		break;

	case SSDFS_PEB_UPDATE_REQ:
	case SSDFS_PEB_PRE_ALLOC_UPDATE_REQ:
		is_valid = cmd > SSDFS_CREATE_CMD_MAX &&
				cmd < SSDFS_UPDATE_CMD_MAX;
		break;

	case SSDFS_PEB_COLLECT_GARBAGE_REQ:
		is_valid = cmd > SSDFS_UPDATE_CMD_MAX &&
				cmd < SSDFS_COLLECT_GARBAGE_CMD_MAX;
		break;

	default:
		is_valid = false;
	}

	return is_valid;
}

/*
 * ssdfs_requests_queue_remove_first() - get request and remove from queue
 * @rq: requests queue
 * @req: first request [out]
 *
 * This function get first request in @rq, remove it from queue
 * and return as @req.
 *
 * RETURN:
 * [success] - @req contains pointer on request.
 * [failure] - error code:
 *
 * %-ENODATA     - queue is empty.
 * %-ENOENT      - first empty is NULL.
 */
int ssdfs_requests_queue_remove_first(struct ssdfs_requests_queue *rq,
				      struct ssdfs_segment_request **req)
{
	bool is_empty;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rq || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&rq->lock);
	is_empty = list_empty_careful(&rq->list);
	if (!is_empty) {
		*req = list_first_entry_or_null(&rq->list,
						struct ssdfs_segment_request,
						list);
		if (!*req) {
			SSDFS_WARN("first entry is NULL\n");
			err = -ENOENT;
		} else
			list_del(&(*req)->list);
	}
	spin_unlock(&rq->lock);

	if (is_empty) {
		SSDFS_WARN("requests queue is empty\n");
		return -ENODATA;
	} else if (err)
		return err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!is_request_command_valid((*req)->private.class,
					 (*req)->private.cmd));
	BUG_ON((*req)->private.type >= SSDFS_REQ_TYPE_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, class %#x, cmd %#x\n",
		  (*req)->place.start.seg_id,
		  (*req)->private.class,
		  (*req)->private.cmd);

	return 0;
}

/*
 * ssdfs_requests_queue_remove_all() - remove all requests from queue
 * @rq: requests queue
 * @err: error code
 *
 * This function removes all requests from the queue.
 */
void ssdfs_requests_queue_remove_all(struct ssdfs_requests_queue *rq,
				     int err)
{
	bool is_empty;
	LIST_HEAD(tmp_list);
	struct list_head *this, *next;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&rq->lock);
	is_empty = list_empty_careful(&rq->list);
	if (!is_empty)
		list_replace_init(&rq->list, &tmp_list);
	spin_unlock(&rq->lock);

	if (is_empty)
		return;

	list_for_each_safe(this, next, &tmp_list) {
		struct ssdfs_segment_request *req;
		unsigned int i;

		req = list_entry(this, struct ssdfs_segment_request, list);

		if (!req) {
			SSDFS_WARN("empty request ptr\n");
			continue;
		}

		list_del(&req->list);

		SSDFS_WARN("delete request: "
			   "class %#x, cmd %#x, type %#x, refs_count %u, "
			   "seg %llu, extent (start %u, len %u)\n",
			   req->private.class, req->private.cmd,
			   req->private.type,
			   atomic_read(&req->private.refs_count),
			   req->place.start.seg_id,
			   req->place.start.blk_index,
			   req->place.len);

		atomic_set(&req->result.state, SSDFS_REQ_FAILED);

		switch (req->private.type) {
		case SSDFS_REQ_SYNC:
			req->result.err = err;
			complete(&req->result.wait);
			wake_up_all(&req->private.wait_queue);
			break;

		case SSDFS_REQ_ASYNC:
			complete(&req->result.wait);
			wake_up_all(&req->private.wait_queue);

			for (i = 0; i < pagevec_count(&req->result.pvec); i++) {
				struct page *page = req->result.pvec.pages[i];

				if (!page) {
					SSDFS_WARN("empty page ptr: index %u\n", i);
					continue;
				}

#ifdef CONFIG_SSDFS_DEBUG
				WARN_ON(!PageLocked(page));
#endif /* CONFIG_SSDFS_DEBUG */

				ClearPageUptodate(page);
				ClearPagePrivate(page);
				ClearPageMappedToDisk(page);
				ssdfs_clear_dirty_page(page);
				ssdfs_unlock_page(page);
				end_page_writeback(page);
			}

			ssdfs_put_request(req);
			ssdfs_request_free(req);
			break;

		case SSDFS_REQ_ASYNC_NO_FREE:
			complete(&req->result.wait);
			wake_up_all(&req->private.wait_queue);

			for (i = 0; i < pagevec_count(&req->result.pvec); i++) {
				struct page *page = req->result.pvec.pages[i];

				if (!page) {
					SSDFS_WARN("empty page ptr: index %u\n", i);
					continue;
				}

#ifdef CONFIG_SSDFS_DEBUG
				WARN_ON(!PageLocked(page));
#endif /* CONFIG_SSDFS_DEBUG */

				ClearPageUptodate(page);
				ClearPagePrivate(page);
				ClearPageMappedToDisk(page);
				ssdfs_clear_dirty_page(page);
				ssdfs_unlock_page(page);
				end_page_writeback(page);
			}

			ssdfs_put_request(req);
			break;

		default:
			BUG();
		};
	}
}

/*
 * ssdfs_request_alloc() - allocate memory for segment request object
 */
struct ssdfs_segment_request *ssdfs_request_alloc(void)
{
	struct ssdfs_segment_request *ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_seg_req_obj_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = kmem_cache_alloc(ssdfs_seg_req_obj_cachep, GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for request\n");
		return ERR_PTR(-ENOMEM);
	}

	ssdfs_req_queue_cache_leaks_increment(ptr);

	return ptr;
}

/*
 * ssdfs_request_free() - free memory for segment request object
 */
void ssdfs_request_free(struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_seg_req_obj_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!req)
		return;

	ssdfs_req_queue_cache_leaks_decrement(req);
	kmem_cache_free(ssdfs_seg_req_obj_cachep, req);
}

/*
 * ssdfs_request_init() - common request initialization
 * @req: request [out]
 */
void ssdfs_request_init(struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(req, 0, sizeof(struct ssdfs_segment_request));

	INIT_LIST_HEAD(&req->list);
	atomic_set(&req->private.refs_count, 0);
	init_waitqueue_head(&req->private.wait_queue);
	pagevec_init(&req->result.pvec);
	atomic_set(&req->result.state, SSDFS_REQ_CREATED);
	init_completion(&req->result.wait);
	req->result.err = 0;
}

/*
 * ssdfs_get_request() - increment reference counter
 * @req: request
 */
void ssdfs_get_request(struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	WARN_ON(atomic_inc_return(&req->private.refs_count) <= 0);
}

/*
 * ssdfs_put_request() - decrement reference counter
 * @req: request
 */
void ssdfs_put_request(struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_dec_return(&req->private.refs_count) < 0) {
		SSDFS_DBG("request's reference count %d\n",
			  atomic_read(&req->private.refs_count));
	}
}

/*
 * ssdfs_request_add_page() - add memory page into segment request
 * @page: memory page
 * @req: segment request [out]
 */
int ssdfs_request_add_page(struct page *page,
			   struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pagevec_space(&req->result.pvec) == 0) {
		SSDFS_WARN("request's pagevec is full\n");
		return -E2BIG;
	}

	pagevec_add(&req->result.pvec, page);
	return 0;
}

/*
 * ssdfs_request_allocate_and_add_page() - allocate and add page into request
 * @req: segment request [out]
 */
struct page *
ssdfs_request_allocate_and_add_page(struct ssdfs_segment_request *req)
{
	struct page *page;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("pagevec count %d\n",
		  pagevec_count(&req->result.pvec));

	if (pagevec_space(&req->result.pvec) == 0) {
		SSDFS_WARN("request's pagevec is full\n");
		return ERR_PTR(-E2BIG);
	}

	page = ssdfs_req_queue_alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (IS_ERR_OR_NULL(page)) {
		err = (page == NULL ? -ENOMEM : PTR_ERR(page));
		SSDFS_ERR("unable to allocate memory page\n");
		return ERR_PTR(err);
	}

	pagevec_add(&req->result.pvec, page);
	return page;
}

/*
 * ssdfs_request_add_allocated_page_locked() - allocate, add and lock page
 * @req: segment request [out]
 */
int ssdfs_request_add_allocated_page_locked(struct ssdfs_segment_request *req)
{
	struct page *page;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	page = ssdfs_request_allocate_and_add_page(req);
	if (IS_ERR_OR_NULL(page)) {
		err = (page == NULL ? -ENOMEM : PTR_ERR(page));
		SSDFS_ERR("fail to allocate page: err %d\n",
			  err);
		return err;
	}

	ssdfs_lock_page(page);
	return 0;
}

/*
 * ssdfs_request_unlock_and_remove_pages() - unlock and remove pages
 * @req: segment request [out]
 */
void ssdfs_request_unlock_and_remove_pages(struct ssdfs_segment_request *req)
{
	unsigned count;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	count = pagevec_count(&req->result.pvec);

	for (i = 0; i < count; i++) {
		struct page *page = req->result.pvec.pages[i];

		if (!page) {
			SSDFS_DBG("page %d is NULL\n", i);
			continue;
		}

		ssdfs_unlock_page(page);
	}

	ssdfs_req_queue_pagevec_release(&req->result.pvec);
	pagevec_reinit(&req->result.pvec);
}

/*
 * ssdfs_request_unlock_and_remove_page() - unlock and remove page
 * @req: segment request [in|out]
 * @page_index: page index
 */
void ssdfs_request_unlock_and_remove_page(struct ssdfs_segment_request *req,
					  int page_index)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	if (page_index >= pagevec_count(&req->result.pvec)) {
		SSDFS_ERR("page_index %d >= pagevec_count %u\n",
			  page_index,
			  pagevec_count(&req->result.pvec));
		return;
	}

	if (!req->result.pvec.pages[page_index]) {
		SSDFS_DBG("page %d is NULL\n", page_index);
		return;
	}

	ssdfs_unlock_page(req->result.pvec.pages[page_index]);
	ssdfs_req_queue_forget_page(req->result.pvec.pages[page_index]);
	req->result.pvec.pages[page_index] = NULL;
}

/*
 * ssdfs_free_flush_request_pages() - unlock and remove flush request's pages
 * @req: segment request [out]
 */
void ssdfs_free_flush_request_pages(struct ssdfs_segment_request *req)
{
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < pagevec_count(&req->result.pvec); i++) {
		struct page *page = req->result.pvec.pages[i];

		if (!page) {
			SSDFS_WARN("page %d is NULL\n", i);
			continue;
		}

		if (need_add_block(page))
			clear_page_new(page);

		if (PageWriteback(page))
			end_page_writeback(page);
		else {
			SSDFS_WARN("page %d is not under writeback: "
				   "cmd %#x, type %#x\n",
				   i, req->private.cmd,
				   req->private.type);
		}

		if (PageLocked(page))
			ssdfs_unlock_page(page);
		else {
			SSDFS_WARN("page %d is not locked: "
				   "cmd %#x, type %#x\n",
				   i, req->private.cmd,
				   req->private.type);
		}

		req->result.pvec.pages[i] = NULL;

		if (!(req->private.flags & SSDFS_REQ_DONT_FREE_PAGES))
			ssdfs_req_queue_free_page(page);
	}
}

/*
 * ssdfs_peb_extent_length() - determine extent length in pagevec
 * @si: segment object
 * @pvec: page vector
 */
u8 ssdfs_peb_extent_length(struct ssdfs_segment_info *si,
			   struct pagevec *pvec)
{
	u32 len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !si->fsi || !pvec);
#endif /* CONFIG_SSDFS_DEBUG */

	if (si->fsi->pagesize < PAGE_SIZE) {
		BUG_ON(PAGE_SIZE % si->fsi->pagesize);
		len = PAGE_SIZE / si->fsi->pagesize;
		len *= pagevec_count(pvec);
		BUG_ON(len == 0);
	} else {
		len = pagevec_count(pvec) * PAGE_SIZE;
		BUG_ON(len == 0);
		BUG_ON(len % si->fsi->pagesize);
		len = si->fsi->pagesize / len;
		BUG_ON(len == 0);
	}

	BUG_ON(len >= U8_MAX);
	return (u8)len;
}
