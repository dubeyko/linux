// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe over Fabrics TCP host.
 * Copyright (c) 2018 Lightbits Labs. All rights reserved.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/crc32.h>
#include <linux/nvme-tcp.h>
#include <linux/nvme-keyring.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/tls.h>
#include <net/tls_prot.h>
#include <net/handshake.h>
#include <linux/blk-mq.h>
#include <net/busy_poll.h>
#include <trace/events/sock.h>

#include "nvme.h"
#include "fabrics.h"

struct nvme_tcp_queue;

/* Define the socket priority to use for connections were it is desirable
 * that the NIC consider performing optimized packet processing or filtering.
 * A non-zero value being sufficient to indicate general consideration of any
 * possible optimization.  Making it a module param allows for alternative
 * values that may be unique for some NIC implementations.
 */
static int so_priority;
module_param(so_priority, int, 0644);
MODULE_PARM_DESC(so_priority, "nvme tcp socket optimize priority");

/*
 * Use the unbound workqueue for nvme_tcp_wq, then we can set the cpu affinity
 * from sysfs.
 */
static bool wq_unbound;
module_param(wq_unbound, bool, 0644);
MODULE_PARM_DESC(wq_unbound, "Use unbound workqueue for nvme-tcp IO context (default false)");

/*
 * TLS handshake timeout
 */
static int tls_handshake_timeout = 10;
#ifdef CONFIG_NVME_TCP_TLS
module_param(tls_handshake_timeout, int, 0644);
MODULE_PARM_DESC(tls_handshake_timeout,
		 "nvme TLS handshake timeout in seconds (default 10)");
#endif

static atomic_t nvme_tcp_cpu_queues[NR_CPUS];

#ifdef CONFIG_DEBUG_LOCK_ALLOC
/* lockdep can detect a circular dependency of the form
 *   sk_lock -> mmap_lock (page fault) -> fs locks -> sk_lock
 * because dependencies are tracked for both nvme-tcp and user contexts. Using
 * a separate class prevents lockdep from conflating nvme-tcp socket use with
 * user-space socket API use.
 */
static struct lock_class_key nvme_tcp_sk_key[2];
static struct lock_class_key nvme_tcp_slock_key[2];

static void nvme_tcp_reclassify_socket(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (WARN_ON_ONCE(!sock_allow_reclassification(sk)))
		return;

	switch (sk->sk_family) {
	case AF_INET:
		sock_lock_init_class_and_name(sk, "slock-AF_INET-NVME",
					      &nvme_tcp_slock_key[0],
					      "sk_lock-AF_INET-NVME",
					      &nvme_tcp_sk_key[0]);
		break;
	case AF_INET6:
		sock_lock_init_class_and_name(sk, "slock-AF_INET6-NVME",
					      &nvme_tcp_slock_key[1],
					      "sk_lock-AF_INET6-NVME",
					      &nvme_tcp_sk_key[1]);
		break;
	default:
		WARN_ON_ONCE(1);
	}
}
#else
static void nvme_tcp_reclassify_socket(struct socket *sock) { }
#endif

enum nvme_tcp_send_state {
	NVME_TCP_SEND_CMD_PDU = 0,
	NVME_TCP_SEND_H2C_PDU,
	NVME_TCP_SEND_DATA,
	NVME_TCP_SEND_DDGST,
};

struct nvme_tcp_request {
	struct nvme_request	req;
	void			*pdu;
	struct nvme_tcp_queue	*queue;
	u32			data_len;
	u32			pdu_len;
	u32			pdu_sent;
	u32			h2cdata_left;
	u32			h2cdata_offset;
	u16			ttag;
	__le16			status;
	struct list_head	entry;
	struct llist_node	lentry;
	__le32			ddgst;

	struct bio		*curr_bio;
	struct iov_iter		iter;

	/* send state */
	size_t			offset;
	size_t			data_sent;
	enum nvme_tcp_send_state state;
};

enum nvme_tcp_queue_flags {
	NVME_TCP_Q_ALLOCATED	= 0,
	NVME_TCP_Q_LIVE		= 1,
	NVME_TCP_Q_POLLING	= 2,
	NVME_TCP_Q_IO_CPU_SET	= 3,
};

enum nvme_tcp_recv_state {
	NVME_TCP_RECV_PDU = 0,
	NVME_TCP_RECV_DATA,
	NVME_TCP_RECV_DDGST,
};

struct nvme_tcp_ctrl;
struct nvme_tcp_queue {
	struct socket		*sock;
	struct work_struct	io_work;
	int			io_cpu;

	struct mutex		queue_lock;
	struct mutex		send_mutex;
	struct llist_head	req_list;
	struct list_head	send_list;

	/* recv state */
	void			*pdu;
	int			pdu_remaining;
	int			pdu_offset;
	size_t			data_remaining;
	size_t			ddgst_remaining;
	unsigned int		nr_cqe;

	/* send state */
	struct nvme_tcp_request *request;

	u32			maxh2cdata;
	size_t			cmnd_capsule_len;
	struct nvme_tcp_ctrl	*ctrl;
	unsigned long		flags;
	bool			rd_enabled;

	bool			hdr_digest;
	bool			data_digest;
	bool			tls_enabled;
	u32			rcv_crc;
	u32			snd_crc;
	__le32			exp_ddgst;
	__le32			recv_ddgst;
	struct completion       tls_complete;
	int                     tls_err;
	struct page_frag_cache	pf_cache;

	void (*state_change)(struct sock *);
	void (*data_ready)(struct sock *);
	void (*write_space)(struct sock *);
};

struct nvme_tcp_ctrl {
	/* read only in the hot path */
	struct nvme_tcp_queue	*queues;
	struct blk_mq_tag_set	tag_set;

	/* other member variables */
	struct list_head	list;
	struct blk_mq_tag_set	admin_tag_set;
	struct sockaddr_storage addr;
	struct sockaddr_storage src_addr;
	struct nvme_ctrl	ctrl;

	struct work_struct	err_work;
	struct delayed_work	connect_work;
	struct nvme_tcp_request async_req;
	u32			io_queues[HCTX_MAX_TYPES];
};

static LIST_HEAD(nvme_tcp_ctrl_list);
static DEFINE_MUTEX(nvme_tcp_ctrl_mutex);
static struct workqueue_struct *nvme_tcp_wq;
static const struct blk_mq_ops nvme_tcp_mq_ops;
static const struct blk_mq_ops nvme_tcp_admin_mq_ops;
static int nvme_tcp_try_send(struct nvme_tcp_queue *queue);

static inline struct nvme_tcp_ctrl *to_tcp_ctrl(struct nvme_ctrl *ctrl)
{
	return container_of(ctrl, struct nvme_tcp_ctrl, ctrl);
}

static inline int nvme_tcp_queue_id(struct nvme_tcp_queue *queue)
{
	return queue - queue->ctrl->queues;
}

static inline bool nvme_tcp_recv_pdu_supported(enum nvme_tcp_pdu_type type)
{
	switch (type) {
	case nvme_tcp_c2h_term:
	case nvme_tcp_c2h_data:
	case nvme_tcp_r2t:
	case nvme_tcp_rsp:
		return true;
	default:
		return false;
	}
}

/*
 * Check if the queue is TLS encrypted
 */
static inline bool nvme_tcp_queue_tls(struct nvme_tcp_queue *queue)
{
	if (!IS_ENABLED(CONFIG_NVME_TCP_TLS))
		return 0;

	return queue->tls_enabled;
}

/*
 * Check if TLS is configured for the controller.
 */
static inline bool nvme_tcp_tls_configured(struct nvme_ctrl *ctrl)
{
	if (!IS_ENABLED(CONFIG_NVME_TCP_TLS))
		return 0;

	return ctrl->opts->tls || ctrl->opts->concat;
}

static inline struct blk_mq_tags *nvme_tcp_tagset(struct nvme_tcp_queue *queue)
{
	u32 queue_idx = nvme_tcp_queue_id(queue);

	if (queue_idx == 0)
		return queue->ctrl->admin_tag_set.tags[queue_idx];
	return queue->ctrl->tag_set.tags[queue_idx - 1];
}

static inline u8 nvme_tcp_hdgst_len(struct nvme_tcp_queue *queue)
{
	return queue->hdr_digest ? NVME_TCP_DIGEST_LENGTH : 0;
}

static inline u8 nvme_tcp_ddgst_len(struct nvme_tcp_queue *queue)
{
	return queue->data_digest ? NVME_TCP_DIGEST_LENGTH : 0;
}

static inline void *nvme_tcp_req_cmd_pdu(struct nvme_tcp_request *req)
{
	return req->pdu;
}

static inline void *nvme_tcp_req_data_pdu(struct nvme_tcp_request *req)
{
	/* use the pdu space in the back for the data pdu */
	return req->pdu + sizeof(struct nvme_tcp_cmd_pdu) -
		sizeof(struct nvme_tcp_data_pdu);
}

static inline size_t nvme_tcp_inline_data_size(struct nvme_tcp_request *req)
{
	if (nvme_is_fabrics(req->req.cmd))
		return NVME_TCP_ADMIN_CCSZ;
	return req->queue->cmnd_capsule_len - sizeof(struct nvme_command);
}

static inline bool nvme_tcp_async_req(struct nvme_tcp_request *req)
{
	return req == &req->queue->ctrl->async_req;
}

static inline bool nvme_tcp_has_inline_data(struct nvme_tcp_request *req)
{
	struct request *rq;

	if (unlikely(nvme_tcp_async_req(req)))
		return false; /* async events don't have a request */

	rq = blk_mq_rq_from_pdu(req);

	return rq_data_dir(rq) == WRITE && req->data_len &&
		req->data_len <= nvme_tcp_inline_data_size(req);
}

static inline struct page *nvme_tcp_req_cur_page(struct nvme_tcp_request *req)
{
	return req->iter.bvec->bv_page;
}

static inline size_t nvme_tcp_req_cur_offset(struct nvme_tcp_request *req)
{
	return req->iter.bvec->bv_offset + req->iter.iov_offset;
}

static inline size_t nvme_tcp_req_cur_length(struct nvme_tcp_request *req)
{
	return min_t(size_t, iov_iter_single_seg_count(&req->iter),
			req->pdu_len - req->pdu_sent);
}

static inline size_t nvme_tcp_pdu_data_left(struct nvme_tcp_request *req)
{
	return rq_data_dir(blk_mq_rq_from_pdu(req)) == WRITE ?
			req->pdu_len - req->pdu_sent : 0;
}

static inline size_t nvme_tcp_pdu_last_send(struct nvme_tcp_request *req,
		int len)
{
	return nvme_tcp_pdu_data_left(req) <= len;
}

static void nvme_tcp_init_iter(struct nvme_tcp_request *req,
		unsigned int dir)
{
	struct request *rq = blk_mq_rq_from_pdu(req);
	struct bio_vec *vec;
	unsigned int size;
	int nr_bvec;
	size_t offset;

	if (rq->rq_flags & RQF_SPECIAL_PAYLOAD) {
		vec = &rq->special_vec;
		nr_bvec = 1;
		size = blk_rq_payload_bytes(rq);
		offset = 0;
	} else {
		struct bio *bio = req->curr_bio;
		struct bvec_iter bi;
		struct bio_vec bv;

		vec = __bvec_iter_bvec(bio->bi_io_vec, bio->bi_iter);
		nr_bvec = 0;
		bio_for_each_bvec(bv, bio, bi) {
			nr_bvec++;
		}
		size = bio->bi_iter.bi_size;
		offset = bio->bi_iter.bi_bvec_done;
	}

	iov_iter_bvec(&req->iter, dir, vec, nr_bvec, size);
	req->iter.iov_offset = offset;
}

static inline void nvme_tcp_advance_req(struct nvme_tcp_request *req,
		int len)
{
	req->data_sent += len;
	req->pdu_sent += len;
	iov_iter_advance(&req->iter, len);
	if (!iov_iter_count(&req->iter) &&
	    req->data_sent < req->data_len) {
		req->curr_bio = req->curr_bio->bi_next;
		nvme_tcp_init_iter(req, ITER_SOURCE);
	}
}

static inline void nvme_tcp_send_all(struct nvme_tcp_queue *queue)
{
	int ret;

	/* drain the send queue as much as we can... */
	do {
		ret = nvme_tcp_try_send(queue);
	} while (ret > 0);
}

static inline bool nvme_tcp_queue_has_pending(struct nvme_tcp_queue *queue)
{
	return !list_empty(&queue->send_list) ||
		!llist_empty(&queue->req_list);
}

static inline bool nvme_tcp_queue_more(struct nvme_tcp_queue *queue)
{
	return !nvme_tcp_queue_tls(queue) &&
		nvme_tcp_queue_has_pending(queue);
}

static inline void nvme_tcp_queue_request(struct nvme_tcp_request *req,
		bool last)
{
	struct nvme_tcp_queue *queue = req->queue;
	bool empty;

	empty = llist_add(&req->lentry, &queue->req_list) &&
		list_empty(&queue->send_list) && !queue->request;

	/*
	 * if we're the first on the send_list and we can try to send
	 * directly, otherwise queue io_work. Also, only do that if we
	 * are on the same cpu, so we don't introduce contention.
	 */
	if (queue->io_cpu == raw_smp_processor_id() &&
	    empty && mutex_trylock(&queue->send_mutex)) {
		nvme_tcp_send_all(queue);
		mutex_unlock(&queue->send_mutex);
	}

	if (last && nvme_tcp_queue_has_pending(queue))
		queue_work_on(queue->io_cpu, nvme_tcp_wq, &queue->io_work);
}

static void nvme_tcp_process_req_list(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_request *req;
	struct llist_node *node;

	for (node = llist_del_all(&queue->req_list); node; node = node->next) {
		req = llist_entry(node, struct nvme_tcp_request, lentry);
		list_add(&req->entry, &queue->send_list);
	}
}

static inline struct nvme_tcp_request *
nvme_tcp_fetch_request(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_request *req;

	req = list_first_entry_or_null(&queue->send_list,
			struct nvme_tcp_request, entry);
	if (!req) {
		nvme_tcp_process_req_list(queue);
		req = list_first_entry_or_null(&queue->send_list,
				struct nvme_tcp_request, entry);
		if (unlikely(!req))
			return NULL;
	}

	list_del_init(&req->entry);
	init_llist_node(&req->lentry);
	return req;
}

#define NVME_TCP_CRC_SEED (~0)

static inline void nvme_tcp_ddgst_update(u32 *crcp,
		struct page *page, size_t off, size_t len)
{
	page += off / PAGE_SIZE;
	off %= PAGE_SIZE;
	while (len) {
		const void *vaddr = kmap_local_page(page);
		size_t n = min(len, (size_t)PAGE_SIZE - off);

		*crcp = crc32c(*crcp, vaddr + off, n);
		kunmap_local(vaddr);
		page++;
		off = 0;
		len -= n;
	}
}

static inline __le32 nvme_tcp_ddgst_final(u32 crc)
{
	return cpu_to_le32(~crc);
}

static inline __le32 nvme_tcp_hdgst(const void *pdu, size_t len)
{
	return cpu_to_le32(~crc32c(NVME_TCP_CRC_SEED, pdu, len));
}

static inline void nvme_tcp_set_hdgst(void *pdu, size_t len)
{
	*(__le32 *)(pdu + len) = nvme_tcp_hdgst(pdu, len);
}

static int nvme_tcp_verify_hdgst(struct nvme_tcp_queue *queue,
		void *pdu, size_t pdu_len)
{
	struct nvme_tcp_hdr *hdr = pdu;
	__le32 recv_digest;
	__le32 exp_digest;

	if (unlikely(!(hdr->flags & NVME_TCP_F_HDGST))) {
		dev_err(queue->ctrl->ctrl.device,
			"queue %d: header digest flag is cleared\n",
			nvme_tcp_queue_id(queue));
		return -EPROTO;
	}

	recv_digest = *(__le32 *)(pdu + hdr->hlen);
	exp_digest = nvme_tcp_hdgst(pdu, pdu_len);
	if (recv_digest != exp_digest) {
		dev_err(queue->ctrl->ctrl.device,
			"header digest error: recv %#x expected %#x\n",
			le32_to_cpu(recv_digest), le32_to_cpu(exp_digest));
		return -EIO;
	}

	return 0;
}

static int nvme_tcp_check_ddgst(struct nvme_tcp_queue *queue, void *pdu)
{
	struct nvme_tcp_hdr *hdr = pdu;
	u8 digest_len = nvme_tcp_hdgst_len(queue);
	u32 len;

	len = le32_to_cpu(hdr->plen) - hdr->hlen -
		((hdr->flags & NVME_TCP_F_HDGST) ? digest_len : 0);

	if (unlikely(len && !(hdr->flags & NVME_TCP_F_DDGST))) {
		dev_err(queue->ctrl->ctrl.device,
			"queue %d: data digest flag is cleared\n",
		nvme_tcp_queue_id(queue));
		return -EPROTO;
	}
	queue->rcv_crc = NVME_TCP_CRC_SEED;

	return 0;
}

static void nvme_tcp_exit_request(struct blk_mq_tag_set *set,
		struct request *rq, unsigned int hctx_idx)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);

	page_frag_free(req->pdu);
}

static int nvme_tcp_init_request(struct blk_mq_tag_set *set,
		struct request *rq, unsigned int hctx_idx,
		unsigned int numa_node)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(set->driver_data);
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	struct nvme_tcp_cmd_pdu *pdu;
	int queue_idx = (set == &ctrl->tag_set) ? hctx_idx + 1 : 0;
	struct nvme_tcp_queue *queue = &ctrl->queues[queue_idx];
	u8 hdgst = nvme_tcp_hdgst_len(queue);

	req->pdu = page_frag_alloc(&queue->pf_cache,
		sizeof(struct nvme_tcp_cmd_pdu) + hdgst,
		GFP_KERNEL | __GFP_ZERO);
	if (!req->pdu)
		return -ENOMEM;

	pdu = req->pdu;
	req->queue = queue;
	nvme_req(rq)->ctrl = &ctrl->ctrl;
	nvme_req(rq)->cmd = &pdu->cmd;
	init_llist_node(&req->lentry);
	INIT_LIST_HEAD(&req->entry);

	return 0;
}

static int nvme_tcp_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
		unsigned int hctx_idx)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(data);
	struct nvme_tcp_queue *queue = &ctrl->queues[hctx_idx + 1];

	hctx->driver_data = queue;
	return 0;
}

static int nvme_tcp_init_admin_hctx(struct blk_mq_hw_ctx *hctx, void *data,
		unsigned int hctx_idx)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(data);
	struct nvme_tcp_queue *queue = &ctrl->queues[0];

	hctx->driver_data = queue;
	return 0;
}

static enum nvme_tcp_recv_state
nvme_tcp_recv_state(struct nvme_tcp_queue *queue)
{
	return  (queue->pdu_remaining) ? NVME_TCP_RECV_PDU :
		(queue->ddgst_remaining) ? NVME_TCP_RECV_DDGST :
		NVME_TCP_RECV_DATA;
}

static void nvme_tcp_init_recv_ctx(struct nvme_tcp_queue *queue)
{
	queue->pdu_remaining = sizeof(struct nvme_tcp_rsp_pdu) +
				nvme_tcp_hdgst_len(queue);
	queue->pdu_offset = 0;
	queue->data_remaining = -1;
	queue->ddgst_remaining = 0;
}

static void nvme_tcp_error_recovery(struct nvme_ctrl *ctrl)
{
	if (!nvme_change_ctrl_state(ctrl, NVME_CTRL_RESETTING))
		return;

	dev_warn(ctrl->device, "starting error recovery\n");
	queue_work(nvme_reset_wq, &to_tcp_ctrl(ctrl)->err_work);
}

static int nvme_tcp_process_nvme_cqe(struct nvme_tcp_queue *queue,
		struct nvme_completion *cqe)
{
	struct nvme_tcp_request *req;
	struct request *rq;

	rq = nvme_find_rq(nvme_tcp_tagset(queue), cqe->command_id);
	if (!rq) {
		dev_err(queue->ctrl->ctrl.device,
			"got bad cqe.command_id %#x on queue %d\n",
			cqe->command_id, nvme_tcp_queue_id(queue));
		nvme_tcp_error_recovery(&queue->ctrl->ctrl);
		return -EINVAL;
	}

	req = blk_mq_rq_to_pdu(rq);
	if (req->status == cpu_to_le16(NVME_SC_SUCCESS))
		req->status = cqe->status;

	if (!nvme_try_complete_req(rq, req->status, cqe->result))
		nvme_complete_rq(rq);
	queue->nr_cqe++;

	return 0;
}

static int nvme_tcp_handle_c2h_data(struct nvme_tcp_queue *queue,
		struct nvme_tcp_data_pdu *pdu)
{
	struct request *rq;

	rq = nvme_find_rq(nvme_tcp_tagset(queue), pdu->command_id);
	if (!rq) {
		dev_err(queue->ctrl->ctrl.device,
			"got bad c2hdata.command_id %#x on queue %d\n",
			pdu->command_id, nvme_tcp_queue_id(queue));
		return -ENOENT;
	}

	if (!blk_rq_payload_bytes(rq)) {
		dev_err(queue->ctrl->ctrl.device,
			"queue %d tag %#x unexpected data\n",
			nvme_tcp_queue_id(queue), rq->tag);
		return -EIO;
	}

	queue->data_remaining = le32_to_cpu(pdu->data_length);

	if (pdu->hdr.flags & NVME_TCP_F_DATA_SUCCESS &&
	    unlikely(!(pdu->hdr.flags & NVME_TCP_F_DATA_LAST))) {
		dev_err(queue->ctrl->ctrl.device,
			"queue %d tag %#x SUCCESS set but not last PDU\n",
			nvme_tcp_queue_id(queue), rq->tag);
		nvme_tcp_error_recovery(&queue->ctrl->ctrl);
		return -EPROTO;
	}

	return 0;
}

static int nvme_tcp_handle_comp(struct nvme_tcp_queue *queue,
		struct nvme_tcp_rsp_pdu *pdu)
{
	struct nvme_completion *cqe = &pdu->cqe;
	int ret = 0;

	/*
	 * AEN requests are special as they don't time out and can
	 * survive any kind of queue freeze and often don't respond to
	 * aborts.  We don't even bother to allocate a struct request
	 * for them but rather special case them here.
	 */
	if (unlikely(nvme_is_aen_req(nvme_tcp_queue_id(queue),
				     cqe->command_id)))
		nvme_complete_async_event(&queue->ctrl->ctrl, cqe->status,
				&cqe->result);
	else
		ret = nvme_tcp_process_nvme_cqe(queue, cqe);

	return ret;
}

static void nvme_tcp_setup_h2c_data_pdu(struct nvme_tcp_request *req)
{
	struct nvme_tcp_data_pdu *data = nvme_tcp_req_data_pdu(req);
	struct nvme_tcp_queue *queue = req->queue;
	struct request *rq = blk_mq_rq_from_pdu(req);
	u32 h2cdata_sent = req->pdu_len;
	u8 hdgst = nvme_tcp_hdgst_len(queue);
	u8 ddgst = nvme_tcp_ddgst_len(queue);

	req->state = NVME_TCP_SEND_H2C_PDU;
	req->offset = 0;
	req->pdu_len = min(req->h2cdata_left, queue->maxh2cdata);
	req->pdu_sent = 0;
	req->h2cdata_left -= req->pdu_len;
	req->h2cdata_offset += h2cdata_sent;

	memset(data, 0, sizeof(*data));
	data->hdr.type = nvme_tcp_h2c_data;
	if (!req->h2cdata_left)
		data->hdr.flags = NVME_TCP_F_DATA_LAST;
	if (queue->hdr_digest)
		data->hdr.flags |= NVME_TCP_F_HDGST;
	if (queue->data_digest)
		data->hdr.flags |= NVME_TCP_F_DDGST;
	data->hdr.hlen = sizeof(*data);
	data->hdr.pdo = data->hdr.hlen + hdgst;
	data->hdr.plen =
		cpu_to_le32(data->hdr.hlen + hdgst + req->pdu_len + ddgst);
	data->ttag = req->ttag;
	data->command_id = nvme_cid(rq);
	data->data_offset = cpu_to_le32(req->h2cdata_offset);
	data->data_length = cpu_to_le32(req->pdu_len);
}

static int nvme_tcp_handle_r2t(struct nvme_tcp_queue *queue,
		struct nvme_tcp_r2t_pdu *pdu)
{
	struct nvme_tcp_request *req;
	struct request *rq;
	u32 r2t_length = le32_to_cpu(pdu->r2t_length);
	u32 r2t_offset = le32_to_cpu(pdu->r2t_offset);

	rq = nvme_find_rq(nvme_tcp_tagset(queue), pdu->command_id);
	if (!rq) {
		dev_err(queue->ctrl->ctrl.device,
			"got bad r2t.command_id %#x on queue %d\n",
			pdu->command_id, nvme_tcp_queue_id(queue));
		return -ENOENT;
	}
	req = blk_mq_rq_to_pdu(rq);

	if (unlikely(!r2t_length)) {
		dev_err(queue->ctrl->ctrl.device,
			"req %d r2t len is %u, probably a bug...\n",
			rq->tag, r2t_length);
		return -EPROTO;
	}

	if (unlikely(req->data_sent + r2t_length > req->data_len)) {
		dev_err(queue->ctrl->ctrl.device,
			"req %d r2t len %u exceeded data len %u (%zu sent)\n",
			rq->tag, r2t_length, req->data_len, req->data_sent);
		return -EPROTO;
	}

	if (unlikely(r2t_offset < req->data_sent)) {
		dev_err(queue->ctrl->ctrl.device,
			"req %d unexpected r2t offset %u (expected %zu)\n",
			rq->tag, r2t_offset, req->data_sent);
		return -EPROTO;
	}

	if (llist_on_list(&req->lentry) ||
	    !list_empty(&req->entry)) {
		dev_err(queue->ctrl->ctrl.device,
			"req %d unexpected r2t while processing request\n",
			rq->tag);
		return -EPROTO;
	}

	req->pdu_len = 0;
	req->h2cdata_left = r2t_length;
	req->h2cdata_offset = r2t_offset;
	req->ttag = pdu->ttag;

	nvme_tcp_setup_h2c_data_pdu(req);

	llist_add(&req->lentry, &queue->req_list);
	queue_work_on(queue->io_cpu, nvme_tcp_wq, &queue->io_work);

	return 0;
}

static void nvme_tcp_handle_c2h_term(struct nvme_tcp_queue *queue,
		struct nvme_tcp_term_pdu *pdu)
{
	u16 fes;
	const char *msg;
	u32 plen = le32_to_cpu(pdu->hdr.plen);

	static const char * const msg_table[] = {
		[NVME_TCP_FES_INVALID_PDU_HDR] = "Invalid PDU Header Field",
		[NVME_TCP_FES_PDU_SEQ_ERR] = "PDU Sequence Error",
		[NVME_TCP_FES_HDR_DIGEST_ERR] = "Header Digest Error",
		[NVME_TCP_FES_DATA_OUT_OF_RANGE] = "Data Transfer Out Of Range",
		[NVME_TCP_FES_DATA_LIMIT_EXCEEDED] = "Data Transfer Limit Exceeded",
		[NVME_TCP_FES_UNSUPPORTED_PARAM] = "Unsupported Parameter",
	};

	if (plen < NVME_TCP_MIN_C2HTERM_PLEN ||
	    plen > NVME_TCP_MAX_C2HTERM_PLEN) {
		dev_err(queue->ctrl->ctrl.device,
			"Received a malformed C2HTermReq PDU (plen = %u)\n",
			plen);
		return;
	}

	fes = le16_to_cpu(pdu->fes);
	if (fes && fes < ARRAY_SIZE(msg_table))
		msg = msg_table[fes];
	else
		msg = "Unknown";

	dev_err(queue->ctrl->ctrl.device,
		"Received C2HTermReq (FES = %s)\n", msg);
}

static int nvme_tcp_recv_pdu(struct nvme_tcp_queue *queue, struct sk_buff *skb,
		unsigned int *offset, size_t *len)
{
	struct nvme_tcp_hdr *hdr;
	char *pdu = queue->pdu;
	size_t rcv_len = min_t(size_t, *len, queue->pdu_remaining);
	int ret;

	ret = skb_copy_bits(skb, *offset,
		&pdu[queue->pdu_offset], rcv_len);
	if (unlikely(ret))
		return ret;

	queue->pdu_remaining -= rcv_len;
	queue->pdu_offset += rcv_len;
	*offset += rcv_len;
	*len -= rcv_len;
	if (queue->pdu_remaining)
		return 0;

	hdr = queue->pdu;
	if (unlikely(hdr->hlen != sizeof(struct nvme_tcp_rsp_pdu))) {
		if (!nvme_tcp_recv_pdu_supported(hdr->type))
			goto unsupported_pdu;

		dev_err(queue->ctrl->ctrl.device,
			"pdu type %d has unexpected header length (%d)\n",
			hdr->type, hdr->hlen);
		return -EPROTO;
	}

	if (unlikely(hdr->type == nvme_tcp_c2h_term)) {
		/*
		 * C2HTermReq never includes Header or Data digests.
		 * Skip the checks.
		 */
		nvme_tcp_handle_c2h_term(queue, (void *)queue->pdu);
		return -EINVAL;
	}

	if (queue->hdr_digest) {
		ret = nvme_tcp_verify_hdgst(queue, queue->pdu, hdr->hlen);
		if (unlikely(ret))
			return ret;
	}


	if (queue->data_digest) {
		ret = nvme_tcp_check_ddgst(queue, queue->pdu);
		if (unlikely(ret))
			return ret;
	}

	switch (hdr->type) {
	case nvme_tcp_c2h_data:
		return nvme_tcp_handle_c2h_data(queue, (void *)queue->pdu);
	case nvme_tcp_rsp:
		nvme_tcp_init_recv_ctx(queue);
		return nvme_tcp_handle_comp(queue, (void *)queue->pdu);
	case nvme_tcp_r2t:
		nvme_tcp_init_recv_ctx(queue);
		return nvme_tcp_handle_r2t(queue, (void *)queue->pdu);
	default:
		goto unsupported_pdu;
	}

unsupported_pdu:
	dev_err(queue->ctrl->ctrl.device,
		"unsupported pdu type (%d)\n", hdr->type);
	return -EINVAL;
}

static inline void nvme_tcp_end_request(struct request *rq, u16 status)
{
	union nvme_result res = {};

	if (!nvme_try_complete_req(rq, cpu_to_le16(status << 1), res))
		nvme_complete_rq(rq);
}

static int nvme_tcp_recv_data(struct nvme_tcp_queue *queue, struct sk_buff *skb,
			      unsigned int *offset, size_t *len)
{
	struct nvme_tcp_data_pdu *pdu = (void *)queue->pdu;
	struct request *rq =
		nvme_cid_to_rq(nvme_tcp_tagset(queue), pdu->command_id);
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);

	while (true) {
		int recv_len, ret;

		recv_len = min_t(size_t, *len, queue->data_remaining);
		if (!recv_len)
			break;

		if (!iov_iter_count(&req->iter)) {
			req->curr_bio = req->curr_bio->bi_next;

			/*
			 * If we don`t have any bios it means that controller
			 * sent more data than we requested, hence error
			 */
			if (!req->curr_bio) {
				dev_err(queue->ctrl->ctrl.device,
					"queue %d no space in request %#x",
					nvme_tcp_queue_id(queue), rq->tag);
				nvme_tcp_init_recv_ctx(queue);
				return -EIO;
			}
			nvme_tcp_init_iter(req, ITER_DEST);
		}

		/* we can read only from what is left in this bio */
		recv_len = min_t(size_t, recv_len,
				iov_iter_count(&req->iter));

		if (queue->data_digest)
			ret = skb_copy_and_crc32c_datagram_iter(skb, *offset,
				&req->iter, recv_len, &queue->rcv_crc);
		else
			ret = skb_copy_datagram_iter(skb, *offset,
					&req->iter, recv_len);
		if (ret) {
			dev_err(queue->ctrl->ctrl.device,
				"queue %d failed to copy request %#x data",
				nvme_tcp_queue_id(queue), rq->tag);
			return ret;
		}

		*len -= recv_len;
		*offset += recv_len;
		queue->data_remaining -= recv_len;
	}

	if (!queue->data_remaining) {
		if (queue->data_digest) {
			queue->exp_ddgst = nvme_tcp_ddgst_final(queue->rcv_crc);
			queue->ddgst_remaining = NVME_TCP_DIGEST_LENGTH;
		} else {
			if (pdu->hdr.flags & NVME_TCP_F_DATA_SUCCESS) {
				nvme_tcp_end_request(rq,
						le16_to_cpu(req->status));
				queue->nr_cqe++;
			}
			nvme_tcp_init_recv_ctx(queue);
		}
	}

	return 0;
}

static int nvme_tcp_recv_ddgst(struct nvme_tcp_queue *queue,
		struct sk_buff *skb, unsigned int *offset, size_t *len)
{
	struct nvme_tcp_data_pdu *pdu = (void *)queue->pdu;
	char *ddgst = (char *)&queue->recv_ddgst;
	size_t recv_len = min_t(size_t, *len, queue->ddgst_remaining);
	off_t off = NVME_TCP_DIGEST_LENGTH - queue->ddgst_remaining;
	int ret;

	ret = skb_copy_bits(skb, *offset, &ddgst[off], recv_len);
	if (unlikely(ret))
		return ret;

	queue->ddgst_remaining -= recv_len;
	*offset += recv_len;
	*len -= recv_len;
	if (queue->ddgst_remaining)
		return 0;

	if (queue->recv_ddgst != queue->exp_ddgst) {
		struct request *rq = nvme_cid_to_rq(nvme_tcp_tagset(queue),
					pdu->command_id);
		struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);

		req->status = cpu_to_le16(NVME_SC_DATA_XFER_ERROR);

		dev_err(queue->ctrl->ctrl.device,
			"data digest error: recv %#x expected %#x\n",
			le32_to_cpu(queue->recv_ddgst),
			le32_to_cpu(queue->exp_ddgst));
	}

	if (pdu->hdr.flags & NVME_TCP_F_DATA_SUCCESS) {
		struct request *rq = nvme_cid_to_rq(nvme_tcp_tagset(queue),
					pdu->command_id);
		struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);

		nvme_tcp_end_request(rq, le16_to_cpu(req->status));
		queue->nr_cqe++;
	}

	nvme_tcp_init_recv_ctx(queue);
	return 0;
}

static int nvme_tcp_recv_skb(read_descriptor_t *desc, struct sk_buff *skb,
			     unsigned int offset, size_t len)
{
	struct nvme_tcp_queue *queue = desc->arg.data;
	size_t consumed = len;
	int result;

	if (unlikely(!queue->rd_enabled))
		return -EFAULT;

	while (len) {
		switch (nvme_tcp_recv_state(queue)) {
		case NVME_TCP_RECV_PDU:
			result = nvme_tcp_recv_pdu(queue, skb, &offset, &len);
			break;
		case NVME_TCP_RECV_DATA:
			result = nvme_tcp_recv_data(queue, skb, &offset, &len);
			break;
		case NVME_TCP_RECV_DDGST:
			result = nvme_tcp_recv_ddgst(queue, skb, &offset, &len);
			break;
		default:
			result = -EFAULT;
		}
		if (result) {
			dev_err(queue->ctrl->ctrl.device,
				"receive failed:  %d\n", result);
			queue->rd_enabled = false;
			nvme_tcp_error_recovery(&queue->ctrl->ctrl);
			return result;
		}
	}

	return consumed;
}

static void nvme_tcp_data_ready(struct sock *sk)
{
	struct nvme_tcp_queue *queue;

	trace_sk_data_ready(sk);

	read_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (likely(queue && queue->rd_enabled) &&
	    !test_bit(NVME_TCP_Q_POLLING, &queue->flags))
		queue_work_on(queue->io_cpu, nvme_tcp_wq, &queue->io_work);
	read_unlock_bh(&sk->sk_callback_lock);
}

static void nvme_tcp_write_space(struct sock *sk)
{
	struct nvme_tcp_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (likely(queue && sk_stream_is_writeable(sk))) {
		clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		queue_work_on(queue->io_cpu, nvme_tcp_wq, &queue->io_work);
	}
	read_unlock_bh(&sk->sk_callback_lock);
}

static void nvme_tcp_state_change(struct sock *sk)
{
	struct nvme_tcp_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (!queue)
		goto done;

	switch (sk->sk_state) {
	case TCP_CLOSE:
	case TCP_CLOSE_WAIT:
	case TCP_LAST_ACK:
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
		nvme_tcp_error_recovery(&queue->ctrl->ctrl);
		break;
	default:
		dev_info(queue->ctrl->ctrl.device,
			"queue %d socket state %d\n",
			nvme_tcp_queue_id(queue), sk->sk_state);
	}

	queue->state_change(sk);
done:
	read_unlock_bh(&sk->sk_callback_lock);
}

static inline void nvme_tcp_done_send_req(struct nvme_tcp_queue *queue)
{
	queue->request = NULL;
}

static void nvme_tcp_fail_request(struct nvme_tcp_request *req)
{
	if (nvme_tcp_async_req(req)) {
		union nvme_result res = {};

		nvme_complete_async_event(&req->queue->ctrl->ctrl,
				cpu_to_le16(NVME_SC_HOST_PATH_ERROR), &res);
	} else {
		nvme_tcp_end_request(blk_mq_rq_from_pdu(req),
				NVME_SC_HOST_PATH_ERROR);
	}
}

static int nvme_tcp_try_send_data(struct nvme_tcp_request *req)
{
	struct nvme_tcp_queue *queue = req->queue;
	int req_data_len = req->data_len;
	u32 h2cdata_left = req->h2cdata_left;

	while (true) {
		struct bio_vec bvec;
		struct msghdr msg = {
			.msg_flags = MSG_DONTWAIT | MSG_SPLICE_PAGES,
		};
		struct page *page = nvme_tcp_req_cur_page(req);
		size_t offset = nvme_tcp_req_cur_offset(req);
		size_t len = nvme_tcp_req_cur_length(req);
		bool last = nvme_tcp_pdu_last_send(req, len);
		int req_data_sent = req->data_sent;
		int ret;

		if (last && !queue->data_digest && !nvme_tcp_queue_more(queue))
			msg.msg_flags |= MSG_EOR;
		else
			msg.msg_flags |= MSG_MORE;

		if (!sendpages_ok(page, len, offset))
			msg.msg_flags &= ~MSG_SPLICE_PAGES;

		bvec_set_page(&bvec, page, len, offset);
		iov_iter_bvec(&msg.msg_iter, ITER_SOURCE, &bvec, 1, len);
		ret = sock_sendmsg(queue->sock, &msg);
		if (ret <= 0)
			return ret;

		if (queue->data_digest)
			nvme_tcp_ddgst_update(&queue->snd_crc, page,
					offset, ret);

		/*
		 * update the request iterator except for the last payload send
		 * in the request where we don't want to modify it as we may
		 * compete with the RX path completing the request.
		 */
		if (req_data_sent + ret < req_data_len)
			nvme_tcp_advance_req(req, ret);

		/* fully successful last send in current PDU */
		if (last && ret == len) {
			if (queue->data_digest) {
				req->ddgst =
					nvme_tcp_ddgst_final(queue->snd_crc);
				req->state = NVME_TCP_SEND_DDGST;
				req->offset = 0;
			} else {
				if (h2cdata_left)
					nvme_tcp_setup_h2c_data_pdu(req);
				else
					nvme_tcp_done_send_req(queue);
			}
			return 1;
		}
	}
	return -EAGAIN;
}

static int nvme_tcp_try_send_cmd_pdu(struct nvme_tcp_request *req)
{
	struct nvme_tcp_queue *queue = req->queue;
	struct nvme_tcp_cmd_pdu *pdu = nvme_tcp_req_cmd_pdu(req);
	struct bio_vec bvec;
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_SPLICE_PAGES, };
	bool inline_data = nvme_tcp_has_inline_data(req);
	u8 hdgst = nvme_tcp_hdgst_len(queue);
	int len = sizeof(*pdu) + hdgst - req->offset;
	int ret;

	if (inline_data || nvme_tcp_queue_more(queue))
		msg.msg_flags |= MSG_MORE;
	else
		msg.msg_flags |= MSG_EOR;

	if (queue->hdr_digest && !req->offset)
		nvme_tcp_set_hdgst(pdu, sizeof(*pdu));

	bvec_set_virt(&bvec, (void *)pdu + req->offset, len);
	iov_iter_bvec(&msg.msg_iter, ITER_SOURCE, &bvec, 1, len);
	ret = sock_sendmsg(queue->sock, &msg);
	if (unlikely(ret <= 0))
		return ret;

	len -= ret;
	if (!len) {
		if (inline_data) {
			req->state = NVME_TCP_SEND_DATA;
			if (queue->data_digest)
				queue->snd_crc = NVME_TCP_CRC_SEED;
		} else {
			nvme_tcp_done_send_req(queue);
		}
		return 1;
	}
	req->offset += ret;

	return -EAGAIN;
}

static int nvme_tcp_try_send_data_pdu(struct nvme_tcp_request *req)
{
	struct nvme_tcp_queue *queue = req->queue;
	struct nvme_tcp_data_pdu *pdu = nvme_tcp_req_data_pdu(req);
	struct bio_vec bvec;
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_MORE, };
	u8 hdgst = nvme_tcp_hdgst_len(queue);
	int len = sizeof(*pdu) - req->offset + hdgst;
	int ret;

	if (queue->hdr_digest && !req->offset)
		nvme_tcp_set_hdgst(pdu, sizeof(*pdu));

	if (!req->h2cdata_left)
		msg.msg_flags |= MSG_SPLICE_PAGES;

	bvec_set_virt(&bvec, (void *)pdu + req->offset, len);
	iov_iter_bvec(&msg.msg_iter, ITER_SOURCE, &bvec, 1, len);
	ret = sock_sendmsg(queue->sock, &msg);
	if (unlikely(ret <= 0))
		return ret;

	len -= ret;
	if (!len) {
		req->state = NVME_TCP_SEND_DATA;
		if (queue->data_digest)
			queue->snd_crc = NVME_TCP_CRC_SEED;
		return 1;
	}
	req->offset += ret;

	return -EAGAIN;
}

static int nvme_tcp_try_send_ddgst(struct nvme_tcp_request *req)
{
	struct nvme_tcp_queue *queue = req->queue;
	size_t offset = req->offset;
	u32 h2cdata_left = req->h2cdata_left;
	int ret;
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT };
	struct kvec iov = {
		.iov_base = (u8 *)&req->ddgst + req->offset,
		.iov_len = NVME_TCP_DIGEST_LENGTH - req->offset
	};

	if (nvme_tcp_queue_more(queue))
		msg.msg_flags |= MSG_MORE;
	else
		msg.msg_flags |= MSG_EOR;

	ret = kernel_sendmsg(queue->sock, &msg, &iov, 1, iov.iov_len);
	if (unlikely(ret <= 0))
		return ret;

	if (offset + ret == NVME_TCP_DIGEST_LENGTH) {
		if (h2cdata_left)
			nvme_tcp_setup_h2c_data_pdu(req);
		else
			nvme_tcp_done_send_req(queue);
		return 1;
	}

	req->offset += ret;
	return -EAGAIN;
}

static int nvme_tcp_try_send(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_request *req;
	unsigned int noreclaim_flag;
	int ret = 1;

	if (!queue->request) {
		queue->request = nvme_tcp_fetch_request(queue);
		if (!queue->request)
			return 0;
	}
	req = queue->request;

	noreclaim_flag = memalloc_noreclaim_save();
	if (req->state == NVME_TCP_SEND_CMD_PDU) {
		ret = nvme_tcp_try_send_cmd_pdu(req);
		if (ret <= 0)
			goto done;
		if (!nvme_tcp_has_inline_data(req))
			goto out;
	}

	if (req->state == NVME_TCP_SEND_H2C_PDU) {
		ret = nvme_tcp_try_send_data_pdu(req);
		if (ret <= 0)
			goto done;
	}

	if (req->state == NVME_TCP_SEND_DATA) {
		ret = nvme_tcp_try_send_data(req);
		if (ret <= 0)
			goto done;
	}

	if (req->state == NVME_TCP_SEND_DDGST)
		ret = nvme_tcp_try_send_ddgst(req);
done:
	if (ret == -EAGAIN) {
		ret = 0;
	} else if (ret < 0) {
		dev_err(queue->ctrl->ctrl.device,
			"failed to send request %d\n", ret);
		nvme_tcp_fail_request(queue->request);
		nvme_tcp_done_send_req(queue);
	}
out:
	memalloc_noreclaim_restore(noreclaim_flag);
	return ret;
}

static int nvme_tcp_try_recv(struct nvme_tcp_queue *queue)
{
	struct socket *sock = queue->sock;
	struct sock *sk = sock->sk;
	read_descriptor_t rd_desc;
	int consumed;

	rd_desc.arg.data = queue;
	rd_desc.count = 1;
	lock_sock(sk);
	queue->nr_cqe = 0;
	consumed = sock->ops->read_sock(sk, &rd_desc, nvme_tcp_recv_skb);
	release_sock(sk);
	return consumed == -EAGAIN ? 0 : consumed;
}

static void nvme_tcp_io_work(struct work_struct *w)
{
	struct nvme_tcp_queue *queue =
		container_of(w, struct nvme_tcp_queue, io_work);
	unsigned long deadline = jiffies + msecs_to_jiffies(1);

	do {
		bool pending = false;
		int result;

		if (mutex_trylock(&queue->send_mutex)) {
			result = nvme_tcp_try_send(queue);
			mutex_unlock(&queue->send_mutex);
			if (result > 0)
				pending = true;
			else if (unlikely(result < 0))
				break;
		}

		result = nvme_tcp_try_recv(queue);
		if (result > 0)
			pending = true;
		else if (unlikely(result < 0))
			return;

		/* did we get some space after spending time in recv? */
		if (nvme_tcp_queue_has_pending(queue) &&
		    sk_stream_is_writeable(queue->sock->sk))
			pending = true;

		if (!pending || !queue->rd_enabled)
			return;

	} while (!time_after(jiffies, deadline)); /* quota is exhausted */

	queue_work_on(queue->io_cpu, nvme_tcp_wq, &queue->io_work);
}

static void nvme_tcp_free_async_req(struct nvme_tcp_ctrl *ctrl)
{
	struct nvme_tcp_request *async = &ctrl->async_req;

	page_frag_free(async->pdu);
}

static int nvme_tcp_alloc_async_req(struct nvme_tcp_ctrl *ctrl)
{
	struct nvme_tcp_queue *queue = &ctrl->queues[0];
	struct nvme_tcp_request *async = &ctrl->async_req;
	u8 hdgst = nvme_tcp_hdgst_len(queue);

	async->pdu = page_frag_alloc(&queue->pf_cache,
		sizeof(struct nvme_tcp_cmd_pdu) + hdgst,
		GFP_KERNEL | __GFP_ZERO);
	if (!async->pdu)
		return -ENOMEM;

	async->queue = &ctrl->queues[0];
	return 0;
}

static void nvme_tcp_free_queue(struct nvme_ctrl *nctrl, int qid)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	struct nvme_tcp_queue *queue = &ctrl->queues[qid];
	unsigned int noreclaim_flag;

	if (!test_and_clear_bit(NVME_TCP_Q_ALLOCATED, &queue->flags))
		return;

	page_frag_cache_drain(&queue->pf_cache);

	noreclaim_flag = memalloc_noreclaim_save();
	/* ->sock will be released by fput() */
	fput(queue->sock->file);
	queue->sock = NULL;
	memalloc_noreclaim_restore(noreclaim_flag);

	kfree(queue->pdu);
	mutex_destroy(&queue->send_mutex);
	mutex_destroy(&queue->queue_lock);
}

static int nvme_tcp_init_connection(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_icreq_pdu *icreq;
	struct nvme_tcp_icresp_pdu *icresp;
	char cbuf[CMSG_LEN(sizeof(char))] = {};
	u8 ctype;
	struct msghdr msg = {};
	struct kvec iov;
	bool ctrl_hdgst, ctrl_ddgst;
	u32 maxh2cdata;
	int ret;

	icreq = kzalloc(sizeof(*icreq), GFP_KERNEL);
	if (!icreq)
		return -ENOMEM;

	icresp = kzalloc(sizeof(*icresp), GFP_KERNEL);
	if (!icresp) {
		ret = -ENOMEM;
		goto free_icreq;
	}

	icreq->hdr.type = nvme_tcp_icreq;
	icreq->hdr.hlen = sizeof(*icreq);
	icreq->hdr.pdo = 0;
	icreq->hdr.plen = cpu_to_le32(icreq->hdr.hlen);
	icreq->pfv = cpu_to_le16(NVME_TCP_PFV_1_0);
	icreq->maxr2t = 0; /* single inflight r2t supported */
	icreq->hpda = 0; /* no alignment constraint */
	if (queue->hdr_digest)
		icreq->digest |= NVME_TCP_HDR_DIGEST_ENABLE;
	if (queue->data_digest)
		icreq->digest |= NVME_TCP_DATA_DIGEST_ENABLE;

	iov.iov_base = icreq;
	iov.iov_len = sizeof(*icreq);
	ret = kernel_sendmsg(queue->sock, &msg, &iov, 1, iov.iov_len);
	if (ret < 0) {
		pr_warn("queue %d: failed to send icreq, error %d\n",
			nvme_tcp_queue_id(queue), ret);
		goto free_icresp;
	}

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = icresp;
	iov.iov_len = sizeof(*icresp);
	if (nvme_tcp_queue_tls(queue)) {
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);
	}
	msg.msg_flags = MSG_WAITALL;
	ret = kernel_recvmsg(queue->sock, &msg, &iov, 1,
			iov.iov_len, msg.msg_flags);
	if (ret >= 0 && ret < sizeof(*icresp))
		ret = -ECONNRESET;
	if (ret < 0) {
		pr_warn("queue %d: failed to receive icresp, error %d\n",
			nvme_tcp_queue_id(queue), ret);
		goto free_icresp;
	}
	ret = -ENOTCONN;
	if (nvme_tcp_queue_tls(queue)) {
		ctype = tls_get_record_type(queue->sock->sk,
					    (struct cmsghdr *)cbuf);
		if (ctype != TLS_RECORD_TYPE_DATA) {
			pr_err("queue %d: unhandled TLS record %d\n",
			       nvme_tcp_queue_id(queue), ctype);
			goto free_icresp;
		}
	}
	ret = -EINVAL;
	if (icresp->hdr.type != nvme_tcp_icresp) {
		pr_err("queue %d: bad type returned %d\n",
			nvme_tcp_queue_id(queue), icresp->hdr.type);
		goto free_icresp;
	}

	if (le32_to_cpu(icresp->hdr.plen) != sizeof(*icresp)) {
		pr_err("queue %d: bad pdu length returned %d\n",
			nvme_tcp_queue_id(queue), icresp->hdr.plen);
		goto free_icresp;
	}

	if (icresp->pfv != NVME_TCP_PFV_1_0) {
		pr_err("queue %d: bad pfv returned %d\n",
			nvme_tcp_queue_id(queue), icresp->pfv);
		goto free_icresp;
	}

	ctrl_ddgst = !!(icresp->digest & NVME_TCP_DATA_DIGEST_ENABLE);
	if ((queue->data_digest && !ctrl_ddgst) ||
	    (!queue->data_digest && ctrl_ddgst)) {
		pr_err("queue %d: data digest mismatch host: %s ctrl: %s\n",
			nvme_tcp_queue_id(queue),
			queue->data_digest ? "enabled" : "disabled",
			ctrl_ddgst ? "enabled" : "disabled");
		goto free_icresp;
	}

	ctrl_hdgst = !!(icresp->digest & NVME_TCP_HDR_DIGEST_ENABLE);
	if ((queue->hdr_digest && !ctrl_hdgst) ||
	    (!queue->hdr_digest && ctrl_hdgst)) {
		pr_err("queue %d: header digest mismatch host: %s ctrl: %s\n",
			nvme_tcp_queue_id(queue),
			queue->hdr_digest ? "enabled" : "disabled",
			ctrl_hdgst ? "enabled" : "disabled");
		goto free_icresp;
	}

	if (icresp->cpda != 0) {
		pr_err("queue %d: unsupported cpda returned %d\n",
			nvme_tcp_queue_id(queue), icresp->cpda);
		goto free_icresp;
	}

	maxh2cdata = le32_to_cpu(icresp->maxdata);
	if ((maxh2cdata % 4) || (maxh2cdata < NVME_TCP_MIN_MAXH2CDATA)) {
		pr_err("queue %d: invalid maxh2cdata returned %u\n",
		       nvme_tcp_queue_id(queue), maxh2cdata);
		goto free_icresp;
	}
	queue->maxh2cdata = maxh2cdata;

	ret = 0;
free_icresp:
	kfree(icresp);
free_icreq:
	kfree(icreq);
	return ret;
}

static bool nvme_tcp_admin_queue(struct nvme_tcp_queue *queue)
{
	return nvme_tcp_queue_id(queue) == 0;
}

static bool nvme_tcp_default_queue(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_ctrl *ctrl = queue->ctrl;
	int qid = nvme_tcp_queue_id(queue);

	return !nvme_tcp_admin_queue(queue) &&
		qid < 1 + ctrl->io_queues[HCTX_TYPE_DEFAULT];
}

static bool nvme_tcp_read_queue(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_ctrl *ctrl = queue->ctrl;
	int qid = nvme_tcp_queue_id(queue);

	return !nvme_tcp_admin_queue(queue) &&
		!nvme_tcp_default_queue(queue) &&
		qid < 1 + ctrl->io_queues[HCTX_TYPE_DEFAULT] +
			  ctrl->io_queues[HCTX_TYPE_READ];
}

static bool nvme_tcp_poll_queue(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_ctrl *ctrl = queue->ctrl;
	int qid = nvme_tcp_queue_id(queue);

	return !nvme_tcp_admin_queue(queue) &&
		!nvme_tcp_default_queue(queue) &&
		!nvme_tcp_read_queue(queue) &&
		qid < 1 + ctrl->io_queues[HCTX_TYPE_DEFAULT] +
			  ctrl->io_queues[HCTX_TYPE_READ] +
			  ctrl->io_queues[HCTX_TYPE_POLL];
}

/*
 * Track the number of queues assigned to each cpu using a global per-cpu
 * counter and select the least used cpu from the mq_map. Our goal is to spread
 * different controllers I/O threads across different cpu cores.
 *
 * Note that the accounting is not 100% perfect, but we don't need to be, we're
 * simply putting our best effort to select the best candidate cpu core that we
 * find at any given point.
 */
static void nvme_tcp_set_queue_io_cpu(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_ctrl *ctrl = queue->ctrl;
	struct blk_mq_tag_set *set = &ctrl->tag_set;
	int qid = nvme_tcp_queue_id(queue) - 1;
	unsigned int *mq_map = NULL;
	int cpu, min_queues = INT_MAX, io_cpu;

	if (wq_unbound)
		goto out;

	if (nvme_tcp_default_queue(queue))
		mq_map = set->map[HCTX_TYPE_DEFAULT].mq_map;
	else if (nvme_tcp_read_queue(queue))
		mq_map = set->map[HCTX_TYPE_READ].mq_map;
	else if (nvme_tcp_poll_queue(queue))
		mq_map = set->map[HCTX_TYPE_POLL].mq_map;

	if (WARN_ON(!mq_map))
		goto out;

	/* Search for the least used cpu from the mq_map */
	io_cpu = WORK_CPU_UNBOUND;
	for_each_online_cpu(cpu) {
		int num_queues = atomic_read(&nvme_tcp_cpu_queues[cpu]);

		if (mq_map[cpu] != qid)
			continue;
		if (num_queues < min_queues) {
			io_cpu = cpu;
			min_queues = num_queues;
		}
	}
	if (io_cpu != WORK_CPU_UNBOUND) {
		queue->io_cpu = io_cpu;
		atomic_inc(&nvme_tcp_cpu_queues[io_cpu]);
		set_bit(NVME_TCP_Q_IO_CPU_SET, &queue->flags);
	}
out:
	dev_dbg(ctrl->ctrl.device, "queue %d: using cpu %d\n",
		qid, queue->io_cpu);
}

static void nvme_tcp_tls_done(void *data, int status, key_serial_t pskid)
{
	struct nvme_tcp_queue *queue = data;
	struct nvme_tcp_ctrl *ctrl = queue->ctrl;
	int qid = nvme_tcp_queue_id(queue);
	struct key *tls_key;

	dev_dbg(ctrl->ctrl.device, "queue %d: TLS handshake done, key %x, status %d\n",
		qid, pskid, status);

	if (status) {
		queue->tls_err = -status;
		goto out_complete;
	}

	tls_key = nvme_tls_key_lookup(pskid);
	if (IS_ERR(tls_key)) {
		dev_warn(ctrl->ctrl.device, "queue %d: Invalid key %x\n",
			 qid, pskid);
		queue->tls_err = -ENOKEY;
	} else {
		queue->tls_enabled = true;
		if (qid == 0)
			ctrl->ctrl.tls_pskid = key_serial(tls_key);
		key_put(tls_key);
		queue->tls_err = 0;
	}

out_complete:
	complete(&queue->tls_complete);
}

static int nvme_tcp_start_tls(struct nvme_ctrl *nctrl,
			      struct nvme_tcp_queue *queue,
			      key_serial_t pskid)
{
	int qid = nvme_tcp_queue_id(queue);
	int ret;
	struct tls_handshake_args args;
	unsigned long tmo = tls_handshake_timeout * HZ;
	key_serial_t keyring = nvme_keyring_id();

	dev_dbg(nctrl->device, "queue %d: start TLS with key %x\n",
		qid, pskid);
	memset(&args, 0, sizeof(args));
	args.ta_sock = queue->sock;
	args.ta_done = nvme_tcp_tls_done;
	args.ta_data = queue;
	args.ta_my_peerids[0] = pskid;
	args.ta_num_peerids = 1;
	if (nctrl->opts->keyring)
		keyring = key_serial(nctrl->opts->keyring);
	args.ta_keyring = keyring;
	args.ta_timeout_ms = tls_handshake_timeout * 1000;
	queue->tls_err = -EOPNOTSUPP;
	init_completion(&queue->tls_complete);
	ret = tls_client_hello_psk(&args, GFP_KERNEL);
	if (ret) {
		dev_err(nctrl->device, "queue %d: failed to start TLS: %d\n",
			qid, ret);
		return ret;
	}
	ret = wait_for_completion_interruptible_timeout(&queue->tls_complete, tmo);
	if (ret <= 0) {
		if (ret == 0)
			ret = -ETIMEDOUT;

		dev_err(nctrl->device,
			"queue %d: TLS handshake failed, error %d\n",
			qid, ret);
		tls_handshake_cancel(queue->sock->sk);
	} else {
		if (queue->tls_err) {
			dev_err(nctrl->device,
				"queue %d: TLS handshake complete, error %d\n",
				qid, queue->tls_err);
		} else {
			dev_dbg(nctrl->device,
				"queue %d: TLS handshake complete\n", qid);
		}
		ret = queue->tls_err;
	}
	return ret;
}

static int nvme_tcp_alloc_queue(struct nvme_ctrl *nctrl, int qid,
				key_serial_t pskid)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	struct nvme_tcp_queue *queue = &ctrl->queues[qid];
	int ret, rcv_pdu_size;
	struct file *sock_file;

	mutex_init(&queue->queue_lock);
	queue->ctrl = ctrl;
	init_llist_head(&queue->req_list);
	INIT_LIST_HEAD(&queue->send_list);
	mutex_init(&queue->send_mutex);
	INIT_WORK(&queue->io_work, nvme_tcp_io_work);

	if (qid > 0)
		queue->cmnd_capsule_len = nctrl->ioccsz * 16;
	else
		queue->cmnd_capsule_len = sizeof(struct nvme_command) +
						NVME_TCP_ADMIN_CCSZ;

	ret = sock_create_kern(current->nsproxy->net_ns,
			ctrl->addr.ss_family, SOCK_STREAM,
			IPPROTO_TCP, &queue->sock);
	if (ret) {
		dev_err(nctrl->device,
			"failed to create socket: %d\n", ret);
		goto err_destroy_mutex;
	}

	sock_file = sock_alloc_file(queue->sock, O_CLOEXEC, NULL);
	if (IS_ERR(sock_file)) {
		ret = PTR_ERR(sock_file);
		goto err_destroy_mutex;
	}

	sk_net_refcnt_upgrade(queue->sock->sk);
	nvme_tcp_reclassify_socket(queue->sock);

	/* Single syn retry */
	tcp_sock_set_syncnt(queue->sock->sk, 1);

	/* Set TCP no delay */
	tcp_sock_set_nodelay(queue->sock->sk);

	/*
	 * Cleanup whatever is sitting in the TCP transmit queue on socket
	 * close. This is done to prevent stale data from being sent should
	 * the network connection be restored before TCP times out.
	 */
	sock_no_linger(queue->sock->sk);

	if (so_priority > 0)
		sock_set_priority(queue->sock->sk, so_priority);

	/* Set socket type of service */
	if (nctrl->opts->tos >= 0)
		ip_sock_set_tos(queue->sock->sk, nctrl->opts->tos);

	/* Set 10 seconds timeout for icresp recvmsg */
	queue->sock->sk->sk_rcvtimeo = 10 * HZ;

	queue->sock->sk->sk_allocation = GFP_ATOMIC;
	queue->sock->sk->sk_use_task_frag = false;
	queue->io_cpu = WORK_CPU_UNBOUND;
	queue->request = NULL;
	queue->data_remaining = 0;
	queue->ddgst_remaining = 0;
	queue->pdu_remaining = 0;
	queue->pdu_offset = 0;
	sk_set_memalloc(queue->sock->sk);

	if (nctrl->opts->mask & NVMF_OPT_HOST_TRADDR) {
		ret = kernel_bind(queue->sock, (struct sockaddr *)&ctrl->src_addr,
			sizeof(ctrl->src_addr));
		if (ret) {
			dev_err(nctrl->device,
				"failed to bind queue %d socket %d\n",
				qid, ret);
			goto err_sock;
		}
	}

	if (nctrl->opts->mask & NVMF_OPT_HOST_IFACE) {
		char *iface = nctrl->opts->host_iface;
		sockptr_t optval = KERNEL_SOCKPTR(iface);

		ret = sock_setsockopt(queue->sock, SOL_SOCKET, SO_BINDTODEVICE,
				      optval, strlen(iface));
		if (ret) {
			dev_err(nctrl->device,
			  "failed to bind to interface %s queue %d err %d\n",
			  iface, qid, ret);
			goto err_sock;
		}
	}

	queue->hdr_digest = nctrl->opts->hdr_digest;
	queue->data_digest = nctrl->opts->data_digest;

	rcv_pdu_size = sizeof(struct nvme_tcp_rsp_pdu) +
			nvme_tcp_hdgst_len(queue);
	queue->pdu = kmalloc(rcv_pdu_size, GFP_KERNEL);
	if (!queue->pdu) {
		ret = -ENOMEM;
		goto err_sock;
	}

	dev_dbg(nctrl->device, "connecting queue %d\n",
			nvme_tcp_queue_id(queue));

	ret = kernel_connect(queue->sock, (struct sockaddr *)&ctrl->addr,
		sizeof(ctrl->addr), 0);
	if (ret) {
		dev_err(nctrl->device,
			"failed to connect socket: %d\n", ret);
		goto err_rcv_pdu;
	}

	/* If PSKs are configured try to start TLS */
	if (nvme_tcp_tls_configured(nctrl) && pskid) {
		ret = nvme_tcp_start_tls(nctrl, queue, pskid);
		if (ret)
			goto err_init_connect;
	}

	ret = nvme_tcp_init_connection(queue);
	if (ret)
		goto err_init_connect;

	set_bit(NVME_TCP_Q_ALLOCATED, &queue->flags);

	return 0;

err_init_connect:
	kernel_sock_shutdown(queue->sock, SHUT_RDWR);
err_rcv_pdu:
	kfree(queue->pdu);
err_sock:
	/* ->sock will be released by fput() */
	fput(queue->sock->file);
	queue->sock = NULL;
err_destroy_mutex:
	mutex_destroy(&queue->send_mutex);
	mutex_destroy(&queue->queue_lock);
	return ret;
}

static void nvme_tcp_restore_sock_ops(struct nvme_tcp_queue *queue)
{
	struct socket *sock = queue->sock;

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_user_data  = NULL;
	sock->sk->sk_data_ready = queue->data_ready;
	sock->sk->sk_state_change = queue->state_change;
	sock->sk->sk_write_space  = queue->write_space;
	write_unlock_bh(&sock->sk->sk_callback_lock);
}

static void __nvme_tcp_stop_queue(struct nvme_tcp_queue *queue)
{
	kernel_sock_shutdown(queue->sock, SHUT_RDWR);
	nvme_tcp_restore_sock_ops(queue);
	cancel_work_sync(&queue->io_work);
}

static void nvme_tcp_stop_queue_nowait(struct nvme_ctrl *nctrl, int qid)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	struct nvme_tcp_queue *queue = &ctrl->queues[qid];

	if (!test_bit(NVME_TCP_Q_ALLOCATED, &queue->flags))
		return;

	if (test_and_clear_bit(NVME_TCP_Q_IO_CPU_SET, &queue->flags))
		atomic_dec(&nvme_tcp_cpu_queues[queue->io_cpu]);

	mutex_lock(&queue->queue_lock);
	if (test_and_clear_bit(NVME_TCP_Q_LIVE, &queue->flags))
		__nvme_tcp_stop_queue(queue);
	/* Stopping the queue will disable TLS */
	queue->tls_enabled = false;
	mutex_unlock(&queue->queue_lock);
}

static void nvme_tcp_wait_queue(struct nvme_ctrl *nctrl, int qid)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	struct nvme_tcp_queue *queue = &ctrl->queues[qid];
	int timeout = 100;

	while (timeout > 0) {
		if (!test_bit(NVME_TCP_Q_ALLOCATED, &queue->flags) ||
		    !sk_wmem_alloc_get(queue->sock->sk))
			return;
		msleep(2);
		timeout -= 2;
	}
	dev_warn(nctrl->device,
		 "qid %d: timeout draining sock wmem allocation expired\n",
		 qid);
}

static void nvme_tcp_stop_queue(struct nvme_ctrl *nctrl, int qid)
{
	nvme_tcp_stop_queue_nowait(nctrl, qid);
	nvme_tcp_wait_queue(nctrl, qid);
}


static void nvme_tcp_setup_sock_ops(struct nvme_tcp_queue *queue)
{
	write_lock_bh(&queue->sock->sk->sk_callback_lock);
	queue->sock->sk->sk_user_data = queue;
	queue->state_change = queue->sock->sk->sk_state_change;
	queue->data_ready = queue->sock->sk->sk_data_ready;
	queue->write_space = queue->sock->sk->sk_write_space;
	queue->sock->sk->sk_data_ready = nvme_tcp_data_ready;
	queue->sock->sk->sk_state_change = nvme_tcp_state_change;
	queue->sock->sk->sk_write_space = nvme_tcp_write_space;
#ifdef CONFIG_NET_RX_BUSY_POLL
	queue->sock->sk->sk_ll_usec = 1;
#endif
	write_unlock_bh(&queue->sock->sk->sk_callback_lock);
}

static int nvme_tcp_start_queue(struct nvme_ctrl *nctrl, int idx)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	struct nvme_tcp_queue *queue = &ctrl->queues[idx];
	int ret;

	queue->rd_enabled = true;
	nvme_tcp_init_recv_ctx(queue);
	nvme_tcp_setup_sock_ops(queue);

	if (idx) {
		nvme_tcp_set_queue_io_cpu(queue);
		ret = nvmf_connect_io_queue(nctrl, idx);
	} else
		ret = nvmf_connect_admin_queue(nctrl);

	if (!ret) {
		set_bit(NVME_TCP_Q_LIVE, &queue->flags);
	} else {
		if (test_bit(NVME_TCP_Q_ALLOCATED, &queue->flags))
			__nvme_tcp_stop_queue(queue);
		dev_err(nctrl->device,
			"failed to connect queue: %d ret=%d\n", idx, ret);
	}
	return ret;
}

static void nvme_tcp_free_admin_queue(struct nvme_ctrl *ctrl)
{
	if (to_tcp_ctrl(ctrl)->async_req.pdu) {
		cancel_work_sync(&ctrl->async_event_work);
		nvme_tcp_free_async_req(to_tcp_ctrl(ctrl));
		to_tcp_ctrl(ctrl)->async_req.pdu = NULL;
	}

	nvme_tcp_free_queue(ctrl, 0);
}

static void nvme_tcp_free_io_queues(struct nvme_ctrl *ctrl)
{
	int i;

	for (i = 1; i < ctrl->queue_count; i++)
		nvme_tcp_free_queue(ctrl, i);
}

static void nvme_tcp_stop_io_queues(struct nvme_ctrl *ctrl)
{
	int i;

	for (i = 1; i < ctrl->queue_count; i++)
		nvme_tcp_stop_queue_nowait(ctrl, i);
	for (i = 1; i < ctrl->queue_count; i++)
		nvme_tcp_wait_queue(ctrl, i);
}

static int nvme_tcp_start_io_queues(struct nvme_ctrl *ctrl,
				    int first, int last)
{
	int i, ret;

	for (i = first; i < last; i++) {
		ret = nvme_tcp_start_queue(ctrl, i);
		if (ret)
			goto out_stop_queues;
	}

	return 0;

out_stop_queues:
	for (i--; i >= first; i--)
		nvme_tcp_stop_queue(ctrl, i);
	return ret;
}

static int nvme_tcp_alloc_admin_queue(struct nvme_ctrl *ctrl)
{
	int ret;
	key_serial_t pskid = 0;

	if (nvme_tcp_tls_configured(ctrl)) {
		if (ctrl->opts->tls_key)
			pskid = key_serial(ctrl->opts->tls_key);
		else if (ctrl->opts->tls) {
			pskid = nvme_tls_psk_default(ctrl->opts->keyring,
						      ctrl->opts->host->nqn,
						      ctrl->opts->subsysnqn);
			if (!pskid) {
				dev_err(ctrl->device, "no valid PSK found\n");
				return -ENOKEY;
			}
		}
	}

	ret = nvme_tcp_alloc_queue(ctrl, 0, pskid);
	if (ret)
		return ret;

	ret = nvme_tcp_alloc_async_req(to_tcp_ctrl(ctrl));
	if (ret)
		goto out_free_queue;

	return 0;

out_free_queue:
	nvme_tcp_free_queue(ctrl, 0);
	return ret;
}

static int __nvme_tcp_alloc_io_queues(struct nvme_ctrl *ctrl)
{
	int i, ret;

	if (nvme_tcp_tls_configured(ctrl)) {
		if (ctrl->opts->concat) {
			/*
			 * The generated PSK is stored in the
			 * fabric options
			 */
			if (!ctrl->opts->tls_key) {
				dev_err(ctrl->device, "no PSK generated\n");
				return -ENOKEY;
			}
			if (ctrl->tls_pskid &&
			    ctrl->tls_pskid != key_serial(ctrl->opts->tls_key)) {
				dev_err(ctrl->device, "Stale PSK id %08x\n", ctrl->tls_pskid);
				ctrl->tls_pskid = 0;
			}
		} else if (!ctrl->tls_pskid) {
			dev_err(ctrl->device, "no PSK negotiated\n");
			return -ENOKEY;
		}
	}

	for (i = 1; i < ctrl->queue_count; i++) {
		ret = nvme_tcp_alloc_queue(ctrl, i,
				ctrl->tls_pskid);
		if (ret)
			goto out_free_queues;
	}

	return 0;

out_free_queues:
	for (i--; i >= 1; i--)
		nvme_tcp_free_queue(ctrl, i);

	return ret;
}

static int nvme_tcp_alloc_io_queues(struct nvme_ctrl *ctrl)
{
	unsigned int nr_io_queues;
	int ret;

	nr_io_queues = nvmf_nr_io_queues(ctrl->opts);
	ret = nvme_set_queue_count(ctrl, &nr_io_queues);
	if (ret)
		return ret;

	if (nr_io_queues == 0) {
		dev_err(ctrl->device,
			"unable to set any I/O queues\n");
		return -ENOMEM;
	}

	ctrl->queue_count = nr_io_queues + 1;
	dev_info(ctrl->device,
		"creating %d I/O queues.\n", nr_io_queues);

	nvmf_set_io_queues(ctrl->opts, nr_io_queues,
			   to_tcp_ctrl(ctrl)->io_queues);
	return __nvme_tcp_alloc_io_queues(ctrl);
}

static int nvme_tcp_configure_io_queues(struct nvme_ctrl *ctrl, bool new)
{
	int ret, nr_queues;

	ret = nvme_tcp_alloc_io_queues(ctrl);
	if (ret)
		return ret;

	if (new) {
		ret = nvme_alloc_io_tag_set(ctrl, &to_tcp_ctrl(ctrl)->tag_set,
				&nvme_tcp_mq_ops,
				ctrl->opts->nr_poll_queues ? HCTX_MAX_TYPES : 2,
				sizeof(struct nvme_tcp_request));
		if (ret)
			goto out_free_io_queues;
	}

	/*
	 * Only start IO queues for which we have allocated the tagset
	 * and limitted it to the available queues. On reconnects, the
	 * queue number might have changed.
	 */
	nr_queues = min(ctrl->tagset->nr_hw_queues + 1, ctrl->queue_count);
	ret = nvme_tcp_start_io_queues(ctrl, 1, nr_queues);
	if (ret)
		goto out_cleanup_connect_q;

	if (!new) {
		nvme_start_freeze(ctrl);
		nvme_unquiesce_io_queues(ctrl);
		if (!nvme_wait_freeze_timeout(ctrl, NVME_IO_TIMEOUT)) {
			/*
			 * If we timed out waiting for freeze we are likely to
			 * be stuck.  Fail the controller initialization just
			 * to be safe.
			 */
			ret = -ENODEV;
			nvme_unfreeze(ctrl);
			goto out_wait_freeze_timed_out;
		}
		blk_mq_update_nr_hw_queues(ctrl->tagset,
			ctrl->queue_count - 1);
		nvme_unfreeze(ctrl);
	}

	/*
	 * If the number of queues has increased (reconnect case)
	 * start all new queues now.
	 */
	ret = nvme_tcp_start_io_queues(ctrl, nr_queues,
				       ctrl->tagset->nr_hw_queues + 1);
	if (ret)
		goto out_wait_freeze_timed_out;

	return 0;

out_wait_freeze_timed_out:
	nvme_quiesce_io_queues(ctrl);
	nvme_sync_io_queues(ctrl);
	nvme_tcp_stop_io_queues(ctrl);
out_cleanup_connect_q:
	nvme_cancel_tagset(ctrl);
	if (new)
		nvme_remove_io_tag_set(ctrl);
out_free_io_queues:
	nvme_tcp_free_io_queues(ctrl);
	return ret;
}

static int nvme_tcp_configure_admin_queue(struct nvme_ctrl *ctrl, bool new)
{
	int error;

	error = nvme_tcp_alloc_admin_queue(ctrl);
	if (error)
		return error;

	if (new) {
		error = nvme_alloc_admin_tag_set(ctrl,
				&to_tcp_ctrl(ctrl)->admin_tag_set,
				&nvme_tcp_admin_mq_ops,
				sizeof(struct nvme_tcp_request));
		if (error)
			goto out_free_queue;
	}

	error = nvme_tcp_start_queue(ctrl, 0);
	if (error)
		goto out_cleanup_tagset;

	error = nvme_enable_ctrl(ctrl);
	if (error)
		goto out_stop_queue;

	nvme_unquiesce_admin_queue(ctrl);

	error = nvme_init_ctrl_finish(ctrl, false);
	if (error)
		goto out_quiesce_queue;

	return 0;

out_quiesce_queue:
	nvme_quiesce_admin_queue(ctrl);
	blk_sync_queue(ctrl->admin_q);
out_stop_queue:
	nvme_tcp_stop_queue(ctrl, 0);
	nvme_cancel_admin_tagset(ctrl);
out_cleanup_tagset:
	if (new)
		nvme_remove_admin_tag_set(ctrl);
out_free_queue:
	nvme_tcp_free_admin_queue(ctrl);
	return error;
}

static void nvme_tcp_teardown_admin_queue(struct nvme_ctrl *ctrl,
		bool remove)
{
	nvme_quiesce_admin_queue(ctrl);
	blk_sync_queue(ctrl->admin_q);
	nvme_tcp_stop_queue(ctrl, 0);
	nvme_cancel_admin_tagset(ctrl);
	if (remove) {
		nvme_unquiesce_admin_queue(ctrl);
		nvme_remove_admin_tag_set(ctrl);
	}
	nvme_tcp_free_admin_queue(ctrl);
	if (ctrl->tls_pskid) {
		dev_dbg(ctrl->device, "Wipe negotiated TLS_PSK %08x\n",
			ctrl->tls_pskid);
		ctrl->tls_pskid = 0;
	}
}

static void nvme_tcp_teardown_io_queues(struct nvme_ctrl *ctrl,
		bool remove)
{
	if (ctrl->queue_count <= 1)
		return;
	nvme_quiesce_io_queues(ctrl);
	nvme_sync_io_queues(ctrl);
	nvme_tcp_stop_io_queues(ctrl);
	nvme_cancel_tagset(ctrl);
	if (remove) {
		nvme_unquiesce_io_queues(ctrl);
		nvme_remove_io_tag_set(ctrl);
	}
	nvme_tcp_free_io_queues(ctrl);
}

static void nvme_tcp_reconnect_or_remove(struct nvme_ctrl *ctrl,
		int status)
{
	enum nvme_ctrl_state state = nvme_ctrl_state(ctrl);

	/* If we are resetting/deleting then do nothing */
	if (state != NVME_CTRL_CONNECTING) {
		WARN_ON_ONCE(state == NVME_CTRL_NEW || state == NVME_CTRL_LIVE);
		return;
	}

	if (nvmf_should_reconnect(ctrl, status)) {
		dev_info(ctrl->device, "Reconnecting in %d seconds...\n",
			ctrl->opts->reconnect_delay);
		queue_delayed_work(nvme_wq, &to_tcp_ctrl(ctrl)->connect_work,
				ctrl->opts->reconnect_delay * HZ);
	} else {
		dev_info(ctrl->device, "Removing controller (%d)...\n",
			 status);
		nvme_delete_ctrl(ctrl);
	}
}

/*
 * The TLS key is set by secure concatenation after negotiation has been
 * completed on the admin queue. We need to revoke the key when:
 * - concatenation is enabled (otherwise it's a static key set by the user)
 * and
 * - the generated key is present in ctrl->tls_key (otherwise there's nothing
 *   to revoke)
 * and
 * - a valid PSK key ID has been set in ctrl->tls_pskid (otherwise TLS
 *   negotiation has not run).
 *
 * We cannot always revoke the key as nvme_tcp_alloc_admin_queue() is called
 * twice during secure concatenation, once on a 'normal' connection to run the
 * DH-HMAC-CHAP negotiation (which generates the key, so it _must not_ be set),
 * and once after the negotiation (which uses the key, so it _must_ be set).
 */
static bool nvme_tcp_key_revoke_needed(struct nvme_ctrl *ctrl)
{
	return ctrl->opts->concat && ctrl->opts->tls_key && ctrl->tls_pskid;
}

static int nvme_tcp_setup_ctrl(struct nvme_ctrl *ctrl, bool new)
{
	struct nvmf_ctrl_options *opts = ctrl->opts;
	int ret;

	ret = nvme_tcp_configure_admin_queue(ctrl, new);
	if (ret)
		return ret;

	if (ctrl->opts->concat && !ctrl->tls_pskid) {
		/* See comments for nvme_tcp_key_revoke_needed() */
		dev_dbg(ctrl->device, "restart admin queue for secure concatenation\n");
		nvme_stop_keep_alive(ctrl);
		nvme_tcp_teardown_admin_queue(ctrl, false);
		ret = nvme_tcp_configure_admin_queue(ctrl, false);
		if (ret)
			goto destroy_admin;
	}

	if (ctrl->icdoff) {
		ret = -EOPNOTSUPP;
		dev_err(ctrl->device, "icdoff is not supported!\n");
		goto destroy_admin;
	}

	if (!nvme_ctrl_sgl_supported(ctrl)) {
		ret = -EOPNOTSUPP;
		dev_err(ctrl->device, "Mandatory sgls are not supported!\n");
		goto destroy_admin;
	}

	if (opts->queue_size > ctrl->sqsize + 1)
		dev_warn(ctrl->device,
			"queue_size %zu > ctrl sqsize %u, clamping down\n",
			opts->queue_size, ctrl->sqsize + 1);

	if (ctrl->sqsize + 1 > ctrl->maxcmd) {
		dev_warn(ctrl->device,
			"sqsize %u > ctrl maxcmd %u, clamping down\n",
			ctrl->sqsize + 1, ctrl->maxcmd);
		ctrl->sqsize = ctrl->maxcmd - 1;
	}

	if (ctrl->queue_count > 1) {
		ret = nvme_tcp_configure_io_queues(ctrl, new);
		if (ret)
			goto destroy_admin;
	}

	if (!nvme_change_ctrl_state(ctrl, NVME_CTRL_LIVE)) {
		/*
		 * state change failure is ok if we started ctrl delete,
		 * unless we're during creation of a new controller to
		 * avoid races with teardown flow.
		 */
		enum nvme_ctrl_state state = nvme_ctrl_state(ctrl);

		WARN_ON_ONCE(state != NVME_CTRL_DELETING &&
			     state != NVME_CTRL_DELETING_NOIO);
		WARN_ON_ONCE(new);
		ret = -EINVAL;
		goto destroy_io;
	}

	nvme_start_ctrl(ctrl);
	return 0;

destroy_io:
	if (ctrl->queue_count > 1) {
		nvme_quiesce_io_queues(ctrl);
		nvme_sync_io_queues(ctrl);
		nvme_tcp_stop_io_queues(ctrl);
		nvme_cancel_tagset(ctrl);
		if (new)
			nvme_remove_io_tag_set(ctrl);
		nvme_tcp_free_io_queues(ctrl);
	}
destroy_admin:
	nvme_stop_keep_alive(ctrl);
	nvme_tcp_teardown_admin_queue(ctrl, new);
	return ret;
}

static void nvme_tcp_reconnect_ctrl_work(struct work_struct *work)
{
	struct nvme_tcp_ctrl *tcp_ctrl = container_of(to_delayed_work(work),
			struct nvme_tcp_ctrl, connect_work);
	struct nvme_ctrl *ctrl = &tcp_ctrl->ctrl;
	int ret;

	++ctrl->nr_reconnects;

	ret = nvme_tcp_setup_ctrl(ctrl, false);
	if (ret)
		goto requeue;

	dev_info(ctrl->device, "Successfully reconnected (attempt %d/%d)\n",
		 ctrl->nr_reconnects, ctrl->opts->max_reconnects);

	ctrl->nr_reconnects = 0;

	return;

requeue:
	dev_info(ctrl->device, "Failed reconnect attempt %d/%d\n",
		 ctrl->nr_reconnects, ctrl->opts->max_reconnects);
	nvme_tcp_reconnect_or_remove(ctrl, ret);
}

static void nvme_tcp_error_recovery_work(struct work_struct *work)
{
	struct nvme_tcp_ctrl *tcp_ctrl = container_of(work,
				struct nvme_tcp_ctrl, err_work);
	struct nvme_ctrl *ctrl = &tcp_ctrl->ctrl;

	if (nvme_tcp_key_revoke_needed(ctrl))
		nvme_auth_revoke_tls_key(ctrl);
	nvme_stop_keep_alive(ctrl);
	flush_work(&ctrl->async_event_work);
	nvme_tcp_teardown_io_queues(ctrl, false);
	/* unquiesce to fail fast pending requests */
	nvme_unquiesce_io_queues(ctrl);
	nvme_tcp_teardown_admin_queue(ctrl, false);
	nvme_unquiesce_admin_queue(ctrl);
	nvme_auth_stop(ctrl);

	if (!nvme_change_ctrl_state(ctrl, NVME_CTRL_CONNECTING)) {
		/* state change failure is ok if we started ctrl delete */
		enum nvme_ctrl_state state = nvme_ctrl_state(ctrl);

		WARN_ON_ONCE(state != NVME_CTRL_DELETING &&
			     state != NVME_CTRL_DELETING_NOIO);
		return;
	}

	nvme_tcp_reconnect_or_remove(ctrl, 0);
}

static void nvme_tcp_teardown_ctrl(struct nvme_ctrl *ctrl, bool shutdown)
{
	nvme_tcp_teardown_io_queues(ctrl, shutdown);
	nvme_quiesce_admin_queue(ctrl);
	nvme_disable_ctrl(ctrl, shutdown);
	nvme_tcp_teardown_admin_queue(ctrl, shutdown);
}

static void nvme_tcp_delete_ctrl(struct nvme_ctrl *ctrl)
{
	nvme_tcp_teardown_ctrl(ctrl, true);
}

static void nvme_reset_ctrl_work(struct work_struct *work)
{
	struct nvme_ctrl *ctrl =
		container_of(work, struct nvme_ctrl, reset_work);
	int ret;

	if (nvme_tcp_key_revoke_needed(ctrl))
		nvme_auth_revoke_tls_key(ctrl);
	nvme_stop_ctrl(ctrl);
	nvme_tcp_teardown_ctrl(ctrl, false);

	if (!nvme_change_ctrl_state(ctrl, NVME_CTRL_CONNECTING)) {
		/* state change failure is ok if we started ctrl delete */
		enum nvme_ctrl_state state = nvme_ctrl_state(ctrl);

		WARN_ON_ONCE(state != NVME_CTRL_DELETING &&
			     state != NVME_CTRL_DELETING_NOIO);
		return;
	}

	ret = nvme_tcp_setup_ctrl(ctrl, false);
	if (ret)
		goto out_fail;

	return;

out_fail:
	++ctrl->nr_reconnects;
	nvme_tcp_reconnect_or_remove(ctrl, ret);
}

static void nvme_tcp_stop_ctrl(struct nvme_ctrl *ctrl)
{
	flush_work(&to_tcp_ctrl(ctrl)->err_work);
	cancel_delayed_work_sync(&to_tcp_ctrl(ctrl)->connect_work);
}

static void nvme_tcp_free_ctrl(struct nvme_ctrl *nctrl)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);

	if (list_empty(&ctrl->list))
		goto free_ctrl;

	mutex_lock(&nvme_tcp_ctrl_mutex);
	list_del(&ctrl->list);
	mutex_unlock(&nvme_tcp_ctrl_mutex);

	nvmf_free_options(nctrl->opts);
free_ctrl:
	kfree(ctrl->queues);
	kfree(ctrl);
}

static void nvme_tcp_set_sg_null(struct nvme_command *c)
{
	struct nvme_sgl_desc *sg = &c->common.dptr.sgl;

	sg->addr = 0;
	sg->length = 0;
	sg->type = (NVME_TRANSPORT_SGL_DATA_DESC << 4) |
			NVME_SGL_FMT_TRANSPORT_A;
}

static void nvme_tcp_set_sg_inline(struct nvme_tcp_queue *queue,
		struct nvme_command *c, u32 data_len)
{
	struct nvme_sgl_desc *sg = &c->common.dptr.sgl;

	sg->addr = cpu_to_le64(queue->ctrl->ctrl.icdoff);
	sg->length = cpu_to_le32(data_len);
	sg->type = (NVME_SGL_FMT_DATA_DESC << 4) | NVME_SGL_FMT_OFFSET;
}

static void nvme_tcp_set_sg_host_data(struct nvme_command *c,
		u32 data_len)
{
	struct nvme_sgl_desc *sg = &c->common.dptr.sgl;

	sg->addr = 0;
	sg->length = cpu_to_le32(data_len);
	sg->type = (NVME_TRANSPORT_SGL_DATA_DESC << 4) |
			NVME_SGL_FMT_TRANSPORT_A;
}

static void nvme_tcp_submit_async_event(struct nvme_ctrl *arg)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(arg);
	struct nvme_tcp_queue *queue = &ctrl->queues[0];
	struct nvme_tcp_cmd_pdu *pdu = ctrl->async_req.pdu;
	struct nvme_command *cmd = &pdu->cmd;
	u8 hdgst = nvme_tcp_hdgst_len(queue);

	memset(pdu, 0, sizeof(*pdu));
	pdu->hdr.type = nvme_tcp_cmd;
	if (queue->hdr_digest)
		pdu->hdr.flags |= NVME_TCP_F_HDGST;
	pdu->hdr.hlen = sizeof(*pdu);
	pdu->hdr.plen = cpu_to_le32(pdu->hdr.hlen + hdgst);

	cmd->common.opcode = nvme_admin_async_event;
	cmd->common.command_id = NVME_AQ_BLK_MQ_DEPTH;
	cmd->common.flags |= NVME_CMD_SGL_METABUF;
	nvme_tcp_set_sg_null(cmd);

	ctrl->async_req.state = NVME_TCP_SEND_CMD_PDU;
	ctrl->async_req.offset = 0;
	ctrl->async_req.curr_bio = NULL;
	ctrl->async_req.data_len = 0;
	init_llist_node(&ctrl->async_req.lentry);
	INIT_LIST_HEAD(&ctrl->async_req.entry);

	nvme_tcp_queue_request(&ctrl->async_req, true);
}

static void nvme_tcp_complete_timed_out(struct request *rq)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	struct nvme_ctrl *ctrl = &req->queue->ctrl->ctrl;

	nvme_tcp_stop_queue(ctrl, nvme_tcp_queue_id(req->queue));
	nvmf_complete_timed_out_request(rq);
}

static enum blk_eh_timer_return nvme_tcp_timeout(struct request *rq)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	struct nvme_ctrl *ctrl = &req->queue->ctrl->ctrl;
	struct nvme_tcp_cmd_pdu *pdu = nvme_tcp_req_cmd_pdu(req);
	struct nvme_command *cmd = &pdu->cmd;
	int qid = nvme_tcp_queue_id(req->queue);

	dev_warn(ctrl->device,
		 "I/O tag %d (%04x) type %d opcode %#x (%s) QID %d timeout\n",
		 rq->tag, nvme_cid(rq), pdu->hdr.type, cmd->common.opcode,
		 nvme_fabrics_opcode_str(qid, cmd), qid);

	if (nvme_ctrl_state(ctrl) != NVME_CTRL_LIVE) {
		/*
		 * If we are resetting, connecting or deleting we should
		 * complete immediately because we may block controller
		 * teardown or setup sequence
		 * - ctrl disable/shutdown fabrics requests
		 * - connect requests
		 * - initialization admin requests
		 * - I/O requests that entered after unquiescing and
		 *   the controller stopped responding
		 *
		 * All other requests should be cancelled by the error
		 * recovery work, so it's fine that we fail it here.
		 */
		nvme_tcp_complete_timed_out(rq);
		return BLK_EH_DONE;
	}

	/*
	 * LIVE state should trigger the normal error recovery which will
	 * handle completing this request.
	 */
	nvme_tcp_error_recovery(ctrl);
	return BLK_EH_RESET_TIMER;
}

static blk_status_t nvme_tcp_map_data(struct nvme_tcp_queue *queue,
			struct request *rq)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	struct nvme_tcp_cmd_pdu *pdu = nvme_tcp_req_cmd_pdu(req);
	struct nvme_command *c = &pdu->cmd;

	c->common.flags |= NVME_CMD_SGL_METABUF;

	if (!blk_rq_nr_phys_segments(rq))
		nvme_tcp_set_sg_null(c);
	else if (rq_data_dir(rq) == WRITE &&
	    req->data_len <= nvme_tcp_inline_data_size(req))
		nvme_tcp_set_sg_inline(queue, c, req->data_len);
	else
		nvme_tcp_set_sg_host_data(c, req->data_len);

	return 0;
}

static blk_status_t nvme_tcp_setup_cmd_pdu(struct nvme_ns *ns,
		struct request *rq)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	struct nvme_tcp_cmd_pdu *pdu = nvme_tcp_req_cmd_pdu(req);
	struct nvme_tcp_queue *queue = req->queue;
	u8 hdgst = nvme_tcp_hdgst_len(queue), ddgst = 0;
	blk_status_t ret;

	ret = nvme_setup_cmd(ns, rq);
	if (ret)
		return ret;

	req->state = NVME_TCP_SEND_CMD_PDU;
	req->status = cpu_to_le16(NVME_SC_SUCCESS);
	req->offset = 0;
	req->data_sent = 0;
	req->pdu_len = 0;
	req->pdu_sent = 0;
	req->h2cdata_left = 0;
	req->data_len = blk_rq_nr_phys_segments(rq) ?
				blk_rq_payload_bytes(rq) : 0;
	req->curr_bio = rq->bio;
	if (req->curr_bio && req->data_len)
		nvme_tcp_init_iter(req, rq_data_dir(rq));

	if (rq_data_dir(rq) == WRITE &&
	    req->data_len <= nvme_tcp_inline_data_size(req))
		req->pdu_len = req->data_len;

	pdu->hdr.type = nvme_tcp_cmd;
	pdu->hdr.flags = 0;
	if (queue->hdr_digest)
		pdu->hdr.flags |= NVME_TCP_F_HDGST;
	if (queue->data_digest && req->pdu_len) {
		pdu->hdr.flags |= NVME_TCP_F_DDGST;
		ddgst = nvme_tcp_ddgst_len(queue);
	}
	pdu->hdr.hlen = sizeof(*pdu);
	pdu->hdr.pdo = req->pdu_len ? pdu->hdr.hlen + hdgst : 0;
	pdu->hdr.plen =
		cpu_to_le32(pdu->hdr.hlen + hdgst + req->pdu_len + ddgst);

	ret = nvme_tcp_map_data(queue, rq);
	if (unlikely(ret)) {
		nvme_cleanup_cmd(rq);
		dev_err(queue->ctrl->ctrl.device,
			"Failed to map data (%d)\n", ret);
		return ret;
	}

	return 0;
}

static void nvme_tcp_commit_rqs(struct blk_mq_hw_ctx *hctx)
{
	struct nvme_tcp_queue *queue = hctx->driver_data;

	if (!llist_empty(&queue->req_list))
		queue_work_on(queue->io_cpu, nvme_tcp_wq, &queue->io_work);
}

static blk_status_t nvme_tcp_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct nvme_ns *ns = hctx->queue->queuedata;
	struct nvme_tcp_queue *queue = hctx->driver_data;
	struct request *rq = bd->rq;
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	bool queue_ready = test_bit(NVME_TCP_Q_LIVE, &queue->flags);
	blk_status_t ret;

	if (!nvme_check_ready(&queue->ctrl->ctrl, rq, queue_ready))
		return nvme_fail_nonready_command(&queue->ctrl->ctrl, rq);

	ret = nvme_tcp_setup_cmd_pdu(ns, rq);
	if (unlikely(ret))
		return ret;

	nvme_start_request(rq);

	nvme_tcp_queue_request(req, bd->last);

	return BLK_STS_OK;
}

static void nvme_tcp_map_queues(struct blk_mq_tag_set *set)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(set->driver_data);

	nvmf_map_queues(set, &ctrl->ctrl, ctrl->io_queues);
}

static int nvme_tcp_poll(struct blk_mq_hw_ctx *hctx, struct io_comp_batch *iob)
{
	struct nvme_tcp_queue *queue = hctx->driver_data;
	struct sock *sk = queue->sock->sk;
	int ret;

	if (!test_bit(NVME_TCP_Q_LIVE, &queue->flags))
		return 0;

	set_bit(NVME_TCP_Q_POLLING, &queue->flags);
	if (sk_can_busy_loop(sk) && skb_queue_empty_lockless(&sk->sk_receive_queue))
		sk_busy_loop(sk, true);
	ret = nvme_tcp_try_recv(queue);
	clear_bit(NVME_TCP_Q_POLLING, &queue->flags);
	return ret < 0 ? ret : queue->nr_cqe;
}

static int nvme_tcp_get_address(struct nvme_ctrl *ctrl, char *buf, int size)
{
	struct nvme_tcp_queue *queue = &to_tcp_ctrl(ctrl)->queues[0];
	struct sockaddr_storage src_addr;
	int ret, len;

	len = nvmf_get_address(ctrl, buf, size);

	if (!test_bit(NVME_TCP_Q_LIVE, &queue->flags))
		return len;

	mutex_lock(&queue->queue_lock);

	ret = kernel_getsockname(queue->sock, (struct sockaddr *)&src_addr);
	if (ret > 0) {
		if (len > 0)
			len--; /* strip trailing newline */
		len += scnprintf(buf + len, size - len, "%ssrc_addr=%pISc\n",
				(len) ? "," : "", &src_addr);
	}

	mutex_unlock(&queue->queue_lock);

	return len;
}

static const struct blk_mq_ops nvme_tcp_mq_ops = {
	.queue_rq	= nvme_tcp_queue_rq,
	.commit_rqs	= nvme_tcp_commit_rqs,
	.complete	= nvme_complete_rq,
	.init_request	= nvme_tcp_init_request,
	.exit_request	= nvme_tcp_exit_request,
	.init_hctx	= nvme_tcp_init_hctx,
	.timeout	= nvme_tcp_timeout,
	.map_queues	= nvme_tcp_map_queues,
	.poll		= nvme_tcp_poll,
};

static const struct blk_mq_ops nvme_tcp_admin_mq_ops = {
	.queue_rq	= nvme_tcp_queue_rq,
	.complete	= nvme_complete_rq,
	.init_request	= nvme_tcp_init_request,
	.exit_request	= nvme_tcp_exit_request,
	.init_hctx	= nvme_tcp_init_admin_hctx,
	.timeout	= nvme_tcp_timeout,
};

static const struct nvme_ctrl_ops nvme_tcp_ctrl_ops = {
	.name			= "tcp",
	.module			= THIS_MODULE,
	.flags			= NVME_F_FABRICS | NVME_F_BLOCKING,
	.reg_read32		= nvmf_reg_read32,
	.reg_read64		= nvmf_reg_read64,
	.reg_write32		= nvmf_reg_write32,
	.subsystem_reset	= nvmf_subsystem_reset,
	.free_ctrl		= nvme_tcp_free_ctrl,
	.submit_async_event	= nvme_tcp_submit_async_event,
	.delete_ctrl		= nvme_tcp_delete_ctrl,
	.get_address		= nvme_tcp_get_address,
	.stop_ctrl		= nvme_tcp_stop_ctrl,
};

static bool
nvme_tcp_existing_controller(struct nvmf_ctrl_options *opts)
{
	struct nvme_tcp_ctrl *ctrl;
	bool found = false;

	mutex_lock(&nvme_tcp_ctrl_mutex);
	list_for_each_entry(ctrl, &nvme_tcp_ctrl_list, list) {
		found = nvmf_ip_options_match(&ctrl->ctrl, opts);
		if (found)
			break;
	}
	mutex_unlock(&nvme_tcp_ctrl_mutex);

	return found;
}

static struct nvme_tcp_ctrl *nvme_tcp_alloc_ctrl(struct device *dev,
		struct nvmf_ctrl_options *opts)
{
	struct nvme_tcp_ctrl *ctrl;
	int ret;

	ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&ctrl->list);
	ctrl->ctrl.opts = opts;
	ctrl->ctrl.queue_count = opts->nr_io_queues + opts->nr_write_queues +
				opts->nr_poll_queues + 1;
	ctrl->ctrl.sqsize = opts->queue_size - 1;
	ctrl->ctrl.kato = opts->kato;

	INIT_DELAYED_WORK(&ctrl->connect_work,
			nvme_tcp_reconnect_ctrl_work);
	INIT_WORK(&ctrl->err_work, nvme_tcp_error_recovery_work);
	INIT_WORK(&ctrl->ctrl.reset_work, nvme_reset_ctrl_work);

	if (!(opts->mask & NVMF_OPT_TRSVCID)) {
		opts->trsvcid =
			kstrdup(__stringify(NVME_TCP_DISC_PORT), GFP_KERNEL);
		if (!opts->trsvcid) {
			ret = -ENOMEM;
			goto out_free_ctrl;
		}
		opts->mask |= NVMF_OPT_TRSVCID;
	}

	ret = inet_pton_with_scope(&init_net, AF_UNSPEC,
			opts->traddr, opts->trsvcid, &ctrl->addr);
	if (ret) {
		pr_err("malformed address passed: %s:%s\n",
			opts->traddr, opts->trsvcid);
		goto out_free_ctrl;
	}

	if (opts->mask & NVMF_OPT_HOST_TRADDR) {
		ret = inet_pton_with_scope(&init_net, AF_UNSPEC,
			opts->host_traddr, NULL, &ctrl->src_addr);
		if (ret) {
			pr_err("malformed src address passed: %s\n",
			       opts->host_traddr);
			goto out_free_ctrl;
		}
	}

	if (opts->mask & NVMF_OPT_HOST_IFACE) {
		if (!__dev_get_by_name(&init_net, opts->host_iface)) {
			pr_err("invalid interface passed: %s\n",
			       opts->host_iface);
			ret = -ENODEV;
			goto out_free_ctrl;
		}
	}

	if (!opts->duplicate_connect && nvme_tcp_existing_controller(opts)) {
		ret = -EALREADY;
		goto out_free_ctrl;
	}

	ctrl->queues = kcalloc(ctrl->ctrl.queue_count, sizeof(*ctrl->queues),
				GFP_KERNEL);
	if (!ctrl->queues) {
		ret = -ENOMEM;
		goto out_free_ctrl;
	}

	ret = nvme_init_ctrl(&ctrl->ctrl, dev, &nvme_tcp_ctrl_ops, 0);
	if (ret)
		goto out_kfree_queues;

	return ctrl;
out_kfree_queues:
	kfree(ctrl->queues);
out_free_ctrl:
	kfree(ctrl);
	return ERR_PTR(ret);
}

static struct nvme_ctrl *nvme_tcp_create_ctrl(struct device *dev,
		struct nvmf_ctrl_options *opts)
{
	struct nvme_tcp_ctrl *ctrl;
	int ret;

	ctrl = nvme_tcp_alloc_ctrl(dev, opts);
	if (IS_ERR(ctrl))
		return ERR_CAST(ctrl);

	ret = nvme_add_ctrl(&ctrl->ctrl);
	if (ret)
		goto out_put_ctrl;

	if (!nvme_change_ctrl_state(&ctrl->ctrl, NVME_CTRL_CONNECTING)) {
		WARN_ON_ONCE(1);
		ret = -EINTR;
		goto out_uninit_ctrl;
	}

	ret = nvme_tcp_setup_ctrl(&ctrl->ctrl, true);
	if (ret)
		goto out_uninit_ctrl;

	dev_info(ctrl->ctrl.device, "new ctrl: NQN \"%s\", addr %pISp, hostnqn: %s\n",
		nvmf_ctrl_subsysnqn(&ctrl->ctrl), &ctrl->addr, opts->host->nqn);

	mutex_lock(&nvme_tcp_ctrl_mutex);
	list_add_tail(&ctrl->list, &nvme_tcp_ctrl_list);
	mutex_unlock(&nvme_tcp_ctrl_mutex);

	return &ctrl->ctrl;

out_uninit_ctrl:
	nvme_uninit_ctrl(&ctrl->ctrl);
out_put_ctrl:
	nvme_put_ctrl(&ctrl->ctrl);
	if (ret > 0)
		ret = -EIO;
	return ERR_PTR(ret);
}

static struct nvmf_transport_ops nvme_tcp_transport = {
	.name		= "tcp",
	.module		= THIS_MODULE,
	.required_opts	= NVMF_OPT_TRADDR,
	.allowed_opts	= NVMF_OPT_TRSVCID | NVMF_OPT_RECONNECT_DELAY |
			  NVMF_OPT_HOST_TRADDR | NVMF_OPT_CTRL_LOSS_TMO |
			  NVMF_OPT_HDR_DIGEST | NVMF_OPT_DATA_DIGEST |
			  NVMF_OPT_NR_WRITE_QUEUES | NVMF_OPT_NR_POLL_QUEUES |
			  NVMF_OPT_TOS | NVMF_OPT_HOST_IFACE | NVMF_OPT_TLS |
			  NVMF_OPT_KEYRING | NVMF_OPT_TLS_KEY | NVMF_OPT_CONCAT,
	.create_ctrl	= nvme_tcp_create_ctrl,
};

static int __init nvme_tcp_init_module(void)
{
	unsigned int wq_flags = WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_SYSFS;
	int cpu;

	BUILD_BUG_ON(sizeof(struct nvme_tcp_hdr) != 8);
	BUILD_BUG_ON(sizeof(struct nvme_tcp_cmd_pdu) != 72);
	BUILD_BUG_ON(sizeof(struct nvme_tcp_data_pdu) != 24);
	BUILD_BUG_ON(sizeof(struct nvme_tcp_rsp_pdu) != 24);
	BUILD_BUG_ON(sizeof(struct nvme_tcp_r2t_pdu) != 24);
	BUILD_BUG_ON(sizeof(struct nvme_tcp_icreq_pdu) != 128);
	BUILD_BUG_ON(sizeof(struct nvme_tcp_icresp_pdu) != 128);
	BUILD_BUG_ON(sizeof(struct nvme_tcp_term_pdu) != 24);

	if (wq_unbound)
		wq_flags |= WQ_UNBOUND;

	nvme_tcp_wq = alloc_workqueue("nvme_tcp_wq", wq_flags, 0);
	if (!nvme_tcp_wq)
		return -ENOMEM;

	for_each_possible_cpu(cpu)
		atomic_set(&nvme_tcp_cpu_queues[cpu], 0);

	nvmf_register_transport(&nvme_tcp_transport);
	return 0;
}

static void __exit nvme_tcp_cleanup_module(void)
{
	struct nvme_tcp_ctrl *ctrl;

	nvmf_unregister_transport(&nvme_tcp_transport);

	mutex_lock(&nvme_tcp_ctrl_mutex);
	list_for_each_entry(ctrl, &nvme_tcp_ctrl_list, list)
		nvme_delete_ctrl(&ctrl->ctrl);
	mutex_unlock(&nvme_tcp_ctrl_mutex);
	flush_workqueue(nvme_delete_wq);

	destroy_workqueue(nvme_tcp_wq);
}

module_init(nvme_tcp_init_module);
module_exit(nvme_tcp_cleanup_module);

MODULE_DESCRIPTION("NVMe host TCP transport driver");
MODULE_LICENSE("GPL v2");
