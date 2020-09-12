/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation. All rights reserved.
 *   Copyright (c) 2020 Mellanox Technologies LTD. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * NVMe/TCP transport
 */

#include "nvme_internal.h"

#include "spdk/endian.h"
#include "spdk/likely.h"
#include "spdk/string.h"
#include "spdk/stdinc.h"
#include "spdk/crc32.h"
#include "spdk/endian.h"
#include "spdk/assert.h"
#include "spdk/string.h"
#include "spdk/thread.h"
#include "spdk/trace.h"
#include "spdk/util.h"

#include "spdk/global_queue.h"

#include "spdk_internal/nvme_tcp.h"

#define NVME_TCP_RW_BUFFER_SIZE 131072
#define NVME_TCP_TIME_OUT_IN_SECONDS 2

#define NVME_TCP_HPDA_DEFAULT			0
#define NVME_TCP_MAX_R2T_DEFAULT		1
#define NVME_TCP_PDU_H2C_MIN_DATA_SIZE		4096
#define NVME_TCP_IN_CAPSULE_DATA_MAX_SIZE	8192

/* NVMe TCP transport extensions for spdk_nvme_ctrlr */
struct nvme_pipe_ctrlr {
	struct spdk_nvme_ctrlr			ctrlr;
};

struct nvme_pipe_poll_group {
	struct spdk_nvme_transport_poll_group group;
	struct spdk_sock_group *sock_group;
	uint32_t completions_per_qpair;
	int64_t num_completions;
};


#if 0
/* NVMe TCP qpair extensions for spdk_nvme_qpair */
struct nvme_pipe_qpair {
	struct spdk_nvme_qpair			qpair;
	struct spdk_sock			*sock;

	struct global_queue			*pipe;

	TAILQ_HEAD(, nvme_pipe_req)		free_reqs;
	TAILQ_HEAD(, nvme_pipe_req)		outstanding_reqs;

	TAILQ_HEAD(, nvme_tcp_pdu)		send_queue;
	struct nvme_tcp_pdu			recv_pdu;
	struct nvme_tcp_pdu			send_pdu; /* only for error pdu and init pdu */
	struct nvme_tcp_pdu			*send_pdus; /* Used by tcp_reqs */
	enum nvme_tcp_pdu_recv_state		recv_state;

	struct nvme_pipe_req			*pipe_reqs;

	uint16_t				num_entries;

	bool					host_hdgst_enable;
	bool					host_ddgst_enable;

	/** Specifies the maximum number of PDU-Data bytes per H2C Data Transfer PDU */
	uint32_t				maxh2cdata;

	uint32_t				maxr2t;

	/* 0 based value, which is used to guide the padding */
	uint8_t					cpda;

	enum nvme_tcp_qpair_state		state;
};

enum nvme_pipe_req_state {
	NVME_PIPE_REQ_FREE,
	NVME_PIPE_REQ_ACTIVE,
	NVME_PIPE_REQ_ACTIVE_R2T,
};

struct nvme_pipe_req {
	struct nvme_request			*req;
	enum nvme_pipe_req_state		state;
	uint16_t				cid;
	uint16_t				ttag;
	uint32_t				datao;
	uint32_t				r2tl_remain;
	uint32_t				active_r2ts;
	bool					in_capsule_data;
	/* It is used to track whether the req can be safely freed */
	struct {
		uint8_t				send_ack : 1;
		uint8_t				data_recv : 1;
		uint8_t				r2t_recv : 1;
		uint8_t				reserved : 5;
	} ordering;
	struct nvme_tcp_pdu			*send_pdu;
	struct iovec				iov[NVME_TCP_MAX_SGL_DESCRIPTORS];
	uint32_t				iovcnt;
	struct nvme_pipe_qpair			*tqpair;
	TAILQ_ENTRY(nvme_pipe_req)		link;
};
#endif

static void nvme_pipe_send_h2c_data(struct nvme_pipe_req *pipe_req);

static inline struct nvme_pipe_qpair *
nvme_pipe_qpair(struct spdk_nvme_qpair *qpair)
{
	assert(qpair->trtype == SPDK_NVME_TRANSPORT_TCP);
	return SPDK_CONTAINEROF(qpair, struct nvme_pipe_qpair, qpair);
}

static inline struct nvme_pipe_poll_group *
nvme_pipe_poll_group(struct spdk_nvme_transport_poll_group *group)
{
	return SPDK_CONTAINEROF(group, struct nvme_pipe_poll_group, group);
}

static inline struct nvme_pipe_ctrlr *
nvme_pipe_ctrlr(struct spdk_nvme_ctrlr *ctrlr)
{
	assert(ctrlr->trid.trtype == SPDK_NVME_TRANSPORT_PIPE);
	return SPDK_CONTAINEROF(ctrlr, struct nvme_pipe_ctrlr, ctrlr);
}

static struct nvme_pipe_req *
nvme_pipe_req_get(struct nvme_pipe_qpair *tqpair)
{
	struct nvme_pipe_req *pipe_req;

	pipe_req = TAILQ_FIRST(&tqpair->free_reqs);
	if (!pipe_req) {
		return NULL;
	}

	assert(pipe_req->state == NVME_PIPE_REQ_FREE);
	pipe_req->state = NVME_PIPE_REQ_ACTIVE;
	TAILQ_REMOVE(&tqpair->free_reqs, pipe_req, link);
	pipe_req->datao = 0;
	pipe_req->req = NULL;
	pipe_req->in_capsule_data = false;
	pipe_req->r2tl_remain = 0;
	pipe_req->active_r2ts = 0;
	pipe_req->iovcnt = 0;
	pipe_req->ordering.send_ack = 0;
	pipe_req->ordering.data_recv = 0;
	pipe_req->ordering.r2t_recv = 0;
	memset(pipe_req->send_pdu, 0, sizeof(struct nvme_tcp_pdu));
	TAILQ_INSERT_TAIL(&tqpair->outstanding_reqs, pipe_req, link);

	return pipe_req;
}

static void
nvme_pipe_req_put(struct nvme_pipe_qpair *tqpair, struct nvme_pipe_req *pipe_req)
{
	assert(pipe_req->state != NVME_PIPE_REQ_FREE);
	pipe_req->state = NVME_PIPE_REQ_FREE;
	TAILQ_INSERT_HEAD(&tqpair->free_reqs, pipe_req, link);
}

static int
nvme_tcp_parse_addr(struct sockaddr_storage *sa, int family, const char *addr, const char *service)
{
	struct addrinfo *res;
	struct addrinfo hints;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;

	ret = getaddrinfo(addr, service, &hints, &res);
	if (ret) {
		SPDK_ERRLOG("getaddrinfo failed: %s (%d)\n", gai_strerror(ret), ret);
		return ret;
	}

	if (res->ai_addrlen > sizeof(*sa)) {
		SPDK_ERRLOG("getaddrinfo() ai_addrlen %zu too large\n", (size_t)res->ai_addrlen);
		ret = EINVAL;
	} else {
		memcpy(sa, res->ai_addr, res->ai_addrlen);
	}

	freeaddrinfo(res);
	return ret;
}

static void
nvme_pipe_free_reqs(struct nvme_pipe_qpair *tqpair)
{
	free(tqpair->pipe_reqs);
	tqpair->pipe_reqs = NULL;

	spdk_free(tqpair->send_pdus);
	tqpair->send_pdus = NULL;
}

static int
nvme_pipe_alloc_reqs(struct nvme_pipe_qpair *tqpair)
{
	uint16_t i;
	struct nvme_pipe_req	*pipe_req;

	tqpair->pipe_reqs = calloc(tqpair->num_entries, sizeof(struct nvme_pipe_req));
	if (tqpair->pipe_reqs == NULL) {
		SPDK_ERRLOG("Failed to allocate tcp_reqs on tqpair=%p\n", tqpair);
		goto fail;
	}

	tqpair->send_pdus = spdk_zmalloc(tqpair->num_entries * sizeof(struct nvme_tcp_pdu),
					 0x1000, NULL,
					 SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);

	if (tqpair->send_pdus == NULL) {
		SPDK_ERRLOG("Failed to allocate send_pdus on tqpair=%p\n", tqpair);
		goto fail;
	}

	TAILQ_INIT(&tqpair->send_queue);
	TAILQ_INIT(&tqpair->free_reqs);
	TAILQ_INIT(&tqpair->outstanding_reqs);
	for (i = 0; i < tqpair->num_entries; i++) {
		pipe_req = &tqpair->pipe_reqs[i];
		pipe_req->cid = i;
		pipe_req->tqpair = tqpair;
		pipe_req->send_pdu = &tqpair->send_pdus[i];
		TAILQ_INSERT_TAIL(&tqpair->free_reqs, pipe_req, link);
	}

	return 0;
fail:
	nvme_pipe_free_reqs(tqpair);
	return -ENOMEM;
}

static void
nvme_pipe_ctrlr_disconnect_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
	struct nvme_pipe_qpair *tqpair = nvme_pipe_qpair(qpair);
	struct nvme_tcp_pdu *pdu;

	spdk_sock_close(&tqpair->sock);

	/* clear the send_queue */
	while (!TAILQ_EMPTY(&tqpair->send_queue)) {
		pdu = TAILQ_FIRST(&tqpair->send_queue);
		/* Remove the pdu from the send_queue to prevent the wrong sending out
		 * in the next round connection
		 */
		TAILQ_REMOVE(&tqpair->send_queue, pdu, tailq);
	}
}

static void nvme_pipe_qpair_abort_reqs(struct spdk_nvme_qpair *qpair, uint32_t dnr);

static int
nvme_pipe_ctrlr_delete_io_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
	struct nvme_pipe_qpair *tqpair;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	if (!qpair) {
		return -1;
	}

	nvme_transport_ctrlr_disconnect_qpair(ctrlr, qpair);
	nvme_pipe_qpair_abort_reqs(qpair, 1);
	nvme_qpair_deinit(qpair);
	tqpair = nvme_pipe_qpair(qpair);
	nvme_pipe_free_reqs(tqpair);
	free(tqpair);

	return 0;
}

static int
nvme_pipe_ctrlr_enable(struct spdk_nvme_ctrlr *ctrlr)
{
	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	return 0;
}

static int
nvme_pipe_ctrlr_destruct(struct spdk_nvme_ctrlr *ctrlr)
{
	struct nvme_pipe_ctrlr *tctrlr = nvme_pipe_ctrlr(ctrlr);

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	if (ctrlr->adminq) {
		nvme_pipe_ctrlr_delete_io_qpair(ctrlr, ctrlr->adminq);
	}

	nvme_ctrlr_destruct_finish(ctrlr);

	free(tctrlr);

	return 0;
}

static void
_pdu_issue_callback(void *_pdu)
{
	struct nvme_tcp_pdu *pdu = _pdu;

	if (pdu->cb_fn)
		pdu->cb_fn(pdu->cb_arg);
}

static void
_pdu_write_done(void *cb_arg, int err)
{
	struct nvme_tcp_pdu *pdu = cb_arg;
	struct nvme_pipe_qpair *tqpair = pdu->qpair;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	TAILQ_REMOVE(&tqpair->send_queue, pdu, tailq);

	if (err != 0) {
		nvme_transport_ctrlr_disconnect_qpair(tqpair->qpair.ctrlr, &tqpair->qpair);
		return;
	}

	assert(pdu->cb_fn != NULL);
	pdu->cb_fn(pdu->cb_arg);
}

static int
nvme_pipe_qpair_write_pdu(struct nvme_pipe_qpair *tqpair,
			 struct nvme_tcp_pdu *pdu,
			 nvme_tcp_qpair_xfer_complete_cb cb_fn,
			 void *cb_arg)
{
	int hlen;
	uint32_t crc32c;
	uint32_t mapped_length = 0;
	struct global_queue_req *global_req;

	hlen = pdu->hdr.common.hlen;

	/* Header Digest */
	if (g_nvme_tcp_hdgst[pdu->hdr.common.pdu_type] && tqpair->host_hdgst_enable) {
		crc32c = nvme_tcp_pdu_calc_header_digest(pdu);
		MAKE_DIGEST_WORD((uint8_t *)pdu->hdr.raw + hlen, crc32c);
	}

	/* Data Digest */
	if (pdu->data_len > 0 && g_nvme_tcp_ddgst[pdu->hdr.common.pdu_type] && tqpair->host_ddgst_enable) {
		crc32c = nvme_tcp_pdu_calc_data_digest(pdu);
		MAKE_DIGEST_WORD(pdu->data_digest, crc32c);
	}

	// FIXME: callback not implemented
	pdu->cb_fn = cb_fn;
	pdu->cb_arg = cb_arg;

	//pdu->sock_req.iovcnt = nvme_tcp_build_iovs(pdu->iov, NVME_TCP_MAX_SGL_DESCRIPTORS, pdu,
	//		       tqpair->host_hdgst_enable, tqpair->host_ddgst_enable,
	//		       &mapped_length);
	pdu->qpair = tqpair;
	// FIXME: callback not implemented
	//pdu->sock_req.cb_fn = _pdu_write_done;
	//pdu->sock_req.cb_arg = pdu;
	//TAILQ_INSERT_TAIL(&tqpair->send_queue, pdu, tailq);
	//spdk_sock_writev_async(tqpair->sock, &pdu->sock_req);
	global_req = spdk_pipe_get_free_h2c_req(tqpair->pipe);
	global_req->pdu = pdu; 

	spdk_pipe_submit_h2c_req(tqpair->pipe, global_req);

	return 0;
}

/*
 * Build SGL describing contiguous payload buffer.
 */
static int
nvme_pipe_build_contig_request(struct nvme_pipe_qpair *tqpair, struct nvme_pipe_req *pipe_req)
{
	struct nvme_request *req = pipe_req->req;

	pipe_req->iov[0].iov_base = req->payload.contig_or_cb_arg + req->payload_offset;
	pipe_req->iov[0].iov_len = req->payload_size;
	pipe_req->iovcnt = 1;

	SPDK_DEBUGLOG(SPDK_LOG_NVME, "enter\n");

	assert(nvme_payload_type(&req->payload) == NVME_PAYLOAD_TYPE_CONTIG);

	return 0;
}

/*
 * Build SGL describing scattered payload buffer.
 */
static int
nvme_pipe_build_sgl_request(struct nvme_pipe_qpair *tqpair, struct nvme_pipe_req *pipe_req)
{
	int rc;
	uint32_t length, remaining_size, iovcnt = 0, max_num_sgl;
	struct nvme_request *req = pipe_req->req;

	SPDK_DEBUGLOG(SPDK_LOG_NVME, "enter\n");

	assert(req->payload_size != 0);
	assert(nvme_payload_type(&req->payload) == NVME_PAYLOAD_TYPE_SGL);
	assert(req->payload.reset_sgl_fn != NULL);
	assert(req->payload.next_sge_fn != NULL);
	req->payload.reset_sgl_fn(req->payload.contig_or_cb_arg, req->payload_offset);

	max_num_sgl = spdk_min(req->qpair->ctrlr->max_sges, NVME_TCP_MAX_SGL_DESCRIPTORS);
	remaining_size = req->payload_size;

	do {
		rc = req->payload.next_sge_fn(req->payload.contig_or_cb_arg, &pipe_req->iov[iovcnt].iov_base,
					      &length);
		if (rc) {
			return -1;
		}

		length = spdk_min(length, remaining_size);
		pipe_req->iov[iovcnt].iov_len = length;
		remaining_size -= length;
		iovcnt++;
	} while (remaining_size > 0 && iovcnt < max_num_sgl);


	/* Should be impossible if we did our sgl checks properly up the stack, but do a sanity check here. */
	if (remaining_size > 0) {
		SPDK_ERRLOG("Failed to construct tcp_req=%p, and the iovcnt=%u, remaining_size=%u\n",
			    pipe_req, iovcnt, remaining_size);
		return -1;
	}

	pipe_req->iovcnt = iovcnt;

	return 0;
}

static int
nvme_pipe_req_init(struct nvme_pipe_qpair *tqpair, struct nvme_request *req,
		  struct nvme_pipe_req *pipe_req)
{
	struct spdk_nvme_ctrlr *ctrlr = tqpair->qpair.ctrlr;
	int rc = 0;
	enum spdk_nvme_data_transfer xfer;
	uint32_t max_incapsule_data_size;

	pipe_req->req = req;
	req->cmd.cid = pipe_req->cid;
	req->cmd.psdt = SPDK_NVME_PSDT_SGL_MPTR_CONTIG;
	req->cmd.dptr.sgl1.unkeyed.type = SPDK_NVME_SGL_TYPE_TRANSPORT_DATA_BLOCK;
	req->cmd.dptr.sgl1.unkeyed.subtype = SPDK_NVME_SGL_SUBTYPE_TRANSPORT;
	req->cmd.dptr.sgl1.unkeyed.length = req->payload_size;

	if (nvme_payload_type(&req->payload) == NVME_PAYLOAD_TYPE_CONTIG) {
		rc = nvme_pipe_build_contig_request(tqpair, pipe_req);
	} else if (nvme_payload_type(&req->payload) == NVME_PAYLOAD_TYPE_SGL) {
		rc = nvme_pipe_build_sgl_request(tqpair, pipe_req);
	} else {
		rc = -1;
	}

	if (rc) {
		return rc;
	}

	if (req->cmd.opc == SPDK_NVME_OPC_FABRIC) {
		struct spdk_nvmf_capsule_cmd *nvmf_cmd = (struct spdk_nvmf_capsule_cmd *)&req->cmd;

		xfer = spdk_nvme_opc_get_data_transfer(nvmf_cmd->fctype);
	} else {
		xfer = spdk_nvme_opc_get_data_transfer(req->cmd.opc);
	}
	if (xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER) {
		max_incapsule_data_size = ctrlr->ioccsz_bytes;
		if ((req->cmd.opc == SPDK_NVME_OPC_FABRIC) || nvme_qpair_is_admin_queue(&tqpair->qpair)) {
			max_incapsule_data_size = spdk_min(max_incapsule_data_size, NVME_TCP_IN_CAPSULE_DATA_MAX_SIZE);
		}

		if (req->payload_size <= max_incapsule_data_size) {
			req->cmd.dptr.sgl1.unkeyed.type = SPDK_NVME_SGL_TYPE_DATA_BLOCK;
			req->cmd.dptr.sgl1.unkeyed.subtype = SPDK_NVME_SGL_SUBTYPE_OFFSET;
			req->cmd.dptr.sgl1.address = 0;
			pipe_req->in_capsule_data = true;
		}
	}

	return 0;
}

static inline void
nvme_pipe_req_put_safe(struct nvme_pipe_req *pipe_req)
{
	if (pipe_req->ordering.send_ack && pipe_req->ordering.data_recv) {
		assert(pipe_req->state == NVME_PIPE_REQ_ACTIVE);
		assert(pipe_req->tqpair != NULL);
		nvme_pipe_req_put(pipe_req->tqpair, pipe_req);
	}
}

static void
nvme_pipe_qpair_cmd_send_complete(void *cb_arg)
{
	struct nvme_pipe_req *pipe_req = cb_arg;

	pipe_req->ordering.send_ack = 1;
	/* Handle the r2t case */
	if (spdk_unlikely(pipe_req->ordering.r2t_recv)) {
		nvme_pipe_send_h2c_data(pipe_req);
	} else {
		nvme_pipe_req_put_safe(pipe_req);
	}
}

static int
nvme_pipe_qpair_capsule_cmd_send(struct nvme_pipe_qpair *tqpair,
				struct nvme_pipe_req *pipe_req)
{
	struct nvme_tcp_pdu *pdu;
	struct spdk_nvme_tcp_cmd *capsule_cmd;
	uint32_t plen = 0, alignment;
	uint8_t pdo;
	struct global_queue_req *global_req;

	SPDK_DEBUGLOG(SPDK_LOG_NVME, "enter\n");
	pdu = pipe_req->send_pdu;

	capsule_cmd = &pdu->hdr.capsule_cmd;
	capsule_cmd->common.pdu_type = SPDK_NVME_TCP_PDU_TYPE_CAPSULE_CMD;
	plen = capsule_cmd->common.hlen = sizeof(*capsule_cmd);
	capsule_cmd->ccsqe = pipe_req->req->cmd;

	SPDK_DEBUGLOG(SPDK_LOG_NVME, "capsule_cmd cid=%u on tqpair(%p)\n", pipe_req->req->cmd.cid, tqpair);

	if (tqpair->host_hdgst_enable) {
		SPDK_DEBUGLOG(SPDK_LOG_NVME, "Header digest is enabled for capsule command on tcp_req=%p\n",
			      pipe_req);
		capsule_cmd->common.flags |= SPDK_NVME_TCP_CH_FLAGS_HDGSTF;
		plen += SPDK_NVME_TCP_DIGEST_LEN;
	}

	if ((pipe_req->req->payload_size == 0) || !pipe_req->in_capsule_data) {
		goto end;
	}

	pdo = plen;
	pdu->padding_len = 0;
	if (tqpair->cpda) {
		alignment = (tqpair->cpda + 1) << 2;
		if (alignment > plen) {
			pdu->padding_len = alignment - plen;
			pdo = alignment;
			plen = alignment;
		}
	}

	capsule_cmd->common.pdo = pdo;
	plen += pipe_req->req->payload_size;
	if (tqpair->host_ddgst_enable) {
		capsule_cmd->common.flags |= SPDK_NVME_TCP_CH_FLAGS_DDGSTF;
		plen += SPDK_NVME_TCP_DIGEST_LEN;
	}

	pipe_req->datao = 0;
	nvme_tcp_pdu_set_data_buf(pdu, pipe_req->iov, pipe_req->iovcnt,
				  0, pipe_req->req->payload_size);
end:
	capsule_cmd->common.plen = plen;
	//return nvme_pipe_qpair_write_pdu(tqpair, pdu, nvme_pipe_qpair_cmd_send_complete, pipe_req);
	// FIXME nvme_pipe_qpair_write_pdu() also handles callback, need to add it here
	pdu->qpair = tqpair;

	global_req = spdk_pipe_get_free_h2c_req(tqpair->pipe);
	global_req->nvme_req = pipe_req;

	return spdk_pipe_submit_h2c_req(tqpair->pipe, global_req);
}

static int
nvme_pipe_qpair_submit_request(struct spdk_nvme_qpair *qpair,
			      struct nvme_request *req)
{
	struct nvme_pipe_qpair *tqpair;
	struct nvme_pipe_req *pipe_req;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	tqpair = nvme_pipe_qpair(qpair);
	assert(tqpair != NULL);
	assert(req != NULL);

	pipe_req = nvme_pipe_req_get(tqpair);
	if (!pipe_req) {
		/* Inform the upper layer to try again later. */
		return -EAGAIN;
	}

	if (nvme_pipe_req_init(tqpair, req, pipe_req)) {
		SPDK_ERRLOG("nvme_tcp_req_init() failed\n");
		TAILQ_REMOVE(&pipe_req->tqpair->outstanding_reqs, pipe_req, link);
		nvme_pipe_req_put(tqpair, pipe_req);
		return -1;
	}
	return nvme_pipe_qpair_capsule_cmd_send(tqpair, pipe_req);
}

static int
nvme_pipe_qpair_reset(struct spdk_nvme_qpair *qpair)
{
	return 0;
}

static void
nvme_pipe_req_complete(struct nvme_pipe_req *pipe_req,
		      struct spdk_nvme_cpl *rsp)
{
	struct nvme_request *req;

	assert(pipe_req->req != NULL);
	req = pipe_req->req;

	TAILQ_REMOVE(&pipe_req->tqpair->outstanding_reqs, pipe_req, link);
	nvme_complete_request(req->cb_fn, req->cb_arg, req->qpair, req, rsp);
	nvme_free_request(req);
}

static void
nvme_pipe_qpair_abort_reqs(struct spdk_nvme_qpair *qpair, uint32_t dnr)
{
	struct nvme_pipe_req *pipe_req, *tmp;
	struct spdk_nvme_cpl cpl;
	struct nvme_pipe_qpair *tqpair = nvme_pipe_qpair(qpair);

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	cpl.status.sc = SPDK_NVME_SC_ABORTED_SQ_DELETION;
	cpl.status.sct = SPDK_NVME_SCT_GENERIC;
	cpl.status.dnr = dnr;

	TAILQ_FOREACH_SAFE(pipe_req, &tqpair->outstanding_reqs, link, tmp) {
		nvme_pipe_req_complete(pipe_req, &cpl);
		nvme_pipe_req_put(tqpair, pipe_req);
	}
}

static struct nvme_pipe_req *
get_nvme_active_req_by_cid(struct nvme_pipe_qpair *tqpair, uint32_t cid)
{
	assert(tqpair != NULL);
	if ((cid >= tqpair->num_entries) || (tqpair->pipe_reqs[cid].state == NVME_PIPE_REQ_FREE)) {
		return NULL;
	}

	return &tqpair->pipe_reqs[cid];
}

static const char *spdk_nvme_tcp_term_req_fes_str[] = {
	"Invalid PDU Header Field",
	"PDU Sequence Error",
	"Header Digest Error",
	"Data Transfer Out of Range",
	"Data Transfer Limit Exceeded",
	"Unsupported parameter",
};

static void
nvme_pipe_qpair_h2c_data_send_complete(void *cb_arg)
{
	struct nvme_pipe_req *pipe_req = cb_arg;

	assert(pipe_req != NULL);

	pipe_req->ordering.send_ack = 1;
	if (pipe_req->r2tl_remain) {
		nvme_pipe_send_h2c_data(pipe_req);
	} else {
		assert(pipe_req->active_r2ts > 0);
		pipe_req->active_r2ts--;
		pipe_req->state = NVME_PIPE_REQ_ACTIVE;
		/* Need also call this function to free the resource */
		nvme_pipe_req_put_safe(pipe_req);
	}
}

static void
nvme_pipe_send_h2c_data(struct nvme_pipe_req *pipe_req)
{
	struct nvme_pipe_qpair *tqpair = nvme_pipe_qpair(pipe_req->req->qpair);
	struct nvme_tcp_pdu *rsp_pdu;
	struct spdk_nvme_tcp_h2c_data_hdr *h2c_data;
	uint32_t plen, pdo, alignment;

	/* Reinit the send_ack and r2t_recv bits */
	pipe_req->ordering.send_ack = 0;
	pipe_req->ordering.r2t_recv = 0;
	rsp_pdu = pipe_req->send_pdu;
	memset(rsp_pdu, 0, sizeof(*rsp_pdu));
	h2c_data = &rsp_pdu->hdr.h2c_data;

	h2c_data->common.pdu_type = SPDK_NVME_TCP_PDU_TYPE_H2C_DATA;
	plen = h2c_data->common.hlen = sizeof(*h2c_data);
	h2c_data->cccid = pipe_req->cid;
	h2c_data->ttag = pipe_req->ttag;
	h2c_data->datao = pipe_req->datao;

	h2c_data->datal = spdk_min(pipe_req->r2tl_remain, tqpair->maxh2cdata);
	nvme_tcp_pdu_set_data_buf(rsp_pdu, pipe_req->iov, pipe_req->iovcnt,
				  h2c_data->datao, h2c_data->datal);
	pipe_req->r2tl_remain -= h2c_data->datal;

	if (tqpair->host_hdgst_enable) {
		h2c_data->common.flags |= SPDK_NVME_TCP_CH_FLAGS_HDGSTF;
		plen += SPDK_NVME_TCP_DIGEST_LEN;
	}

	rsp_pdu->padding_len = 0;
	pdo = plen;
	if (tqpair->cpda) {
		alignment = (tqpair->cpda + 1) << 2;
		if (alignment > plen) {
			rsp_pdu->padding_len = alignment - plen;
			pdo = plen = alignment;
		}
	}

	h2c_data->common.pdo = pdo;
	plen += h2c_data->datal;
	if (tqpair->host_ddgst_enable) {
		h2c_data->common.flags |= SPDK_NVME_TCP_CH_FLAGS_DDGSTF;
		plen += SPDK_NVME_TCP_DIGEST_LEN;
	}

	h2c_data->common.plen = plen;
	pipe_req->datao += h2c_data->datal;
	if (!pipe_req->r2tl_remain) {
		h2c_data->common.flags |= SPDK_NVME_TCP_H2C_DATA_FLAGS_LAST_PDU;
	}

	SPDK_DEBUGLOG(SPDK_LOG_NVME, "h2c_data info: datao=%u, datal=%u, pdu_len=%u for tqpair=%p\n",
		      h2c_data->datao, h2c_data->datal, h2c_data->common.plen, tqpair);

	nvme_pipe_qpair_write_pdu(tqpair, rsp_pdu, nvme_pipe_qpair_h2c_data_send_complete, pipe_req);
}

static void
nvme_pipe_qpair_set_recv_state(struct nvme_pipe_qpair *tqpair,
			      enum nvme_tcp_pdu_recv_state state)
{
	if (tqpair->recv_state == state) {
		SPDK_ERRLOG("The recv state of tqpair=%p is same with the state(%d) to be set\n",
			    tqpair, state);
		return;
	}

	tqpair->recv_state = state;
	switch (state) {
	case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY:
	case NVME_TCP_PDU_RECV_STATE_ERROR:
		tqpair->current_pdu = NULL;
		//memset(&tqpair->recv_pdu, 0, sizeof(struct nvme_tcp_pdu));
		break;
	case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_CH:
	case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PSH:
	case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PAYLOAD:
	default:
		break;
	}
}

static void
nvme_pipe_capsule_resp_hdr_handle(struct nvme_pipe_qpair *tqpair, struct nvme_tcp_pdu *pdu,
				 uint32_t *reaped)
{
	struct nvme_pipe_req *pipe_req;
	struct spdk_nvme_tcp_rsp *capsule_resp = &pdu->hdr.capsule_resp;
	uint32_t cid, error_offset = 0;
	enum spdk_nvme_tcp_term_req_fes fes;
	struct spdk_nvme_cpl cpl;

	SPDK_DEBUGLOG(SPDK_LOG_NVME, "enter\n");
	cpl = capsule_resp->rccqe;
	cid = cpl.cid;

	/* Recv the pdu again */
	nvme_pipe_qpair_set_recv_state(tqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY);

	pipe_req = get_nvme_active_req_by_cid(tqpair, cid);
	if (!pipe_req) {
		SPDK_ERRLOG("no tcp_req is found with cid=%u for tqpair=%p\n", cid, tqpair);
		fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
		error_offset = offsetof(struct spdk_nvme_tcp_rsp, rccqe);
		goto end;

	}

	nvme_pipe_req_complete(pipe_req, &cpl);
	if (pipe_req->ordering.send_ack) {
		(*reaped)++;
	}

	pipe_req->ordering.data_recv = 1;
	nvme_pipe_req_put_safe(pipe_req);

	SPDK_DEBUGLOG(SPDK_LOG_NVME, "complete pipe_req(%p) on tqpair=%p\n", pipe_req, tqpair);

	return;

end:
	//nvme_tcp_qpair_send_h2c_term_req(tqpair, pdu, fes, error_offset);
	SPDK_ERRLOG("%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
	return;
}


static void
nvme_pipe_r2t_hdr_handle(struct nvme_pipe_qpair *tqpair, struct nvme_tcp_pdu *pdu)
{
	struct nvme_pipe_req *pipe_req;
	struct spdk_nvme_tcp_r2t_hdr *r2t = &pdu->hdr.r2t;
	uint32_t cid, error_offset = 0;
	enum spdk_nvme_tcp_term_req_fes fes;

	pipe_req = get_nvme_active_req_by_cid(tqpair, cid);

	if (!pipe_req) {
		SPDK_ERRLOG("Cannot find tcp_req for tqpair=%p\n", tqpair);
		fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
		error_offset = offsetof(struct spdk_nvme_tcp_r2t_hdr, cccid);
		goto end;
	}
	SPDK_ERRLOG("%s (%s:%d) active_r2ts %u tqpair %p pdu %p\n", __func__, __FILE__, __LINE__,
			pipe_req->active_r2ts, tqpair, pdu);

	pipe_req->ordering.r2t_recv = 1;

	if (pipe_req->state == NVME_PIPE_REQ_ACTIVE) {
		assert(pipe_req->active_r2ts == 0);
		pipe_req->state = NVME_PIPE_REQ_ACTIVE_R2T;
	}

	pipe_req->active_r2ts++;
	if (pipe_req->active_r2ts > tqpair->maxr2t) {
		fes = SPDK_NVME_TCP_TERM_REQ_FES_R2T_LIMIT_EXCEEDED;
		SPDK_ERRLOG("Invalid R2T: it %u exceeds the R2T maixmal=%u for tqpair=%p\n", pipe_req->active_r2ts, tqpair->maxr2t, tqpair);
		goto end;
	}

	if (pipe_req->datao != r2t->r2to) {
		fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
		error_offset = offsetof(struct spdk_nvme_tcp_r2t_hdr, r2to);
		goto end;

	}

	if ((r2t->r2tl + r2t->r2to) > pipe_req->req->payload_size) {
		SPDK_ERRLOG("Invalid R2T info for tcp_req=%p: (r2to(%u) + r2tl(%u)) exceeds payload_size(%u)\n",
			    pipe_req, r2t->r2to, r2t->r2tl, tqpair->maxh2cdata);
		fes = SPDK_NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_OUT_OF_RANGE;
		error_offset = offsetof(struct spdk_nvme_tcp_r2t_hdr, r2tl);
		goto end;

	}

	pipe_req->ttag = r2t->ttag;
	pipe_req->r2tl_remain = r2t->r2tl;
	nvme_pipe_qpair_set_recv_state(tqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY);
	_pdu_issue_callback(pdu);

	if (spdk_likely(pipe_req->ordering.send_ack)) {
		nvme_pipe_send_h2c_data(pipe_req);
	}
	return;

end:
	SPDK_ERRLOG("%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
	return;
}

static void
nvme_pipe_icresp_handle(struct nvme_pipe_qpair *tqpair,
		       struct nvme_tcp_pdu *pdu)
{
	struct spdk_nvme_tcp_ic_resp *ic_resp = &pdu->hdr.ic_resp;
	uint32_t error_offset = 0;
	enum spdk_nvme_tcp_term_req_fes fes;
	int recv_buf_size;

	/* Only PFV 0 is defined currently */
	if (ic_resp->pfv != 0) {
		SPDK_ERRLOG("Expected ICResp PFV %u, got %u\n", 0u, ic_resp->pfv);
		fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
		error_offset = offsetof(struct spdk_nvme_tcp_ic_resp, pfv);
		goto end;
	}

	if (ic_resp->maxh2cdata < NVME_TCP_PDU_H2C_MIN_DATA_SIZE) {
		SPDK_ERRLOG("Expected ICResp maxh2cdata >=%u, got %u\n", NVME_TCP_PDU_H2C_MIN_DATA_SIZE,
			    ic_resp->maxh2cdata);
		fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
		error_offset = offsetof(struct spdk_nvme_tcp_ic_resp, maxh2cdata);
		goto end;
	}
	tqpair->maxh2cdata = ic_resp->maxh2cdata;

	if (ic_resp->cpda > SPDK_NVME_TCP_CPDA_MAX) {
		SPDK_ERRLOG("Expected ICResp cpda <=%u, got %u\n", SPDK_NVME_TCP_CPDA_MAX, ic_resp->cpda);
		fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
		error_offset = offsetof(struct spdk_nvme_tcp_ic_resp, cpda);
		goto end;
	}
	tqpair->cpda = ic_resp->cpda;

	tqpair->host_hdgst_enable = ic_resp->dgst.bits.hdgst_enable ? true : false;
	tqpair->host_ddgst_enable = ic_resp->dgst.bits.ddgst_enable ? true : false;
	SPDK_DEBUGLOG(SPDK_LOG_NVME, "host_hdgst_enable: %u\n", tqpair->host_hdgst_enable);
	SPDK_DEBUGLOG(SPDK_LOG_NVME, "host_ddgst_enable: %u\n", tqpair->host_ddgst_enable);

	/* Now that we know whether digests are enabled, properly size the receive buffer to
	 * handle several incoming 4K read commands according to SPDK_NVMF_TCP_RECV_BUF_SIZE_FACTOR
	 * parameter. */
	recv_buf_size = 0x1000 + sizeof(struct spdk_nvme_tcp_c2h_data_hdr);

	if (tqpair->host_hdgst_enable) {
		recv_buf_size += SPDK_NVME_TCP_DIGEST_LEN;
	}

	if (tqpair->host_ddgst_enable) {
		recv_buf_size += SPDK_NVME_TCP_DIGEST_LEN;
	}

#if 0
	if (spdk_sock_set_recvbuf(tqpair->sock, recv_buf_size * SPDK_NVMF_TCP_RECV_BUF_SIZE_FACTOR) < 0) {
		SPDK_WARNLOG("Unable to allocate enough memory for receive buffer on tqpair=%p with size=%d\n",
			     tqpair,
			     recv_buf_size);
		/* Not fatal. */
	}
#endif

	SPDK_ERRLOG("%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
	tqpair->state = NVME_TCP_QPAIR_STATE_RUNNING;
	nvme_pipe_qpair_set_recv_state(tqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY);
	return;
end:
	//nvme_tcp_qpair_send_h2c_term_req(tqpair, pdu, fes, error_offset);
	SPDK_ERRLOG("%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
	return;
}


static void
nvme_pipe_pdu_psh_handle(struct nvme_pipe_qpair *tqpair, uint32_t *reaped)
{
	struct nvme_tcp_pdu *pdu;

	pdu = tqpair->current_pdu;

	switch (pdu->hdr.common.pdu_type) {
	case SPDK_NVME_TCP_PDU_TYPE_IC_RESP:
		nvme_pipe_icresp_handle(tqpair, pdu);
		break;
	case SPDK_NVME_TCP_PDU_TYPE_CAPSULE_RESP:
		nvme_pipe_capsule_resp_hdr_handle(tqpair, pdu, reaped);
		break;
	case SPDK_NVME_TCP_PDU_TYPE_R2T:
		nvme_pipe_r2t_hdr_handle(tqpair, pdu);
		break;
	default:
		SPDK_ERRLOG("Unexpected PDU type 0x%02x\n", pdu->hdr.common.pdu_type);
		assert(0);
		break;
	}
}

static void
dump_pdu_ch(struct nvme_tcp_pdu *pdu)
{
	SPDK_NOTICELOG("Dumping pdu_ch pdu %p\n"
			"\thdr.common.pdu_type %u\n"
			"\thdr.common.flags %u\n"
			"\thdr.common.hlen %u\n"
			"\thdr.common.pdo %u\n"
			"\thdr.common.plen %u\n"
			"\t\thas_hdgst %d\n"
			"\t\tddgst_enable %d\n"
			"\t\tdata_iovcnt %u\n"
			"\t\tdata_len %u\n",
			pdu,
			pdu->hdr.common.pdu_type,
			pdu->hdr.common.flags,
			pdu->hdr.common.hlen,
			pdu->hdr.common.pdo,
			pdu->hdr.common.plen,
			pdu->has_hdgst,
			pdu->ddgst_enable,
			pdu->data_iovcnt,
			pdu->data_len);
}

static int
nvme_pipe_read_pdu(struct nvme_pipe_qpair *tqpair, uint32_t *reaped)
{
	int rc = 0;
	struct nvme_tcp_pdu *pdu;
	enum nvme_tcp_pdu_recv_state prev_state;
	struct global_queue_req *global_req;


	do {
		prev_state = tqpair->recv_state;
		switch (tqpair->recv_state) {
		case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY:
			if (spdk_pipe_c2h_queue_empty(tqpair->pipe))
				return rc;
			global_req = spdk_pipe_get_recv_c2h_req(tqpair->pipe);
			pdu = global_req->pdu;
			tqpair->current_pdu = pdu;
			dump_pdu_ch(pdu);
			nvme_pipe_qpair_set_recv_state(tqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_CH);
			break;
		/* common header */
		case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_CH:
			nvme_pipe_qpair_set_recv_state(tqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PSH);
			break;
		/* Wait for the pdu specific header  */
		case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PSH:
			nvme_pipe_pdu_psh_handle(tqpair, reaped);
			break;
		case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PAYLOAD:
			SPDK_ERRLOG("%s (%s:%d) unhandled state %d\n",
					__func__, __FILE__, __LINE__, tqpair->recv_state);
			assert(0);
			break;
		default:
			SPDK_ERRLOG("%s (%s:%d) unhandled state %d\n",
					__func__, __FILE__, __LINE__, tqpair->recv_state);
			assert(0);
			break;
		}
	} while (prev_state != tqpair->recv_state);

	return rc;
}

static int
nvme_pipe_qpair_process_completions(struct spdk_nvme_qpair *qpair, uint32_t max_completions)
{
	struct nvme_pipe_qpair *tqpair = nvme_pipe_qpair(qpair);
	uint32_t reaped;
	int rc;

	// XXX anything needed here?
	//SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	if (max_completions == 0) {
		max_completions = tqpair->num_entries;
	} else {
		max_completions = spdk_min(max_completions, tqpair->num_entries);
	}

	reaped = 0;
	do {
		rc = nvme_pipe_read_pdu(tqpair, &reaped);
		if (rc < 0) {
			SPDK_ERRLOG("%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
		} else if (rc == 0) {
			/* Partial PDU is read */
			break;
		}
	} while (reaped < max_completions);

	return reaped;
fail:

	/*
	 * Since admin queues take the ctrlr_lock before entering this function,
	 * we can call nvme_transport_ctrlr_disconnect_qpair. For other qpairs we need
	 * to call the generic function which will take the lock for us.
	 */
	qpair->transport_failure_reason = SPDK_NVME_QPAIR_FAILURE_UNKNOWN;

	if (nvme_qpair_is_admin_queue(qpair)) {
		nvme_transport_ctrlr_disconnect_qpair(qpair->ctrlr, qpair);
	} else {
		nvme_ctrlr_disconnect_qpair(qpair);
	}
	return -ENXIO;
}

static void
nvme_pipe_send_icreq_complete(void *cb_arg)
{
	SPDK_DEBUGLOG(SPDK_LOG_NVMF, "Complete the icreq send for tqpair=%p\n",
		      (struct nvme_pipe_qpair *)cb_arg);
}

static int
nvme_pipe_qpair_icreq_send(struct nvme_pipe_qpair *tqpair)
{
	struct spdk_nvme_tcp_ic_req *ic_req;
	struct nvme_tcp_pdu *pdu;
	uint64_t icreq_timeout_tsc;
	int rc;

	pdu = &tqpair->send_pdu;
	memset(&tqpair->send_pdu, 0, sizeof(tqpair->send_pdu));
	ic_req = &pdu->hdr.ic_req;

	ic_req->common.pdu_type = SPDK_NVME_TCP_PDU_TYPE_IC_REQ;
	ic_req->common.hlen = ic_req->common.plen = sizeof(*ic_req);
	ic_req->pfv = 0;
	ic_req->maxr2t = NVME_TCP_MAX_R2T_DEFAULT - 1;
	ic_req->hpda = NVME_TCP_HPDA_DEFAULT;

	ic_req->dgst.bits.hdgst_enable = tqpair->qpair.ctrlr->opts.header_digest;
	ic_req->dgst.bits.ddgst_enable = tqpair->qpair.ctrlr->opts.data_digest;

	// FIXME: callback not implemented
	nvme_pipe_qpair_write_pdu(tqpair, pdu, nvme_pipe_send_icreq_complete, tqpair);

	icreq_timeout_tsc = spdk_get_ticks() + (NVME_TCP_TIME_OUT_IN_SECONDS * spdk_get_ticks_hz());
	do {
		rc = nvme_pipe_qpair_process_completions(&tqpair->qpair, 0);
	} while ((tqpair->state == NVME_TCP_QPAIR_STATE_INVALID) &&
		 (rc == 0) && (spdk_get_ticks() <= icreq_timeout_tsc));

	if (tqpair->state != NVME_TCP_QPAIR_STATE_RUNNING) {
		SPDK_ERRLOG("Failed to construct the tqpair=%p via correct icresp\n", tqpair);
		return -1;
	}

	SPDK_DEBUGLOG(SPDK_LOG_NVME, "Succesfully construct the tqpair=%p via correct icresp\n", tqpair);

	return 0;
}

static int
nvme_pipe_ctrlr_connect_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
	struct sockaddr_storage dst_addr;
	struct sockaddr_storage src_addr;
	int rc;
	struct nvme_pipe_qpair *tqpair;
	struct spdk_sock_opts opts;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	tqpair = nvme_pipe_qpair(qpair);

	tqpair->pipe = spdk_pipe_connect();
	if (tqpair->pipe == NULL) {
		SPDK_ERRLOG("Failed to create buffer for spdk_pipe\n");
		nvme_pipe_ctrlr_delete_io_qpair(ctrlr, qpair);
		return NULL;
	}
	SPDK_NOTICELOG("global_pipe allocated at %p\n",
			tqpair->pipe);

	tqpair->maxr2t = NVME_TCP_MAX_R2T_DEFAULT;
	tqpair->state = NVME_TCP_QPAIR_STATE_INVALID;
	if (tqpair->recv_state != NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY) {
		nvme_pipe_qpair_set_recv_state(tqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY);
	}
	rc = nvme_pipe_qpair_icreq_send(tqpair);
	if (rc != 0) {
		SPDK_ERRLOG("Unable to connect the tqpair (%d)\n", rc);
		return -1;
	}

	rc = nvme_fabric_qpair_connect(&tqpair->qpair, tqpair->num_entries);

	return 0;
}

static struct spdk_nvme_qpair *
nvme_pipe_ctrlr_create_qpair(struct spdk_nvme_ctrlr *ctrlr,
			    uint16_t qid, uint32_t qsize,
			    enum spdk_nvme_qprio qprio,
			    uint32_t num_requests)
{
	struct nvme_pipe_qpair *tqpair;
	struct spdk_nvme_qpair *qpair;
	int rc;

	tqpair = calloc(1, sizeof(struct nvme_pipe_qpair));
	if (!tqpair) {
		SPDK_ERRLOG("failed to get create tqpair\n");
		return NULL;
	}

	tqpair->num_entries = qsize;
	qpair = &tqpair->qpair;
	rc = nvme_qpair_init(qpair, qid, ctrlr, qprio, num_requests);
	if (rc != 0) {
		free(tqpair);
		return NULL;
	}

	rc = nvme_pipe_alloc_reqs(tqpair);
	if (rc) {
		nvme_pipe_ctrlr_delete_io_qpair(ctrlr, qpair);
		return NULL;
	}

	return qpair;
}

static struct spdk_nvme_qpair *
nvme_pipe_ctrlr_create_io_qpair(struct spdk_nvme_ctrlr *ctrlr, uint16_t qid,
			       const struct spdk_nvme_io_qpair_opts *opts)
{
	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	return nvme_pipe_ctrlr_create_qpair(ctrlr, qid, opts->io_queue_size, opts->qprio,
					   opts->io_queue_requests);
}

static struct spdk_nvme_ctrlr *
nvme_pipe_ctrlr_construct(const struct spdk_nvme_transport_id *trid,
		const struct spdk_nvme_ctrlr_opts *opts,
		void *devhandle)
{
	struct nvme_pipe_ctrlr *tctrlr;
	union spdk_nvme_cap_register cap;
	union spdk_nvme_vs_register vs;
	int rc;

	// XXX anything needed here?
	SPDK_NOTICELOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	tctrlr = calloc(1, sizeof(*tctrlr));
	if (tctrlr == NULL) {
		SPDK_ERRLOG("could not allocate ctrlr\n");
		return NULL;
	}

	tctrlr->ctrlr.opts = *opts;
	tctrlr->ctrlr.trid = *trid;

	rc = nvme_ctrlr_construct(&tctrlr->ctrlr);
	if (rc != 0) {
		free(tctrlr);
		return NULL;
	}

	tctrlr->ctrlr.adminq = nvme_pipe_ctrlr_create_qpair(&tctrlr->ctrlr, 0,
			       tctrlr->ctrlr.opts.admin_queue_size, 0,
			       tctrlr->ctrlr.opts.admin_queue_size);
	if (!tctrlr->ctrlr.adminq) {
		SPDK_ERRLOG("failed to create admin qpair\n");
		nvme_pipe_ctrlr_destruct(&tctrlr->ctrlr);
		return NULL;
	}

	rc = nvme_transport_ctrlr_connect_qpair(&tctrlr->ctrlr, tctrlr->ctrlr.adminq);
	if (rc < 0) {
		SPDK_ERRLOG("failed to connect admin qpair\n");
		nvme_pipe_ctrlr_destruct(&tctrlr->ctrlr);
		return NULL;
	}

	if (nvme_ctrlr_get_cap(&tctrlr->ctrlr, &cap)) {
		SPDK_ERRLOG("get_cap() failed\n");
		nvme_ctrlr_destruct(&tctrlr->ctrlr);
		return NULL;
	}

	if (nvme_ctrlr_get_vs(&tctrlr->ctrlr, &vs)) {
		SPDK_ERRLOG("get_vs() failed\n");
		nvme_ctrlr_destruct(&tctrlr->ctrlr);
		return NULL;
	}

	if (nvme_ctrlr_add_process(&tctrlr->ctrlr, 0) != 0) {
		SPDK_ERRLOG("nvme_ctrlr_add_process() failed\n");
		nvme_ctrlr_destruct(&tctrlr->ctrlr);
		return NULL;
	}

	nvme_ctrlr_init_cap(&tctrlr->ctrlr, &cap, &vs);

	return &tctrlr->ctrlr;
}

static uint32_t
nvme_pipe_ctrlr_get_max_xfer_size(struct spdk_nvme_ctrlr *ctrlr)
{
	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	/* TCP transport doens't limit maximum IO transfer size. */
	return UINT32_MAX;
}

static uint16_t
nvme_pipe_ctrlr_get_max_sges(struct spdk_nvme_ctrlr *ctrlr)
{
	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	/*
	 * We do not support >1 SGE in the initiator currently,
	 *  so we can only return 1 here.  Once that support is
	 *  added, this should return ctrlr->cdata.nvmf_specific.msdbd
	 *  instead.
	 */
	return 1;
}

static int
nvme_pipe_qpair_iterate_requests(struct spdk_nvme_qpair *qpair,
				int (*iter_fn)(struct nvme_request *req, void *arg),
				void *arg)
{
	struct nvme_pipe_qpair *tqpair = nvme_pipe_qpair(qpair);
	struct nvme_pipe_req *pipe_req, *tmp;
	int rc;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	assert(iter_fn != NULL);

	TAILQ_FOREACH_SAFE(pipe_req, &tqpair->outstanding_reqs, link, tmp) {
		assert(pipe_req->req != NULL);

		rc = iter_fn(pipe_req->req, arg);
		if (rc != 0) {
			return rc;
		}
	}

	return 0;
}

static void
nvme_pipe_admin_qpair_abort_aers(struct spdk_nvme_qpair *qpair)
{
	struct nvme_pipe_req *pipe_req, *tmp;
	struct spdk_nvme_cpl cpl;
	struct nvme_pipe_qpair *tqpair = nvme_pipe_qpair(qpair);

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	cpl.status.sc = SPDK_NVME_SC_ABORTED_SQ_DELETION;
	cpl.status.sct = SPDK_NVME_SCT_GENERIC;

	TAILQ_FOREACH_SAFE(pipe_req, &tqpair->outstanding_reqs, link, tmp) {
		assert(pipe_req->req != NULL);
		if (pipe_req->req->cmd.opc != SPDK_NVME_OPC_ASYNC_EVENT_REQUEST) {
			continue;
		}

		nvme_pipe_req_complete(pipe_req, &cpl);
		nvme_pipe_req_put(tqpair, pipe_req);
	}
}

static struct spdk_nvme_transport_poll_group *
nvme_pipe_poll_group_create(void)
{
	struct nvme_pipe_poll_group *group = calloc(1, sizeof(*group));

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	if (group == NULL) {
		SPDK_ERRLOG("Unable to allocate poll group.\n");
		return NULL;
	}

	return &group->group;
}

static int
nvme_pipe_poll_group_connect_qpair(struct spdk_nvme_qpair *qpair)
{
	struct nvme_pipe_poll_group *group = nvme_pipe_poll_group(qpair->poll_group);
	struct nvme_pipe_qpair *tqpair = nvme_pipe_qpair(qpair);

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	return 0;
}

static int
nvme_pipe_poll_group_disconnect_qpair(struct spdk_nvme_qpair *qpair)
{
	struct nvme_pipe_poll_group *group = nvme_pipe_poll_group(qpair->poll_group);
	struct nvme_pipe_qpair *tqpair = nvme_pipe_qpair(qpair);

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	return 0;
}

static int
nvme_pipe_poll_group_add(struct spdk_nvme_transport_poll_group *tgroup,
			struct spdk_nvme_qpair *qpair)
{
	struct nvme_pipe_qpair *tqpair = nvme_pipe_qpair(qpair);
	struct nvme_pipe_poll_group *group = nvme_pipe_poll_group(tgroup);

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	/* disconnected qpairs won't have a sock to add. */
	if (nvme_qpair_get_state(qpair) >= NVME_QPAIR_CONNECTED) {
		// do something
	}

	return 0;
}

static int
nvme_pipe_poll_group_remove(struct spdk_nvme_transport_poll_group *tgroup,
			   struct spdk_nvme_qpair *qpair)
{
	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	if (qpair->poll_group_tailq_head == &tgroup->connected_qpairs) {
		return nvme_poll_group_disconnect_qpair(qpair);
	}

	return 0;
}

static int64_t
nvme_pipe_poll_group_process_completions(struct spdk_nvme_transport_poll_group *tgroup,
					uint32_t completions_per_qpair, spdk_nvme_disconnected_qpair_cb disconnected_qpair_cb)
{
	struct nvme_pipe_poll_group *group = nvme_pipe_poll_group(tgroup);
	struct spdk_nvme_qpair *qpair, *tmp_qpair;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	group->completions_per_qpair = completions_per_qpair;
	group->num_completions = 0;

	STAILQ_FOREACH_SAFE(qpair, &tgroup->disconnected_qpairs, poll_group_stailq, tmp_qpair) {
		disconnected_qpair_cb(qpair, tgroup->group->ctx);
	}

	return group->num_completions;
}

static int
nvme_pipe_poll_group_destroy(struct spdk_nvme_transport_poll_group *tgroup)
{
	int rc;
	struct nvme_pipe_poll_group *group = nvme_pipe_poll_group(tgroup);

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	if (!STAILQ_EMPTY(&tgroup->connected_qpairs) || !STAILQ_EMPTY(&tgroup->disconnected_qpairs)) {
		return -EBUSY;
	}

	if (rc != 0) {
		SPDK_ERRLOG("Failed to close the sock group for a tcp poll group.\n");
		assert(false);
	}

	free(tgroup);

	return 0;
}

const struct spdk_nvme_transport_ops pipe_ops = {
	.name = "PIPE",
	.type = SPDK_NVME_TRANSPORT_PIPE,
	.ctrlr_construct = nvme_pipe_ctrlr_construct,
	.ctrlr_scan = nvme_fabric_ctrlr_scan,
	.ctrlr_destruct = nvme_pipe_ctrlr_destruct,
	.ctrlr_enable = nvme_pipe_ctrlr_enable,

	.ctrlr_set_reg_4 = nvme_fabric_ctrlr_set_reg_4,
	.ctrlr_set_reg_8 = nvme_fabric_ctrlr_set_reg_8,
	.ctrlr_get_reg_4 = nvme_fabric_ctrlr_get_reg_4,
	.ctrlr_get_reg_8 = nvme_fabric_ctrlr_get_reg_8,

	.ctrlr_get_max_xfer_size = nvme_pipe_ctrlr_get_max_xfer_size,
	.ctrlr_get_max_sges = nvme_pipe_ctrlr_get_max_sges,

	.ctrlr_create_io_qpair = nvme_pipe_ctrlr_create_io_qpair,
	.ctrlr_delete_io_qpair = nvme_pipe_ctrlr_delete_io_qpair,
	.ctrlr_connect_qpair = nvme_pipe_ctrlr_connect_qpair,
	.ctrlr_disconnect_qpair = nvme_pipe_ctrlr_disconnect_qpair,

	.qpair_abort_reqs = nvme_pipe_qpair_abort_reqs,
	.qpair_reset = nvme_pipe_qpair_reset,
	.qpair_submit_request = nvme_pipe_qpair_submit_request,
	.qpair_process_completions = nvme_pipe_qpair_process_completions,
	.qpair_iterate_requests = nvme_pipe_qpair_iterate_requests,
	.admin_qpair_abort_aers = nvme_pipe_admin_qpair_abort_aers,

	.poll_group_create = nvme_pipe_poll_group_create,
	.poll_group_connect_qpair = nvme_pipe_poll_group_connect_qpair,
	.poll_group_disconnect_qpair = nvme_pipe_poll_group_disconnect_qpair,
	.poll_group_add = nvme_pipe_poll_group_add,
	.poll_group_remove = nvme_pipe_poll_group_remove,
	.poll_group_process_completions = nvme_pipe_poll_group_process_completions,
	.poll_group_destroy = nvme_pipe_poll_group_destroy,
};

SPDK_NVME_TRANSPORT_REGISTER(pipe, &pipe_ops);
