/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation. All rights reserved.
 *   Copyright (c) 2019, 2020 Mellanox Technologies LTD. All rights reserved.
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

#include "spdk/stdinc.h"
#include "spdk/crc32.h"
#include "spdk/endian.h"
#include "spdk/assert.h"
#include "spdk/thread.h"
#include "spdk/nvmf_transport.h"
#include "spdk/sock.h"
#include "spdk/string.h"
#include "spdk/trace.h"
#include "spdk/pipe.h"
#include "spdk/util.h"
#include "spdk/global_queue.h"

#include "spdk_internal/assert.h"
#include "spdk_internal/log.h"
#include "spdk_internal/nvme_tcp.h"

#include "nvmf_internal.h"

#define NVMF_TCP_MAX_ACCEPT_SOCK_ONE_TIME 16
#define SPDK_NVMF_TCP_DEFAULT_MAX_SOCK_PRIORITY 6

const struct spdk_nvmf_transport_ops spdk_nvmf_transport_pipe;

#if 0
/* spdk nvmf related structure */
enum spdk_nvmf_pipe_req_state {

	/* The request is not currently in use */
	PIPE_REQUEST_STATE_FREE = 0,

	/* Initial state when request first received */
	PIPE_REQUEST_STATE_NEW,

	/* The request is queued until a data buffer is available. */
	PIPE_REQUEST_STATE_NEED_BUFFER,

	/* The request is currently transferring data from the host to the controller. */
	PIPE_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER,

	/* The request is waiting for the R2T send acknowledgement. */
	PIPE_REQUEST_STATE_AWAITING_R2T_ACK,

	/* The request is ready to execute at the block device */
	PIPE_REQUEST_STATE_READY_TO_EXECUTE,

	/* The request is currently executing at the block device */
	PIPE_REQUEST_STATE_EXECUTING,

	/* The request finished executing at the block device */
	PIPE_REQUEST_STATE_EXECUTED,

	/* The request is ready to send a completion */
	PIPE_REQUEST_STATE_READY_TO_COMPLETE,

	/* The request is currently transferring final pdus from the controller to the host. */
	PIPE_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST,

	/* The request completed and can be marked free. */
	PIPE_REQUEST_STATE_COMPLETED,

	/* Terminator */
	PIPE_REQUEST_NUM_STATES,
};
#endif

static const char *spdk_nvmf_tcp_term_req_fes_str[] = {
	"Invalid PDU Header Field",
	"PDU Sequence Error",
	"Header Digiest Error",
	"Data Transfer Out of Range",
	"R2T Limit Exceeded",
	"Unsupported parameter",
};

#if 0
#define OBJECT_NVMF_PIPE_IO				0x80

#define TRACE_GROUP_NVMF_PIPE				0x5
#define TRACE_TCP_REQUEST_STATE_NEW					SPDK_TPOINT_ID(TRACE_GROUP_NVMF_TCP, 0x0)
#define TRACE_TCP_REQUEST_STATE_NEED_BUFFER				SPDK_TPOINT_ID(TRACE_GROUP_NVMF_TCP, 0x1)
#define TRACE_TCP_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER		SPDK_TPOINT_ID(TRACE_GROUP_NVMF_TCP, 0x2)
#define TRACE_TCP_REQUEST_STATE_READY_TO_EXECUTE			SPDK_TPOINT_ID(TRACE_GROUP_NVMF_TCP, 0x3)
#define TRACE_TCP_REQUEST_STATE_EXECUTING				SPDK_TPOINT_ID(TRACE_GROUP_NVMF_TCP, 0x4)
#define TRACE_TCP_REQUEST_STATE_EXECUTED				SPDK_TPOINT_ID(TRACE_GROUP_NVMF_TCP, 0x5)
#define TRACE_TCP_REQUEST_STATE_READY_TO_COMPLETE			SPDK_TPOINT_ID(TRACE_GROUP_NVMF_TCP, 0x6)
#define TRACE_TCP_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST		SPDK_TPOINT_ID(TRACE_GROUP_NVMF_TCP, 0x7)
#define TRACE_TCP_REQUEST_STATE_COMPLETED				SPDK_TPOINT_ID(TRACE_GROUP_NVMF_TCP, 0x8)
#define TRACE_TCP_FLUSH_WRITEBUF_START					SPDK_TPOINT_ID(TRACE_GROUP_NVMF_TCP, 0x9)
#define TRACE_TCP_FLUSH_WRITEBUF_DONE					SPDK_TPOINT_ID(TRACE_GROUP_NVMF_TCP, 0xA)
#define TRACE_TCP_READ_FROM_SOCKET_DONE					SPDK_TPOINT_ID(TRACE_GROUP_NVMF_TCP, 0xB)
#define TRACE_TCP_REQUEST_STATE_AWAIT_R2T_ACK				SPDK_TPOINT_ID(TRACE_GROUP_NVMF_TCP, 0xC)

SPDK_TRACE_REGISTER_FN(nvmf_pipe_trace, "nvmf_pipe", TRACE_GROUP_NVMF_PIPE)
{
	spdk_trace_register_object(OBJECT_NVMF_TCP_IO, 'r');
	spdk_trace_register_description("TCP_REQ_NEW",
					TRACE_TCP_REQUEST_STATE_NEW,
					OWNER_NONE, OBJECT_NVMF_TCP_IO, 1, 1, "");
	spdk_trace_register_description("TCP_REQ_NEED_BUFFER",
					TRACE_TCP_REQUEST_STATE_NEED_BUFFER,
					OWNER_NONE, OBJECT_NVMF_TCP_IO, 0, 1, "");
	spdk_trace_register_description("TCP_REQ_TX_H_TO_C",
					TRACE_TCP_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER,
					OWNER_NONE, OBJECT_NVMF_TCP_IO, 0, 1, "");
	spdk_trace_register_description("TCP_REQ_RDY_TO_EXECUTE",
					TRACE_TCP_REQUEST_STATE_READY_TO_EXECUTE,
					OWNER_NONE, OBJECT_NVMF_TCP_IO, 0, 1, "");
	spdk_trace_register_description("TCP_REQ_EXECUTING",
					TRACE_TCP_REQUEST_STATE_EXECUTING,
					OWNER_NONE, OBJECT_NVMF_TCP_IO, 0, 1, "");
	spdk_trace_register_description("TCP_REQ_EXECUTED",
					TRACE_TCP_REQUEST_STATE_EXECUTED,
					OWNER_NONE, OBJECT_NVMF_TCP_IO, 0, 1, "");
	spdk_trace_register_description("TCP_REQ_RDY_TO_COMPLETE",
					TRACE_TCP_REQUEST_STATE_READY_TO_COMPLETE,
					OWNER_NONE, OBJECT_NVMF_TCP_IO, 0, 1, "");
	spdk_trace_register_description("TCP_REQ_TRANSFER_C2H",
					TRACE_TCP_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST,
					OWNER_NONE, OBJECT_NVMF_TCP_IO, 0, 1, "");
	spdk_trace_register_description("TCP_REQ_COMPLETED",
					TRACE_TCP_REQUEST_STATE_COMPLETED,
					OWNER_NONE, OBJECT_NVMF_TCP_IO, 0, 1, "");
	spdk_trace_register_description("TCP_WRITE_START",
					TRACE_TCP_FLUSH_WRITEBUF_START,
					OWNER_NONE, OBJECT_NONE, 0, 0, "");
	spdk_trace_register_description("TCP_WRITE_DONE",
					TRACE_TCP_FLUSH_WRITEBUF_DONE,
					OWNER_NONE, OBJECT_NONE, 0, 0, "");
	spdk_trace_register_description("TCP_READ_DONE",
					TRACE_TCP_READ_FROM_SOCKET_DONE,
					OWNER_NONE, OBJECT_NONE, 0, 0, "");
	spdk_trace_register_description("TCP_REQ_AWAIT_R2T_ACK",
					TRACE_TCP_REQUEST_STATE_AWAIT_R2T_ACK,
					OWNER_NONE, OBJECT_NVMF_TCP_IO, 0, 1, "");
}
#endif

#if 0
struct spdk_nvmf_pipe_req  {
	struct spdk_nvmf_request		req;
	struct spdk_nvme_cpl			rsp;
	struct spdk_nvme_cmd			cmd;

	/* A PDU that can be used for sending responses. This is
	 * not the incoming PDU! */
	struct nvme_tcp_pdu			*pdu;

	/*
	 * The PDU for a request may be used multiple times in serial over
	 * the request's lifetime. For example, first to send an R2T, then
	 * to send a completion. To catch mistakes where the PDU is used
	 * twice at the same time, add a debug flag here for init/fini.
	 */
	bool					pdu_in_use;

	/* In-capsule data buffer */
	uint8_t					*buf;

	bool					has_incapsule_data;

	/* transfer_tag */
	uint16_t				ttag;

	enum spdk_nvmf_pipe_req_state		state;

	/*
	 * h2c_offset is used when we receive the h2c_data PDU.
	 */
	uint32_t				h2c_offset;

	STAILQ_ENTRY(spdk_nvmf_pipe_req)	link;
	TAILQ_ENTRY(spdk_nvmf_pipe_req)		state_link;
};
#endif

struct spdk_nvmf_pipe_qpair {
	struct spdk_nvmf_qpair			qpair;
	struct spdk_nvmf_pipe_poll_group	*group;
	struct spdk_nvmf_pipe_port		*port;
	struct global_queue			*pipe;

	enum nvme_tcp_pdu_recv_state		recv_state;
	enum nvme_tcp_qpair_state		state;

	/* PDU being actively received */
	struct nvme_tcp_pdu			*current_pdu;
	struct nvme_tcp_pdu			pdu_in_progress;
	uint32_t				recv_buf_size;

	/* This is a spare PDU used for sending special management
	 * operations. Primarily, this is used for the initial
	 * connection response and c2h termination request. */
	struct nvme_tcp_pdu			mgmt_pdu;

	TAILQ_HEAD(, nvme_tcp_pdu)		send_queue;

	/* Arrays of in-capsule buffers, requests, and pdus.
	 * Each array is 'resource_count' number of elements */
	void					*bufs;
	struct spdk_nvmf_pipe_req		*reqs;
	struct nvme_tcp_pdu			*pdus;
	uint32_t				resource_count;

	/* Queues to track the requests in all states */
	TAILQ_HEAD(, spdk_nvmf_pipe_req)	state_queue[PIPE_REQUEST_NUM_STATES];
	/* Number of requests in each state */
	uint32_t				state_cntr[PIPE_REQUEST_NUM_STATES];

	uint8_t					cpda;

	bool					host_hdgst_enable;
	bool					host_ddgst_enable;

	/* IP address */
	char					initiator_addr[SPDK_NVMF_TRADDR_MAX_LEN];
	char					target_addr[SPDK_NVMF_TRADDR_MAX_LEN];

	/* IP port */
	uint16_t				initiator_port;
	uint16_t				target_port;

	/* Timer used to destroy qpair after detecting transport error issue if initiator does
	 *  not close the connection.
	 */
	struct spdk_poller			*timeout_poller;

	TAILQ_ENTRY(spdk_nvmf_pipe_qpair)	link;
};

struct spdk_nvmf_pipe_poll_group {
	struct spdk_nvmf_transport_poll_group	group;

	TAILQ_HEAD(, spdk_nvmf_pipe_qpair)	qpairs;
	TAILQ_HEAD(, spdk_nvmf_pipe_qpair)	await_req;
};

struct spdk_nvmf_pipe_port {
	const struct spdk_nvme_transport_id	*trid;
	struct spdk_sock			*listen_sock;
	TAILQ_ENTRY(spdk_nvmf_pipe_port)	link;
};

struct spdk_nvmf_pipe_transport {
	struct spdk_nvmf_transport		transport;

	pthread_mutex_t				lock;

	struct global_queue			*pipe;
};

static bool nvmf_pipe_req_process(struct spdk_nvmf_pipe_transport *ttransport,
				 struct spdk_nvmf_pipe_req *pipe_req);

static void
nvmf_pipe_req_set_state(struct spdk_nvmf_pipe_req *pipe_req,
		       enum spdk_nvmf_pipe_req_state state)
{
	struct spdk_nvmf_qpair *qpair;
	struct spdk_nvmf_pipe_qpair *tqpair;

	qpair = pipe_req->req.qpair;
	tqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_pipe_qpair, qpair);

	TAILQ_REMOVE(&tqpair->state_queue[pipe_req->state], pipe_req, state_link);
	assert(tqpair->state_cntr[pipe_req->state] > 0);
	tqpair->state_cntr[pipe_req->state]--;

	TAILQ_INSERT_TAIL(&tqpair->state_queue[state], pipe_req, state_link);
	tqpair->state_cntr[state]++;

	pipe_req->state = state;
}

static struct spdk_nvmf_pipe_req *
nvmf_pipe_req_get(struct spdk_nvmf_pipe_qpair *tqpair)
{
	struct spdk_nvmf_pipe_req *pipe_req;

	pipe_req = TAILQ_FIRST(&tqpair->state_queue[PIPE_REQUEST_STATE_FREE]);
	if (!pipe_req) {
		return NULL;
	}

	memset(&pipe_req->rsp, 0, sizeof(pipe_req->rsp));
	pipe_req->h2c_offset = 0;
	pipe_req->has_incapsule_data = false;
	pipe_req->req.dif.dif_insert_or_strip = false;

	nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_NEW);
	return pipe_req;
}

static void
nvmf_pipe_request_free(struct spdk_nvmf_pipe_req *pipe_req)
{
	struct spdk_nvmf_pipe_transport *ttransport;

	assert(pipe_req != NULL);

	SPDK_DEBUGLOG(SPDK_LOG_NVMF_PIPE, "pipe_req=%p will be freed\n", pipe_req);
	ttransport = SPDK_CONTAINEROF(pipe_req->req.qpair->transport,
				      struct spdk_nvmf_pipe_transport, transport);
	nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_COMPLETED);
	nvmf_pipe_req_process(ttransport, pipe_req);
}

static int
nvmf_pipe_req_free(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_pipe_req *pipe_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_pipe_req, req);

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	nvmf_pipe_request_free(pipe_req);

	return 0;
}

static void
nvmf_pipe_qpair_destroy(struct spdk_nvmf_pipe_qpair *tqpair)
{
	int err = 0;

	SPDK_DEBUGLOG(SPDK_LOG_NVMF_PIPE, "enter\n");

	assert(err == 0);

	if (tqpair->state_cntr[PIPE_REQUEST_STATE_FREE] != tqpair->resource_count) {
		SPDK_ERRLOG("tqpair(%p) free tcp request num is %u but should be %u\n", tqpair,
			    tqpair->state_cntr[PIPE_REQUEST_STATE_FREE],
			    tqpair->resource_count);
		err++;
	}

	spdk_dma_free(tqpair->pdus);
	free(tqpair->reqs);
	spdk_free(tqpair->bufs);
	free(tqpair);
	SPDK_DEBUGLOG(SPDK_LOG_NVMF_TCP, "Leave\n");
}

static int
nvmf_pipe_destroy(struct spdk_nvmf_transport *transport)
{
	struct spdk_nvmf_pipe_transport	*ttransport;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	assert(transport != NULL);
	ttransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_pipe_transport, transport);

	pthread_mutex_destroy(&ttransport->lock);
	free(ttransport);
	return 0;
}

static struct spdk_nvmf_transport *
nvmf_pipe_create(struct spdk_nvmf_transport_opts *opts)
{
	struct spdk_nvmf_pipe_transport *ttransport;
	uint32_t sge_count;
	uint32_t min_shared_buffers;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	ttransport = calloc(1, sizeof(*ttransport));
	if (!ttransport) {
		return NULL;
	}

	ttransport->transport.ops = &spdk_nvmf_transport_pipe;

	SPDK_NOTICELOG("*** PIPE Transport Init ***\n");

	SPDK_INFOLOG(SPDK_LOG_NVMF_PIPE, "*** PIPE Transport Init ***\n"
		     "  Transport opts:  max_ioq_depth=%d, max_io_size=%d,\n"
		     "  max_io_qpairs_per_ctrlr=%d, io_unit_size=%d,\n"
		     "  in_capsule_data_size=%d, max_aq_depth=%d\n"
		     "  num_shared_buffers=%d, c2h_success=%d,\n"
		     "  dif_insert_or_strip=%d, sock_priority=%d\n"
		     "  abort_timeout_sec=%d\n",
		     opts->max_queue_depth,
		     opts->max_io_size,
		     opts->max_qpairs_per_ctrlr - 1,
		     opts->io_unit_size,
		     opts->in_capsule_data_size,
		     opts->max_aq_depth,
		     opts->num_shared_buffers,
		     opts->c2h_success,
		     opts->dif_insert_or_strip,
		     opts->sock_priority,
		     opts->abort_timeout_sec);

	if (opts->sock_priority > SPDK_NVMF_TCP_DEFAULT_MAX_SOCK_PRIORITY) {
		SPDK_ERRLOG("Unsupported socket_priority=%d, the current range is: 0 to %d\n"
			    "you can use man 7 socket to view the range of priority under SO_PRIORITY item\n",
			    opts->sock_priority, SPDK_NVMF_TCP_DEFAULT_MAX_SOCK_PRIORITY);
		free(ttransport);
		return NULL;
	}

	/* I/O unit size cannot be larger than max I/O size */
	if (opts->io_unit_size > opts->max_io_size) {
		opts->io_unit_size = opts->max_io_size;
	}

	sge_count = opts->max_io_size / opts->io_unit_size;
	if (sge_count > SPDK_NVMF_MAX_SGL_ENTRIES) {
		SPDK_ERRLOG("Unsupported IO Unit size specified, %d bytes\n", opts->io_unit_size);
		free(ttransport);
		return NULL;
	}

	min_shared_buffers = spdk_thread_get_count() * opts->buf_cache_size;
	if (min_shared_buffers > opts->num_shared_buffers) {
		SPDK_ERRLOG("There are not enough buffers to satisfy"
			    "per-poll group caches for each thread. (%" PRIu32 ")"
			    "supplied. (%" PRIu32 ") required\n", opts->num_shared_buffers, min_shared_buffers);
		SPDK_ERRLOG("Please specify a larger number of shared buffers\n");
		nvmf_pipe_destroy(&ttransport->transport);
		return NULL;
	}

	pthread_mutex_init(&ttransport->lock, NULL);

	return &ttransport->transport;
}

static int
nvmf_pipe_listen(struct spdk_nvmf_transport *transport,
		const struct spdk_nvme_transport_id *trid)
{
	struct spdk_nvmf_pipe_transport *ttransport;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	ttransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_pipe_transport, transport);

	// TODO: need to do anything here? maybe init spdk_pipe here?

	return 0;
}

static void
nvmf_pipe_stop_listen(struct spdk_nvmf_transport *transport,
		     const struct spdk_nvme_transport_id *trid)
{
	struct spdk_nvmf_pipe_transport *ttransport;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	ttransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_pipe_transport, transport);

	SPDK_DEBUGLOG(SPDK_LOG_NVMF_TCP, "Removing listen address %s port %s\n",
		      trid->traddr, trid->trsvcid);

}

static void nvmf_pipe_qpair_set_recv_state(struct spdk_nvmf_pipe_qpair *tqpair,
		enum nvme_tcp_pdu_recv_state state);

static int
nvmf_pipe_qpair_init_mem_resource(struct spdk_nvmf_pipe_qpair *tqpair)
{
	uint32_t i;
	struct spdk_nvmf_transport_opts *opts;
	uint32_t in_capsule_data_size;

	opts = &tqpair->qpair.transport->opts;

	in_capsule_data_size = opts->in_capsule_data_size;
	if (opts->dif_insert_or_strip) {
		in_capsule_data_size = SPDK_BDEV_BUF_SIZE_WITH_MD(in_capsule_data_size);
	}

	tqpair->resource_count = opts->max_queue_depth;

	tqpair->mgmt_pdu.qpair = tqpair;

	tqpair->reqs = calloc(tqpair->resource_count, sizeof(*tqpair->reqs));
	if (!tqpair->reqs) {
		SPDK_ERRLOG("Unable to allocate reqs on tqpair=%p\n", tqpair);
		return -1;
	}

	if (in_capsule_data_size) {
		tqpair->bufs = spdk_zmalloc(tqpair->resource_count * in_capsule_data_size, 0x1000,
					    NULL, SPDK_ENV_LCORE_ID_ANY,
					    SPDK_MALLOC_DMA);
		if (!tqpair->bufs) {
			SPDK_ERRLOG("Unable to allocate bufs on tqpair=%p.\n", tqpair);
			return -1;
		}
	}

	tqpair->pdus = spdk_dma_malloc(tqpair->resource_count * sizeof(*tqpair->pdus), 0x1000, NULL);
	if (!tqpair->pdus) {
		SPDK_ERRLOG("Unable to allocate pdu pool on tqpair =%p.\n", tqpair);
		return -1;
	}

	for (i = 0; i < tqpair->resource_count; i++) {
		struct spdk_nvmf_pipe_req *pipe_req = &tqpair->reqs[i];

		pipe_req->ttag = i + 1;
		pipe_req->req.qpair = &tqpair->qpair;

		pipe_req->pdu = &tqpair->pdus[i];
		pipe_req->pdu->qpair = tqpair;

		/* Set up memory to receive commands */
		if (tqpair->bufs) {
			pipe_req->buf = (void *)((uintptr_t)tqpair->bufs + (i * in_capsule_data_size));
		}

		/* Set the cmdn and rsp */
		pipe_req->req.rsp = (union nvmf_c2h_msg *)&pipe_req->rsp;
		pipe_req->req.cmd = (union nvmf_h2c_msg *)&pipe_req->cmd;

		/* Initialize request state to FREE */
		pipe_req->state = PIPE_REQUEST_STATE_FREE;
		TAILQ_INSERT_TAIL(&tqpair->state_queue[pipe_req->state], pipe_req, state_link);
		tqpair->state_cntr[PIPE_REQUEST_STATE_FREE]++;
	}

	tqpair->recv_buf_size = (in_capsule_data_size + sizeof(struct spdk_nvme_tcp_cmd) + 2 *
				 SPDK_NVME_TCP_DIGEST_LEN) * SPDK_NVMF_TCP_RECV_BUF_SIZE_FACTOR;

	return 0;
}

static int
nvmf_pipe_qpair_init(struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_pipe_qpair *tqpair;
	int i;

	tqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_pipe_qpair, qpair);

	SPDK_DEBUGLOG(SPDK_LOG_NVMF_PIPE, "New PIPE Connection: %p\n", qpair);

	TAILQ_INIT(&tqpair->send_queue);

	/* Initialise request state queues of the qpair */
	for (i = PIPE_REQUEST_STATE_FREE; i < PIPE_REQUEST_NUM_STATES; i++) {
		TAILQ_INIT(&tqpair->state_queue[i]);
	}

	tqpair->host_hdgst_enable = true;
	tqpair->host_ddgst_enable = true;

	return 0;
}

static void nvmf_tcp_qpair_set_recv_state(struct spdk_nvmf_tcp_qpair *tqpair,
		enum nvme_tcp_pdu_recv_state state);

static uint32_t
nvmf_pipe_handle_connect(struct spdk_nvmf_transport *transport)
{
	uint32_t count = 0;
	struct spdk_nvmf_pipe_qpair *tqpair;
	struct global_queue *gq;

	gq = spdk_pipe_accept();

	SPDK_NOTICELOG("New connection accepted on pipe %p\n",
			gq);

	assert(gq != NULL);

	tqpair = calloc(1, sizeof(struct spdk_nvmf_pipe_qpair));
	if (tqpair == NULL) {
		SPDK_ERRLOG("Could not allocate new qpair\n");
		return 0;
	}

	tqpair->pipe = gq;
	SPDK_NOTICELOG("aquired global pipe at %p\n", tqpair->pipe);

	tqpair->state_cntr[PIPE_REQUEST_STATE_FREE] = 0;
	tqpair->qpair.transport = transport;

	spdk_nvmf_tgt_new_qpair(transport->tgt, &tqpair->qpair);

	count += 1;

	return count;
}

static uint32_t
nvmf_pipe_accept(struct spdk_nvmf_transport *transport)
{
	struct spdk_nvmf_pipe_transport *ttransport;
	uint32_t count = 0;

	// XXX anything needed here?
	//SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	ttransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_pipe_transport, transport);

	// FIXME: this is where new connection created, fio will create num_job+1 connections
	if (spdk_pipe_pending_connection()) {
		count = nvmf_pipe_handle_connect(transport);
	}

	return count;
}

static void
nvmf_pipe_discover(struct spdk_nvmf_transport *transport,
		  struct spdk_nvme_transport_id *trid,
		  struct spdk_nvmf_discovery_log_page_entry *entry)
{
	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	// XXX: anything needed for discovery?
	entry->trtype = SPDK_NVMF_TRTYPE_PIPE;
	entry->adrfam = trid->adrfam;
	entry->treq.secure_channel = SPDK_NVMF_TREQ_SECURE_CHANNEL_NOT_REQUIRED;

	spdk_strcpy_pad(entry->trsvcid, trid->trsvcid, sizeof(entry->trsvcid), ' ');
	spdk_strcpy_pad(entry->traddr, trid->traddr, sizeof(entry->traddr), ' ');

	entry->tsas.tcp.sectype = SPDK_NVME_TCP_SECURITY_NONE;
}

static struct spdk_nvmf_transport_poll_group *
nvmf_pipe_poll_group_create(struct spdk_nvmf_transport *transport)
{
	struct spdk_nvmf_pipe_poll_group *tgroup;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	tgroup = calloc(1, sizeof(*tgroup));
	if (!tgroup) {
		return NULL;
	}

	TAILQ_INIT(&tgroup->qpairs);
	TAILQ_INIT(&tgroup->await_req);

	return &tgroup->group;

cleanup:
	free(tgroup);
	return NULL;
}

static struct spdk_nvmf_transport_poll_group *
nvmf_pipe_get_optimal_poll_group(struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_pipe_qpair *tqpair;
	int rc;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	tqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_pipe_qpair, qpair);

	// XXX: anything needed here?

	return NULL;
}

static void
nvmf_pipe_poll_group_destroy(struct spdk_nvmf_transport_poll_group *group)
{
	struct spdk_nvmf_pipe_poll_group *tgroup;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	tgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_pipe_poll_group, group);

	free(tgroup);
}

static void
nvmf_pipe_qpair_set_recv_state(struct spdk_nvmf_pipe_qpair *tqpair,
			      enum nvme_tcp_pdu_recv_state state)
{
	if (tqpair->recv_state == state) {
		SPDK_ERRLOG("The recv state of tqpair=%p is same with the state(%d) to be set\n",
			    tqpair, state);
		return;
	}

	if (tqpair->recv_state == NVME_TCP_PDU_RECV_STATE_AWAIT_REQ) {
		/* When leaving the await req state, move the qpair to the main list */
		TAILQ_REMOVE(&tqpair->group->await_req, tqpair, link);
		TAILQ_INSERT_TAIL(&tqpair->group->qpairs, tqpair, link);
	}

	//SPDK_DEBUGLOG(SPDK_LOG_NVMF_TCP, "tqpair(%p) recv state=%d\n", tqpair, state);
	tqpair->recv_state = state;

	switch (state) {
	case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_CH:
	case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PSH:
	case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PAYLOAD:
		break;
	case NVME_TCP_PDU_RECV_STATE_AWAIT_REQ:
		TAILQ_REMOVE(&tqpair->group->qpairs, tqpair, link);
		TAILQ_INSERT_TAIL(&tqpair->group->await_req, tqpair, link);
		break;
	case NVME_TCP_PDU_RECV_STATE_ERROR:
	case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY:
		tqpair->current_pdu = NULL;
		//memset(&tqpair->pdu_in_progress, 0, sizeof(tqpair->pdu_in_progress));
		break;
	default:
		SPDK_ERRLOG("The state(%d) is invalid\n", state);
		abort();
		break;
	}
}

static int
nvmf_pipe_nvme_req_process(struct spdk_nvmf_pipe_qpair *tqpair,
		struct global_queue_req *global_req);
static int
nvmf_pipe_gq_process(struct spdk_nvmf_pipe_qpair *tqpair)
{
	int rc = 0;
	struct global_queue *gp;

	gp = tqpair->pipe;

	if (!spdk_pipe_h2c_queue_empty(gp)) {
		struct global_queue_req *global_req;
		global_req = spdk_pipe_get_recv_h2c_req(gp);
		if (global_req->pdu)
			tqpair->current_pdu = global_req->pdu;
		else
			tqpair->current_pdu = global_req->nvme_req->send_pdu;
		SPDK_NOTICELOG("global_req aquired at %p nvme_req %p pdu %p\n",
				global_req, global_req->nvme_req, tqpair->current_pdu);
		nvmf_pipe_nvme_req_process(tqpair, global_req);
	}
	return rc;
}

static int
nvmf_pipe_req_parse_sgl(struct spdk_nvmf_pipe_req *pipe_req,
		       struct spdk_nvmf_transport *transport,
		       struct spdk_nvmf_transport_poll_group *group)
{
	struct spdk_nvmf_request		*req = &pipe_req->req;
	struct spdk_nvme_cmd			*cmd;
	struct spdk_nvme_cpl			*rsp;
	struct spdk_nvme_sgl_descriptor		*sgl;
	uint32_t				length;

	cmd = &req->cmd->nvme_cmd;
	rsp = &req->rsp->nvme_cpl;
	sgl = &cmd->dptr.sgl1;

	length = sgl->unkeyed.length;

	if (sgl->generic.type == SPDK_NVME_SGL_TYPE_TRANSPORT_DATA_BLOCK &&
	    sgl->unkeyed.subtype == SPDK_NVME_SGL_SUBTYPE_TRANSPORT) {
		if (length > transport->opts.max_io_size) {
			SPDK_ERRLOG("SGL length 0x%x exceeds max io size 0x%x\n",
				    length, transport->opts.max_io_size);
			rsp->status.sc = SPDK_NVME_SC_DATA_SGL_LENGTH_INVALID;
			return -1;
		}

		/* fill request length and populate iovs */
		req->length = length;

		SPDK_DEBUGLOG(SPDK_LOG_NVMF_PIPE, "Data requested length= 0x%x\n", length);

		if (spdk_unlikely(req->dif.dif_insert_or_strip)) {
			req->dif.orig_length = length;
			length = spdk_dif_get_length_with_md(length, &req->dif.dif_ctx);
			req->dif.elba_length = length;
		}

		if (spdk_nvmf_request_get_buffers(req, group, transport, length)) {
			/* No available buffers. Queue this request up. */
			SPDK_DEBUGLOG(SPDK_LOG_NVMF_PIPE, "No available large data buffers. Queueing request %p\n",
				      pipe_req);
			return 0;
		}

		/* backward compatible */
		req->data = req->iov[0].iov_base;

		SPDK_DEBUGLOG(SPDK_LOG_NVMF_PIPE, "Request %p took %d buffer/s from central pool, and data=%p\n",
			      pipe_req, req->iovcnt, req->data);

		return 0;
	} else if (sgl->generic.type == SPDK_NVME_SGL_TYPE_DATA_BLOCK &&
		   sgl->unkeyed.subtype == SPDK_NVME_SGL_SUBTYPE_OFFSET) {
		uint64_t offset = sgl->address;
		uint32_t max_len = transport->opts.in_capsule_data_size;

		SPDK_DEBUGLOG(SPDK_LOG_NVMF_PIPE, "In-capsule data: offset 0x%" PRIx64 ", length 0x%x\n",
			      offset, length);

		if (offset > max_len) {
			SPDK_ERRLOG("In-capsule offset 0x%" PRIx64 " exceeds capsule length 0x%x\n",
				    offset, max_len);
			rsp->status.sc = SPDK_NVME_SC_INVALID_SGL_OFFSET;
			return -1;
		}
		max_len -= (uint32_t)offset;

		if (length > max_len) {
			SPDK_ERRLOG("In-capsule data length 0x%x exceeds capsule length 0x%x\n",
				    length, max_len);
			rsp->status.sc = SPDK_NVME_SC_DATA_SGL_LENGTH_INVALID;
			return -1;
		}

		req->data = pipe_req->buf + offset;
		req->data_from_pool = false;
		req->length = length;

		if (spdk_unlikely(req->dif.dif_insert_or_strip)) {
			length = spdk_dif_get_length_with_md(length, &req->dif.dif_ctx);
			req->dif.elba_length = length;
		}

		req->iov[0].iov_base = req->data;
		req->iov[0].iov_len = length;
		req->iovcnt = 1;

		return 0;
	}

	SPDK_ERRLOG("Invalid NVMf I/O Command SGL:  Type 0x%x, Subtype 0x%x\n",
		    sgl->generic.type, sgl->generic.subtype);
	rsp->status.sc = SPDK_NVME_SC_SGL_DESCRIPTOR_TYPE_INVALID;
	return -1;
}

static void
nvmf_pipe_set_incapsule_data(struct spdk_nvmf_pipe_qpair *tqpair,
			    struct spdk_nvmf_pipe_req *pipe_req)
{
	struct nvme_tcp_pdu *pdu;
	uint32_t plen = 0;

	pdu = tqpair->current_pdu;
	plen = pdu->hdr.common.hlen;

	if (tqpair->host_hdgst_enable) {
		plen += SPDK_NVME_TCP_DIGEST_LEN;
	}

	if (pdu->hdr.common.plen != plen) {
		pipe_req->has_incapsule_data = true;
	}
}

static inline struct nvme_tcp_pdu *
nvmf_pipe_req_pdu_init(struct spdk_nvmf_pipe_req *pipe_req)
{
	assert(pipe_req->pdu_in_use == false);
	pipe_req->pdu_in_use = true;

	memset(pipe_req->pdu, 0, sizeof(*pipe_req->pdu));
	pipe_req->pdu->qpair = SPDK_CONTAINEROF(pipe_req->req.qpair, struct spdk_nvmf_pipe_qpair, qpair);

	return pipe_req->pdu;
}

static inline void
nvmf_pipe_req_pdu_fini(struct spdk_nvmf_pipe_req *pipe_req)
{
	pipe_req->pdu_in_use = false;
}

static void _pdu_issue_callback(void *_pdu)
{
	struct nvme_tcp_pdu	*pdu = _pdu;

	if (pdu->cb_fn)
		pdu->cb_fn(pdu->cb_arg);
}

static void
_pdu_write_done(void *_pdu, int err)
{
	struct nvme_tcp_pdu			*pdu = _pdu;
	struct spdk_nvmf_pipe_qpair		*tqpair = pdu->qpair;

	TAILQ_REMOVE(&tqpair->send_queue, pdu, tailq);

	if (err != 0) {
		SPDK_ERRLOG("|%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
		assert(0);
		//nvmf_tcp_qpair_disconnect(tqpair);
		return;
	}

	assert(pdu->cb_fn != NULL);
	pdu->cb_fn(pdu->cb_arg);
}

static void
nvmf_pipe_qpair_write_pdu(struct spdk_nvmf_pipe_qpair *tqpair,
			 struct nvme_tcp_pdu *pdu,
			 nvme_tcp_qpair_xfer_complete_cb cb_fn,
			 void *cb_arg)
{
	int hlen;
	uint32_t crc32c;
	uint32_t mapped_length = 0;
	ssize_t rc = 0;

	assert(&tqpair->pdu_in_progress != pdu);

	hlen = pdu->hdr.common.hlen;

	/* Header Digest */
	if (g_nvme_tcp_hdgst[pdu->hdr.common.pdu_type] && tqpair->host_hdgst_enable) {
		//crc32c = nvme_tcp_pdu_calc_header_digest(pdu);
		//MAKE_DIGEST_WORD((uint8_t *)pdu->hdr.raw + hlen, crc32c);
		//SPDK_ERRLOG("|%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
		//assert(0);
		// XXX: need anything here?
	}

	/* Data Digest */
	if (pdu->data_len > 0 && g_nvme_tcp_ddgst[pdu->hdr.common.pdu_type] && tqpair->host_ddgst_enable) {
		//crc32c = nvme_tcp_pdu_calc_data_digest(pdu);
		//MAKE_DIGEST_WORD(pdu->data_digest, crc32c);
		SPDK_ERRLOG("|%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
		assert(0);
	}

	// FIXME: callback not implemented yet
	pdu->cb_fn = cb_fn;
	pdu->cb_arg = cb_arg;

	// FIXME: callback not implemented yet
	//pdu->sock_req.iovcnt = nvme_tcp_build_iovs(pdu->iov, SPDK_COUNTOF(pdu->iov), pdu,
	//		       tqpair->host_hdgst_enable, tqpair->host_ddgst_enable,
	//		       &mapped_length);
	//pdu->sock_req.cb_fn = _pdu_write_done;
	//pdu->sock_req.cb_arg = pdu;
	TAILQ_INSERT_TAIL(&tqpair->send_queue, pdu, tailq);
	if (pdu->hdr.common.pdu_type == SPDK_NVME_TCP_PDU_TYPE_IC_RESP ||
	    pdu->hdr.common.pdu_type == SPDK_NVME_TCP_PDU_TYPE_C2H_TERM_REQ) {
		//rc = spdk_sock_writev(tqpair->sock, pdu->iov, pdu->sock_req.iovcnt);
		struct global_queue_req *global_req;

		global_req = spdk_pipe_get_free_c2h_req(tqpair->pipe);
		global_req->pdu = pdu;
		spdk_pipe_submit_c2h_req(tqpair->pipe, global_req);
		// FIXME: how to do synchronously
		SPDK_ERRLOG("|%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
		assert(0);
		if (rc == mapped_length) {
			//_pdu_write_done(pdu, 0);
		} else {
			SPDK_ERRLOG("IC_RESP or TERM_REQ could not write to socket.\n");
			//_pdu_write_done(pdu, -1);
		}
	} else {
		//spdk_sock_writev_async(tqpair->sock, &pdu->sock_req);
		struct global_queue_req *global_req;

		global_req = spdk_pipe_get_free_c2h_req(tqpair->pipe);
		global_req->pdu = pdu;
		spdk_pipe_submit_c2h_req(tqpair->pipe, global_req);
	}
}

static void
nvmf_pipe_r2t_complete(void *cb_arg)
{
	// FIXME: callback not implemented yet
	struct spdk_nvmf_pipe_req *pipe_req = cb_arg;
	struct spdk_nvmf_pipe_transport *ttransport;

	SPDK_ERRLOG("|%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
	nvmf_pipe_req_pdu_fini(pipe_req);

	ttransport = SPDK_CONTAINEROF(pipe_req->req.qpair->transport,
				      struct spdk_nvmf_pipe_transport, transport);

	nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER);

	nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_READY_TO_EXECUTE);
	nvmf_pipe_req_process(ttransport, pipe_req);
}

static void
nvmf_pipe_send_r2t_pdu(struct spdk_nvmf_pipe_qpair *tqpair,
		      struct spdk_nvmf_pipe_req *pipe_req)
{
	struct nvme_tcp_pdu *rsp_pdu;
	struct spdk_nvme_tcp_r2t_hdr *r2t;

	SPDK_ERRLOG("|%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
	rsp_pdu = nvmf_pipe_req_pdu_init(pipe_req);
	assert(rsp_pdu != NULL);

	r2t = &rsp_pdu->hdr.r2t;
	r2t->common.pdu_type = SPDK_NVME_TCP_PDU_TYPE_R2T;
	r2t->common.plen = r2t->common.hlen = sizeof(*r2t);

	if (tqpair->host_hdgst_enable) {
		r2t->common.flags |= SPDK_NVME_TCP_CH_FLAGS_HDGSTF;
		r2t->common.plen += SPDK_NVME_TCP_DIGEST_LEN;
	}

	r2t->cccid = pipe_req->req.cmd->nvme_cmd.cid;
	r2t->ttag = pipe_req->ttag;
	r2t->r2to = pipe_req->h2c_offset;
	r2t->r2tl = pipe_req->req.length;

	nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_AWAITING_R2T_ACK);

	SPDK_DEBUGLOG(SPDK_LOG_NVMF_TCP,
		      "tcp_req(%p) on tqpair(%p), r2t_info: cccid=%u, ttag=%u, r2to=%u, r2tl=%u\n",
		      tcp_req, tqpair, r2t->cccid, r2t->ttag, r2t->r2to, r2t->r2tl);
	nvmf_pipe_qpair_write_pdu(tqpair, rsp_pdu, nvmf_pipe_r2t_complete, pipe_req);
}

static void
nvmf_pipe_pdu_c2h_data_complete(void *cb_arg)
{
	struct spdk_nvmf_pipe_req *pipe_req = cb_arg;
	struct spdk_nvmf_pipe_qpair *tqpair = SPDK_CONTAINEROF(pipe_req->req.qpair,
					     struct spdk_nvmf_pipe_qpair, qpair);

	assert(tqpair != NULL);
	if (tqpair->qpair.transport->opts.c2h_success) {
		nvmf_pipe_request_free(pipe_req);
	} else {
		SPDK_ERRLOG("|%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
		assert(0);
	}
}

static void
_nvme_pipe_pdu_set_data(struct nvme_tcp_pdu *pdu, void *data, uint32_t data_len)
{
	pdu->data_iov[0].iov_base = data;
	pdu->data_iov[0].iov_len = data_len;
	pdu->data_iovcnt = 1;
}

static void
nvme_pipe_pdu_set_data_buf(struct nvme_tcp_pdu *pdu,
			  struct iovec *iov, int iovcnt,
			  uint32_t data_offset, uint32_t data_len)
{
	uint32_t buf_offset, buf_len, remain_len, len;
	uint8_t *buf;
	struct _nvme_tcp_sgl *pdu_sgl, buf_sgl;

	pdu->data_len = data_len;

	if (spdk_likely(!pdu->dif_ctx)) {
		buf_offset = data_offset;
		buf_len = data_len;
	} else {
		spdk_dif_ctx_set_data_offset(pdu->dif_ctx, data_offset);
		spdk_dif_get_range_with_md(data_offset, data_len,
					   &buf_offset, &buf_len, pdu->dif_ctx);
	}

	if (iovcnt == 1) {
		_nvme_pipe_pdu_set_data(pdu, (void *)((uint64_t)iov[0].iov_base + buf_offset), buf_len);
	} else {
		pdu_sgl = &pdu->sgl;

		_nvme_tcp_sgl_init(pdu_sgl, pdu->data_iov, NVME_TCP_MAX_SGL_DESCRIPTORS, 0);
		_nvme_tcp_sgl_init(&buf_sgl, iov, iovcnt, 0);

		_nvme_tcp_sgl_advance(&buf_sgl, buf_offset);
		remain_len = buf_len;

		while (remain_len > 0) {
			_nvme_tcp_sgl_get_buf(&buf_sgl, (void *)&buf, &len);
			len = spdk_min(len, remain_len);

			_nvme_tcp_sgl_advance(&buf_sgl, len);
			remain_len -= len;

			if (!_nvme_tcp_sgl_append(pdu_sgl, buf, len)) {
				break;
			}
		}

		assert(remain_len == 0);
		assert(pdu_sgl->total_size == buf_len);

		pdu->data_iovcnt = NVME_TCP_MAX_SGL_DESCRIPTORS - pdu_sgl->iovcnt;
	}
}


static void
nvmf_pipe_send_c2h_data(struct spdk_nvmf_pipe_qpair *tqpair,
		       struct spdk_nvmf_pipe_req *pipe_req)
{
	struct nvme_tcp_pdu *rsp_pdu;
	struct spdk_nvme_tcp_c2h_data_hdr *c2h_data;
	uint32_t plen, pdo, alignment;
	int rc;

	SPDK_DEBUGLOG(SPDK_LOG_NVMF_TCP, "enter\n");

	rsp_pdu = nvmf_pipe_req_pdu_init(pipe_req);
	assert(rsp_pdu != NULL);

	c2h_data = &rsp_pdu->hdr.c2h_data;
	c2h_data->common.pdu_type = SPDK_NVME_TCP_PDU_TYPE_C2H_DATA;
	plen = c2h_data->common.hlen = sizeof(*c2h_data);

	if (tqpair->host_hdgst_enable) {
		plen += SPDK_NVME_TCP_DIGEST_LEN;
		c2h_data->common.flags |= SPDK_NVME_TCP_CH_FLAGS_HDGSTF;
	}

	/* set the psh */
	c2h_data->cccid = pipe_req->req.cmd->nvme_cmd.cid;
	c2h_data->datal = pipe_req->req.length;
	c2h_data->datao = 0;

	/* set the padding */
	rsp_pdu->padding_len = 0;
	pdo = plen;
	if (tqpair->cpda) {
		alignment = (tqpair->cpda + 1) << 2;
		if (alignment > plen) {
			rsp_pdu->padding_len = alignment - plen;
			pdo = plen = alignment;
		}
	}

	c2h_data->common.pdo = pdo;
	plen += c2h_data->datal;
	if (tqpair->host_ddgst_enable) {
		c2h_data->common.flags |= SPDK_NVME_TCP_CH_FLAGS_DDGSTF;
		plen += SPDK_NVME_TCP_DIGEST_LEN;
	}

	c2h_data->common.plen = plen;

	if (spdk_unlikely(pipe_req->req.dif.dif_insert_or_strip)) {
		rsp_pdu->dif_ctx = &pipe_req->req.dif.dif_ctx;
	}

	nvme_pipe_pdu_set_data_buf(rsp_pdu, pipe_req->req.iov, pipe_req->req.iovcnt,
				  c2h_data->datao, c2h_data->datal);

	if (spdk_unlikely(pipe_req->req.dif.dif_insert_or_strip)) {
		struct spdk_nvme_cpl *rsp = &pipe_req->req.rsp->nvme_cpl;
		struct spdk_dif_error err_blk = {};

		SPDK_ERRLOG("|%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
		assert(0);

	}

	c2h_data->common.flags |= SPDK_NVME_TCP_C2H_DATA_FLAGS_LAST_PDU;
	if (tqpair->qpair.transport->opts.c2h_success) {
		c2h_data->common.flags |= SPDK_NVME_TCP_C2H_DATA_FLAGS_SUCCESS;
	}

	nvmf_pipe_qpair_write_pdu(tqpair, rsp_pdu, nvmf_pipe_pdu_c2h_data_complete, pipe_req);
}

static void
nvmf_pipe_pdu_cmd_complete(void *cb_arg)
{
	struct spdk_nvmf_pipe_req *pipe_req = cb_arg;
	nvmf_pipe_request_free(pipe_req);
}

static void
nvmf_pipe_send_capsule_resp_pdu(struct spdk_nvmf_pipe_req *pipe_req,
			       struct spdk_nvmf_pipe_qpair *tqpair)
{
	struct nvme_tcp_pdu *rsp_pdu;
	struct spdk_nvme_tcp_rsp *capsule_resp;

	SPDK_DEBUGLOG(SPDK_LOG_NVMF_TCP, "enter, tqpair=%p\n", tqpair);

	rsp_pdu = nvmf_pipe_req_pdu_init(pipe_req);
	assert(rsp_pdu != NULL);

	capsule_resp = &rsp_pdu->hdr.capsule_resp;
	capsule_resp->common.pdu_type = SPDK_NVME_TCP_PDU_TYPE_CAPSULE_RESP;
	capsule_resp->common.plen = capsule_resp->common.hlen = sizeof(*capsule_resp);
	capsule_resp->rccqe = pipe_req->req.rsp->nvme_cpl;
	if (tqpair->host_hdgst_enable) {
		capsule_resp->common.flags |= SPDK_NVME_TCP_CH_FLAGS_HDGSTF;
		capsule_resp->common.plen += SPDK_NVME_TCP_DIGEST_LEN;
	}

	nvmf_pipe_qpair_write_pdu(tqpair, rsp_pdu, nvmf_pipe_pdu_cmd_complete, pipe_req);
}

static int
request_transfer_out(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_pipe_req	*pipe_req;
	struct spdk_nvmf_qpair		*qpair;
	struct spdk_nvmf_pipe_qpair	*tqpair;
	struct spdk_nvme_cpl		*rsp;

	SPDK_DEBUGLOG(SPDK_LOG_NVMF_PIPE, "enter\n");

	qpair = req->qpair;
	rsp = &req->rsp->nvme_cpl;
	pipe_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_pipe_req, req);

	/* Advance our sq_head pointer */
	if (qpair->sq_head == qpair->sq_head_max) {
		qpair->sq_head = 0;
	} else {
		qpair->sq_head++;
	}
	rsp->sqhd = qpair->sq_head;

	tqpair = SPDK_CONTAINEROF(pipe_req->req.qpair, struct spdk_nvmf_pipe_qpair, qpair);
	nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST);
	if (rsp->status.sc == SPDK_NVME_SC_SUCCESS && req->xfer == SPDK_NVME_DATA_CONTROLLER_TO_HOST) {
		nvmf_pipe_send_c2h_data(tqpair, pipe_req);
	} else {
		nvmf_pipe_send_capsule_resp_pdu(pipe_req, tqpair);
	}

	return 0;
}

static bool
nvmf_pipe_req_process(struct spdk_nvmf_pipe_transport *ttransport,
		     struct spdk_nvmf_pipe_req *pipe_req)
{
	struct spdk_nvmf_pipe_qpair		*tqpair;
	int					rc;
	enum spdk_nvmf_pipe_req_state		prev_state;
	bool					progress = false;
	struct spdk_nvmf_transport		*transport = &ttransport->transport;
	struct spdk_nvmf_transport_poll_group	*group;

	tqpair = SPDK_CONTAINEROF(pipe_req->req.qpair, struct spdk_nvmf_pipe_qpair, qpair);
	group = &tqpair->group->group;
	assert(pipe_req->state != PIPE_REQUEST_STATE_FREE);

	if (tqpair->qpair.state != SPDK_NVMF_QPAIR_ACTIVE) {
		if (pipe_req->state == PIPE_REQUEST_STATE_NEED_BUFFER) {
			STAILQ_REMOVE(&group->pending_buf_queue, &pipe_req->req,
					spdk_nvmf_request, buf_link);
		}
		nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_COMPLETED);
	}

	do {
		prev_state = pipe_req->state;

		SPDK_NOTICELOG("Request %p entering state %d on tqpair=%p\n", pipe_req, prev_state,
			      tqpair);

		switch (pipe_req->state) {
		case PIPE_REQUEST_STATE_FREE:
			break;
		case PIPE_REQUEST_STATE_NEW:
			// 1. copy the cmd from recv buffer
			pipe_req->cmd = tqpair->current_pdu->hdr.capsule_cmd.ccsqe;

			pipe_req->req.xfer = spdk_nvmf_req_get_xfer(&pipe_req->req);

			if (pipe_req->req.xfer == SPDK_NVME_DATA_NONE) {
				_pdu_issue_callback(tqpair->current_pdu);
				nvmf_pipe_qpair_set_recv_state(tqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY);
				nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_READY_TO_EXECUTE);
				break;
			}
			// TODO: copy data
			nvmf_pipe_set_incapsule_data(tqpair, pipe_req);

			nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_NEED_BUFFER);
			STAILQ_INSERT_TAIL(&group->pending_buf_queue, &pipe_req->req, buf_link);
			break;
		case PIPE_REQUEST_STATE_NEED_BUFFER:

			if (!pipe_req->has_incapsule_data && (&pipe_req->req != STAILQ_FIRST(&group->pending_buf_queue))) {
				SPDK_NOTICELOG(
					      "Not the first element to wait for the buf for tcp_req(%p) on tqpair=%p\n", pipe_req, tqpair);
				break;
			}

			rc = nvmf_pipe_req_parse_sgl(pipe_req, transport, group);
			if (rc < 0) {
				SPDK_ERRLOG("failed to get buffer\n");
				assert(0);
				break;
			}

			if (!pipe_req->req.data) {
				SPDK_ERRLOG("No buffer allocated for pipe_req(%p) on tqpair(%p)\n",
						pipe_req, tqpair);
				break;
			}
			STAILQ_REMOVE(&group->pending_buf_queue, &pipe_req->req, spdk_nvmf_request, buf_link);
			if (pipe_req->req.xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER) {
				if (pipe_req->req.data_from_pool) {
					nvmf_pipe_send_r2t_pdu(tqpair, pipe_req);
				} else {
					struct nvme_tcp_pdu *pdu;

					nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER);
					pdu = tqpair->current_pdu;

					// XXX: don't call nvme_tcp_pdu_set_data_buf here, since pdu is shared
					nvmf_pipe_qpair_set_recv_state(tqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PAYLOAD);
				}
				break;
			}

			nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_READY_TO_EXECUTE);
			break;
		case PIPE_REQUEST_STATE_AWAITING_R2T_ACK:
			break;
		case PIPE_REQUEST_STATE_READY_TO_EXECUTE:

			if (spdk_unlikely(pipe_req->req.dif.dif_insert_or_strip)) {
				assert(pipe_req->req.dif.elba_length >= pipe_req->req.length);
				pipe_req->req.length = pipe_req->req.dif.elba_length;
			}

			nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_EXECUTING);
			spdk_nvmf_request_exec(&pipe_req->req);
			break;
		case PIPE_REQUEST_STATE_EXECUTING:
			// nothing need here
			break;
		case PIPE_REQUEST_STATE_EXECUTED:

			if (spdk_unlikely(pipe_req->req.dif.dif_insert_or_strip)) {
				pipe_req->req.length = pipe_req->req.dif.orig_length;
			}

			nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_READY_TO_COMPLETE);
			break;
		case PIPE_REQUEST_STATE_READY_TO_COMPLETE:
			rc = request_transfer_out(&pipe_req->req);
			assert(rc == 0);
			break;
		case PIPE_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST:
			SPDK_ERRLOG("|%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
			break;
		case PIPE_REQUEST_STATE_COMPLETED:
			if (pipe_req->req.data_from_pool) {
				spdk_nvmf_request_free_buffers(&pipe_req->req, group, transport);
			}

			pipe_req->req.length = 0;
			pipe_req->req.iovcnt = 0;
			pipe_req->req.data = NULL;

			nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_FREE);
			break;
		default:
			SPDK_ERRLOG("%s (%s:%d) unexpected req state %d\n",
					__func__, __FILE__, __LINE__, pipe_req->state);
			assert(0);
			break;
		}

		if (pipe_req->state != prev_state)
			progress = true;
	} while (pipe_req->state != prev_state);

	return progress;
}

static void
dump_global_req(struct global_queue_req *req)
{
	SPDK_NOTICELOG("Dumping global_queue req %p\n"
			"\tnvme_req %p\n"
			"\tnvmf_req %p\n"
			"\tpdu %p\n",
			req,
			req->nvme_req,
			req->nvmf_req,
			req->pdu);
}

static void
dump_nvme_req(struct global_queue_req *req)
{
	int i;

	if (req->nvme_req == NULL)
		return;

	SPDK_NOTICELOG("Dumping nvme_req in global_req %p\n"
			"\tnvme_req %p\n"
			"\t\treq %p\n"
			"\t\tstate %d\n"
			"\t\tcid %u\n"
			"\t\tttag %u\n"
			"\t\tdatao %u\n"
			"\t\tr2tl_remain %u\n"
			"\t\tactive_r2ts %u\n"
			"\t\tin_capsule_data %u\n"
			"\t\tordering %x\n"
			"\t\tsend_pdu %p\n"
			"\t\tpayload_size %u\n"
			"\t\tiovcnt %u\n",
			req,
			req->nvme_req,
			req->nvme_req->req,
			req->nvme_req->state,
			req->nvme_req->cid,
			req->nvme_req->ttag,
			req->nvme_req->datao,
			req->nvme_req->r2tl_remain,
			req->nvme_req->active_r2ts,
			req->nvme_req->in_capsule_data,
			req->nvme_req->ordering,
			req->nvme_req->send_pdu,
			req->nvme_req->req->payload_size,
			req->nvme_req->iovcnt);
	for (i = 0; i < req->nvme_req->iovcnt; i++)
		SPDK_NOTICELOG("iov[%d] base %p len %lu\n",
				i, req->nvme_req->iov[i].iov_base,
				req->nvme_req->iov[i].iov_len);
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

static void
nvmf_pipe_pdu_ch_handle(struct spdk_nvmf_pipe_qpair *tqpair)
{
	struct nvme_tcp_pdu *pdu;

	pdu = tqpair->current_pdu;

	dump_pdu_ch(pdu);

	if (pdu->hdr.common.pdu_type == SPDK_NVME_TCP_PDU_TYPE_IC_REQ)
		goto skip_switch;

	switch (pdu->hdr.common.pdu_type) {
	case SPDK_NVME_TCP_PDU_TYPE_CAPSULE_CMD:
		nvmf_pipe_qpair_set_recv_state(tqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PSH);
		break;
	default:
		SPDK_ERRLOG("Unsupported PDU type %x\n", pdu->hdr.common.pdu_type);
		break;
	}

skip_switch:
	nvmf_pipe_qpair_set_recv_state(tqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PSH);
	return;
}

static void
nvmf_pipe_send_icresp_complete(void *cb_arg)
{
	struct spdk_nvmf_pipe_qpair *tqpair = cb_arg;

	tqpair->state = NVME_TCP_QPAIR_STATE_RUNNING;
}


static void
nvmf_pipe_icreq_handle(struct spdk_nvmf_pipe_transport *ttransport,
		      struct spdk_nvmf_pipe_qpair *tqpair,
		      struct nvme_tcp_pdu *pdu)
{
	struct spdk_nvme_tcp_ic_req *ic_req = &pdu->hdr.ic_req;
	struct nvme_tcp_pdu *rsp_pdu;
	struct spdk_nvme_tcp_ic_resp *ic_resp;
	uint32_t error_offset = 0;
	enum spdk_nvme_tcp_term_req_fes fes;

	/* Only PFV 0 is defined currently */
	if (ic_req->pfv != 0) {
		SPDK_ERRLOG("Expected ICReq PFV %u, got %u\n", 0u, ic_req->pfv);
		fes = SPDK_NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD;
		error_offset = offsetof(struct spdk_nvme_tcp_ic_req, pfv);
		goto end;
	}

	/* MAXR2T is 0's based */
	SPDK_DEBUGLOG(SPDK_LOG_NVMF_TCP, "maxr2t =%u\n", (ic_req->maxr2t + 1u));

	tqpair->host_hdgst_enable = ic_req->dgst.bits.hdgst_enable ? true : false;
	if (!tqpair->host_hdgst_enable) {
		tqpair->recv_buf_size -= SPDK_NVME_TCP_DIGEST_LEN * SPDK_NVMF_TCP_RECV_BUF_SIZE_FACTOR;
	}

	tqpair->host_ddgst_enable = ic_req->dgst.bits.ddgst_enable ? true : false;
	if (!tqpair->host_ddgst_enable) {
		tqpair->recv_buf_size -= SPDK_NVME_TCP_DIGEST_LEN * SPDK_NVMF_TCP_RECV_BUF_SIZE_FACTOR;
	}

#if 0
	/* Now that we know whether digests are enabled, properly size the receive buffer */
	if (spdk_sock_set_recvbuf(tqpair->sock, tqpair->recv_buf_size) < 0) {
		SPDK_WARNLOG("Unable to allocate enough memory for receive buffer on tqpair=%p with size=%d\n",
			     tqpair,
			     tqpair->recv_buf_size);
		/* Not fatal. */
	}
#endif

	tqpair->cpda = spdk_min(ic_req->hpda, SPDK_NVME_TCP_CPDA_MAX);
	SPDK_DEBUGLOG(SPDK_LOG_NVMF_TCP, "cpda of tqpair=(%p) is : %u\n", tqpair, tqpair->cpda);

	rsp_pdu = &tqpair->mgmt_pdu;

	ic_resp = &rsp_pdu->hdr.ic_resp;
	ic_resp->common.pdu_type = SPDK_NVME_TCP_PDU_TYPE_IC_RESP;
	ic_resp->common.hlen = ic_resp->common.plen =  sizeof(*ic_resp);
	ic_resp->pfv = 0;
	ic_resp->cpda = tqpair->cpda;
	ic_resp->maxh2cdata = ttransport->transport.opts.max_io_size;
	ic_resp->dgst.bits.hdgst_enable = tqpair->host_hdgst_enable ? 1 : 0;
	ic_resp->dgst.bits.ddgst_enable = tqpair->host_ddgst_enable ? 1 : 0;

	SPDK_DEBUGLOG(SPDK_LOG_NVMF_TCP, "host_hdgst_enable: %u\n", tqpair->host_hdgst_enable);
	SPDK_DEBUGLOG(SPDK_LOG_NVMF_TCP, "host_ddgst_enable: %u\n", tqpair->host_ddgst_enable);

	tqpair->state = NVME_TCP_QPAIR_STATE_INITIALIZING;
	nvmf_pipe_qpair_write_pdu(tqpair, rsp_pdu, nvmf_pipe_send_icresp_complete, tqpair);
	nvmf_pipe_qpair_set_recv_state(tqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY);
	return;
end:
	//nvmf_tcp_send_c2h_term_req(tqpair, pdu, fes, error_offset);
	SPDK_ERRLOG("|%s (%s:%d) unhandled\n", __func__, __FILE__, __LINE__);
	assert(0);
}


static void
nvmf_pipe_pdu_psh_handle(struct spdk_nvmf_pipe_qpair *tqpair,
			struct spdk_nvmf_pipe_transport *ttransport)
{
	struct nvme_tcp_pdu *pdu;

	pdu = tqpair->current_pdu;

	switch (pdu->hdr.common.pdu_type) {
	case SPDK_NVME_TCP_PDU_TYPE_IC_REQ:
		nvmf_pipe_icreq_handle(ttransport, tqpair, pdu);
		break;
	case SPDK_NVME_TCP_PDU_TYPE_CAPSULE_CMD:
		nvmf_pipe_qpair_set_recv_state(tqpair, NVME_TCP_PDU_RECV_STATE_AWAIT_REQ);
		break;
	default:
		SPDK_ERRLOG("Unsupported PDU type %x\n", pdu->hdr.common.pdu_type);
		assert(0);
		break;
	}
}

static void
nvmf_pipe_capsule_cmd_hdr_handle(struct spdk_nvmf_pipe_transport *ttransport,
				struct spdk_nvmf_pipe_qpair *tqpair,
				struct nvme_tcp_pdu *pdu)
{
	struct spdk_nvmf_pipe_req *pipe_req;

	pipe_req = nvmf_pipe_req_get(tqpair);

	if (!pipe_req) {
		SPDK_ERRLOG("Failed to get new pipe request on %p\n", tqpair);
		assert(0);
		return;
	}

	pdu->nvmf_req = pipe_req;
	assert(pipe_req->state == TCP_REQUEST_STATE_NEW);
	nvmf_pipe_req_process(ttransport, pipe_req);
}

static int
nvmf_pipe_nvme_req_process(struct spdk_nvmf_pipe_qpair *tqpair,
		struct global_queue_req *global_req)
{
	int rc = 0;
	struct nvme_tcp_pdu *pdu;
	enum nvme_tcp_pdu_recv_state prev_state;
	struct spdk_nvmf_pipe_transport *ttransport = SPDK_CONTAINEROF(tqpair->qpair.transport,
			struct spdk_nvmf_pipe_transport, transport);

	//dump_global_req(global_req);

	do {
		prev_state = tqpair->recv_state;
		SPDK_NOTICELOG("tqpair(%p) recv pdu %p global_req %p entering state %d\n",
				tqpair, tqpair->current_pdu, global_req, prev_state);
		dump_global_req(global_req);

		switch (tqpair->recv_state) {
		case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_READY:
			tqpair->current_pdu = global_req->pdu;
			pdu = tqpair->current_pdu;
			// fall through
		case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_CH:

			nvmf_pipe_pdu_ch_handle(tqpair);
			break;
		/* Wait for the pdu specific header  */
		case NVME_TCP_PDU_RECV_STATE_AWAIT_PDU_PSH:
			nvmf_pipe_pdu_psh_handle(tqpair, ttransport);
			break;
		/* Wait for the req slot */
		case NVME_TCP_PDU_RECV_STATE_AWAIT_REQ:
			nvmf_pipe_capsule_cmd_hdr_handle(ttransport, tqpair, pdu);
			break;
		default:
			assert(0);
			SPDK_ERRLOG("%s (%s:%d) unknown state %d\n",
					__func__, __FILE__, __LINE__, tqpair->recv_state);
			break;
		}
	} while (tqpair->recv_state != prev_state);

	return rc;
}

static int
nvmf_pipe_poll_group_add(struct spdk_nvmf_transport_poll_group *group,
			struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_pipe_poll_group	*tgroup;
	struct spdk_nvmf_pipe_qpair	*tqpair;
	int				rc;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);
	assert(0);

	tgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_pipe_poll_group, group);
	tqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_pipe_qpair, qpair);

	rc = nvmf_pipe_qpair_init(&tqpair->qpair);
	if (rc < 0) {
		SPDK_ERRLOG("Cannot init tqpair=%p\n", tqpair);
		return -1;
	}

	rc = nvmf_pipe_qpair_init_mem_resource(tqpair);
	if (rc < 0) {
		SPDK_ERRLOG("Cannot init memory resource info for tqpair=%p\n", tqpair);
		return -1;
	}

	tqpair->group = tgroup;
	tqpair->state = NVME_TCP_QPAIR_STATE_INVALID;
	TAILQ_INSERT_TAIL(&tgroup->qpairs, tqpair, link);

	return 0;
}

static int
nvmf_pipe_poll_group_remove(struct spdk_nvmf_transport_poll_group *group,
			   struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_pipe_poll_group	*tgroup;
	struct spdk_nvmf_pipe_qpair		*tqpair;
	int				rc;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	tgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_pipe_poll_group, group);
	tqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_pipe_qpair, qpair);

	assert(tqpair->group == tgroup);

	SPDK_DEBUGLOG(SPDK_LOG_NVMF_TCP, "remove tqpair=%p from the tgroup=%p\n", tqpair, tgroup);
	if (tqpair->recv_state == NVME_TCP_PDU_RECV_STATE_AWAIT_REQ) {
		TAILQ_REMOVE(&tgroup->await_req, tqpair, link);
	} else {
		TAILQ_REMOVE(&tgroup->qpairs, tqpair, link);
	}


	return rc;
}

static int
nvmf_pipe_req_complete(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_pipe_transport *ttransport;
	struct spdk_nvmf_pipe_req *pipe_req;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	ttransport = SPDK_CONTAINEROF(req->qpair->transport, struct spdk_nvmf_pipe_transport, transport);
	pipe_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_pipe_req, req);

	nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_EXECUTED);
	nvmf_pipe_req_process(ttransport, pipe_req);

	return 0;
}

static void
nvmf_pipe_close_qpair(struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_pipe_qpair *tqpair;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	SPDK_DEBUGLOG(SPDK_LOG_NVMF_PIPE, "Qpair: %p\n", qpair);

	tqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_pipe_qpair, qpair);
	tqpair->state = NVME_TCP_QPAIR_STATE_EXITED;
	nvmf_pipe_qpair_destroy(tqpair);
}

static int
nvmf_pipe_poll_group_poll(struct spdk_nvmf_transport_poll_group *group)
{
	struct spdk_nvmf_pipe_poll_group *tgroup;
	int rc = 0;
	struct spdk_nvmf_request *req, *req_tmp;
	struct spdk_nvmf_pipe_req *pipe_req;
	struct spdk_nvmf_pipe_qpair *tqpair, *tqpair_tmp;
	struct spdk_nvmf_pipe_transport *ttransport = SPDK_CONTAINEROF(group->transport,
			struct spdk_nvmf_pipe_transport, transport);

	// XXX anything needed here?
	//SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	tgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_pipe_poll_group, group);

	if (spdk_unlikely(TAILQ_EMPTY(&tgroup->qpairs) && TAILQ_EMPTY(&tgroup->await_req))) {
		return 0;
	}

	// FIXME this should be converted into a callback style
	TAILQ_FOREACH_SAFE(tqpair, &tgroup->qpairs, link, tqpair_tmp) {
		nvmf_pipe_gq_process(tqpair);
	}

	STAILQ_FOREACH_SAFE(req, &group->pending_buf_queue, buf_link, req_tmp) {
		pipe_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_pipe_req, req);
		if (nvmf_pipe_req_process(ttransport, pipe_req) == false) {
			break;
		}
	}

	TAILQ_FOREACH_SAFE(tqpair, &tgroup->await_req, link, tqpair_tmp) {
		nvmf_pipe_gq_process(tqpair);
	}
	return rc;
}

static int
nvmf_pipe_qpair_get_trid(struct spdk_nvmf_qpair *qpair,
			struct spdk_nvme_transport_id *trid, bool peer)
{
	struct spdk_nvmf_pipe_qpair     *tqpair;
	uint16_t			port;

	tqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_pipe_qpair, qpair);
	spdk_nvme_trid_populate_transport(trid, SPDK_NVME_TRANSPORT_PIPE);

	if (peer) {
		snprintf(trid->traddr, sizeof(trid->traddr), "%s", tqpair->initiator_addr);
		port = tqpair->initiator_port;
	} else {
		snprintf(trid->traddr, sizeof(trid->traddr), "%s", tqpair->target_addr);
		port = tqpair->target_port;
	}

	snprintf(trid->trsvcid, sizeof(trid->trsvcid), "%d", port);
	return 0;
}

static int
nvmf_pipe_qpair_get_local_trid(struct spdk_nvmf_qpair *qpair,
			      struct spdk_nvme_transport_id *trid)
{
	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	return nvmf_pipe_qpair_get_trid(qpair, trid, 0);
}

static int
nvmf_pipe_qpair_get_peer_trid(struct spdk_nvmf_qpair *qpair,
			     struct spdk_nvme_transport_id *trid)
{
	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	return nvmf_pipe_qpair_get_trid(qpair, trid, 1);
}

static int
nvmf_pipe_qpair_get_listen_trid(struct spdk_nvmf_qpair *qpair,
			       struct spdk_nvme_transport_id *trid)
{
	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	return nvmf_pipe_qpair_get_trid(qpair, trid, 0);
}

static void
nvmf_pipe_qpair_abort_request(struct spdk_nvmf_qpair *qpair,
			     struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_pipe_qpair *tqpair;
	struct spdk_nvmf_pipe_transport *ttransport;
	struct spdk_nvmf_transport *transport;
	uint16_t cid;
	uint32_t i;
	struct spdk_nvmf_pipe_req *pipe_req_to_abort = NULL;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	tqpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_pipe_qpair, qpair);
	ttransport = SPDK_CONTAINEROF(qpair->transport, struct spdk_nvmf_pipe_transport, transport);
	transport = &ttransport->transport;
}

#define SPDK_NVMF_TCP_DEFAULT_MAX_QUEUE_DEPTH 128
#define SPDK_NVMF_TCP_DEFAULT_AQ_DEPTH 128
#define SPDK_NVMF_TCP_DEFAULT_MAX_QPAIRS_PER_CTRLR 128
#define SPDK_NVMF_TCP_DEFAULT_IN_CAPSULE_DATA_SIZE 4096
#define SPDK_NVMF_TCP_DEFAULT_MAX_IO_SIZE 131072
#define SPDK_NVMF_TCP_DEFAULT_IO_UNIT_SIZE 131072
#define SPDK_NVMF_TCP_DEFAULT_NUM_SHARED_BUFFERS 511
#define SPDK_NVMF_TCP_DEFAULT_BUFFER_CACHE_SIZE 32
#define SPDK_NVMF_TCP_DEFAULT_SUCCESS_OPTIMIZATION true
#define SPDK_NVMF_TCP_DEFAULT_DIF_INSERT_OR_STRIP false
#define SPDK_NVMF_TCP_DEFAULT_SOCK_PRIORITY 0
#define SPDK_NVMF_TCP_DEFAULT_ABORT_TIMEOUT_SEC 1

static void
nvmf_pipe_opts_init(struct spdk_nvmf_transport_opts *opts)
{
	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	opts->max_queue_depth =		SPDK_NVMF_TCP_DEFAULT_MAX_QUEUE_DEPTH;
	opts->max_qpairs_per_ctrlr =	SPDK_NVMF_TCP_DEFAULT_MAX_QPAIRS_PER_CTRLR;
	opts->in_capsule_data_size =	SPDK_NVMF_TCP_DEFAULT_IN_CAPSULE_DATA_SIZE;
	opts->max_io_size =		SPDK_NVMF_TCP_DEFAULT_MAX_IO_SIZE;
	opts->io_unit_size =		SPDK_NVMF_TCP_DEFAULT_IO_UNIT_SIZE;
	opts->max_aq_depth =		SPDK_NVMF_TCP_DEFAULT_AQ_DEPTH;
	opts->num_shared_buffers =	SPDK_NVMF_TCP_DEFAULT_NUM_SHARED_BUFFERS;
	opts->buf_cache_size =		SPDK_NVMF_TCP_DEFAULT_BUFFER_CACHE_SIZE;
	opts->c2h_success =		SPDK_NVMF_TCP_DEFAULT_SUCCESS_OPTIMIZATION;
	opts->dif_insert_or_strip =	SPDK_NVMF_TCP_DEFAULT_DIF_INSERT_OR_STRIP;
	opts->sock_priority =		SPDK_NVMF_TCP_DEFAULT_SOCK_PRIORITY;
	opts->abort_timeout_sec =	SPDK_NVMF_TCP_DEFAULT_ABORT_TIMEOUT_SEC;
}

const struct spdk_nvmf_transport_ops spdk_nvmf_transport_pipe = {
	.name = "PIPE",
	.type = SPDK_NVME_TRANSPORT_PIPE,
	.opts_init = nvmf_pipe_opts_init,
	.create = nvmf_pipe_create,
	.destroy = nvmf_pipe_destroy,

	.listen = nvmf_pipe_listen,
	.stop_listen = nvmf_pipe_stop_listen,
	.accept = nvmf_pipe_accept,

	.listener_discover = nvmf_pipe_discover,

	.poll_group_create = nvmf_pipe_poll_group_create,
	.get_optimal_poll_group = nvmf_pipe_get_optimal_poll_group,
	.poll_group_destroy = nvmf_pipe_poll_group_destroy,
	.poll_group_add = nvmf_pipe_poll_group_add,
	.poll_group_remove = nvmf_pipe_poll_group_remove,
	.poll_group_poll = nvmf_pipe_poll_group_poll,

	.req_free = nvmf_pipe_req_free,
	.req_complete = nvmf_pipe_req_complete,

	.qpair_fini = nvmf_pipe_close_qpair,
	.qpair_get_local_trid = nvmf_pipe_qpair_get_local_trid,
	.qpair_get_peer_trid = nvmf_pipe_qpair_get_peer_trid,
	.qpair_get_listen_trid = nvmf_pipe_qpair_get_listen_trid,
	.qpair_abort_request = nvmf_pipe_qpair_abort_request,
};

SPDK_NVMF_TRANSPORT_REGISTER(pipe, &spdk_nvmf_transport_pipe);
SPDK_LOG_REGISTER_COMPONENT("nvmf_pipe", SPDK_LOG_NVMF_PIPE)
