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

#include "spdk_internal/assert.h"
#include "spdk_internal/log.h"
#include "spdk_internal/nvme_tcp.h"

#include "nvmf_internal.h"

#define NVMF_TCP_MAX_ACCEPT_SOCK_ONE_TIME 16
#define SPDK_NVMF_TCP_DEFAULT_MAX_SOCK_PRIORITY 6

const struct spdk_nvmf_transport_ops spdk_nvmf_transport_pipe;

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

struct spdk_nvmf_pipe_qpair {
	struct spdk_nvmf_qpair			qpair;
	struct spdk_nvmf_pipe_poll_group	*group;
	struct spdk_nvmf_pipe_port		*port;

	enum nvme_tcp_pdu_recv_state		recv_state;
	enum nvme_tcp_qpair_state		state;

	/* PDU being actively received */
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

	struct spdk_pipe			*pipe;
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

	// TODO: initialize spdk_pipe
	//ttransport->pipe = spdk_pipe_create();

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
		//nvmf_tcp_destroy(&ttransport->transport);
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
nvmf_pipe_accept(struct spdk_nvmf_transport *transport)
{
	struct spdk_nvmf_pipe_transport *ttransport;
	uint32_t count = 0;

	// XXX anything needed here?
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	ttransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_pipe_transport, transport);

	// FIXME: this seems to be where polling happens, spdk_pipe_reader

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

		switch (pipe_req->state) {
		case PIPE_REQUEST_STATE_FREE:
			break;
		case PIPE_REQUEST_STATE_NEW:
			// 1. copy the cmd from recv buffer

			pipe_req->req.xfer = spdk_nvmf_req_get_xfer(&pipe_req->req);

			if (pipe_req->req.xfer == SPDK_NVME_DATA_NONE) {
				nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_READY_TO_EXECUTE);
				break;
			}
			// TODO: copy data
			nvmf_pipe_req_set_state(pipe_req, PIPE_REQUEST_STATE_NEED_BUFFER);
			STAILQ_INSERT_TAIL(&group->pending_buf_queue, &pipe_req->req, buf_link);
			break;
		case PIPE_REQUEST_STATE_NEED_BUFFER:
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
			// TODO: need transfer C2H code
			break;
		case PIPE_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST:
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
	SPDK_ERRLOG("%s (%s:%d) called\n", __func__, __FILE__, __LINE__);

	tgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_pipe_poll_group, group);

	if (spdk_unlikely(TAILQ_EMPTY(&tgroup->qpairs) && TAILQ_EMPTY(&tgroup->await_req))) {
		return 0;
	}

	STAILQ_FOREACH_SAFE(req, &group->pending_buf_queue, buf_link, req_tmp) {
		pipe_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_pipe_req, req);
		if (nvmf_pipe_req_process(ttransport, pipe_req) == false) {
			break;
		}
	}

	TAILQ_FOREACH_SAFE(tqpair, &tgroup->await_req, link, tqpair_tmp) {
		//nvmf_tcp_sock_process(tqpair);
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
