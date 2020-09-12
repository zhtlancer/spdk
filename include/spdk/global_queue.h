#ifndef SPDK_INTERNAL_GLOBAL_PIPE_H
#define SPDK_INTERNAL_GLOBAL_PIPE_H

#include "spdk/nvme_internal.h"
#include "spdk/nvmf_transport.h"
#include "spdk_internal/nvme_tcp.h"

/* NVMe TCP qpair extensions for spdk_nvme_qpair */
struct nvme_pipe_qpair {
	struct spdk_nvme_qpair			qpair;
	struct spdk_sock			*sock;

	struct global_queue			*pipe;

	TAILQ_HEAD(, nvme_pipe_req)		free_reqs;
	TAILQ_HEAD(, nvme_pipe_req)		outstanding_reqs;

	TAILQ_HEAD(, nvme_tcp_pdu)		send_queue;
	struct nvme_tcp_pdu			*current_pdu;
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

/* spdk nvmf related structure */
enum spdk_nvmf_pipe_req_state {

	/* The request is not currently in use */
	PIPE_REQUEST_STATE_FREE = 0,

	/* 1 Initial state when request first received */
	PIPE_REQUEST_STATE_NEW,

	/* 2 The request is queued until a data buffer is available. */
	PIPE_REQUEST_STATE_NEED_BUFFER,

	/* 3 The request is currently transferring data from the host to the controller. */
	PIPE_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER,

	/* 4 The request is waiting for the R2T send acknowledgement. */
	PIPE_REQUEST_STATE_AWAITING_R2T_ACK,

	/* 5 The request is ready to execute at the block device */
	PIPE_REQUEST_STATE_READY_TO_EXECUTE,

	/* 6 The request is currently executing at the block device */
	PIPE_REQUEST_STATE_EXECUTING,

	/* 7 The request finished executing at the block device */
	PIPE_REQUEST_STATE_EXECUTED,

	/* 8 The request is ready to send a completion */
	PIPE_REQUEST_STATE_READY_TO_COMPLETE,

	/* 9 The request is currently transferring final pdus from the controller to the host. */
	PIPE_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST,

	/* 10 The request completed and can be marked free. */
	PIPE_REQUEST_STATE_COMPLETED,

	/* 11 Terminator */
	PIPE_REQUEST_NUM_STATES,
};

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

enum global_req_state {
	GLOBAL_REQ_STATE_FREE	= 0x0,
	GLOBAL_REQ_STATE_NEW	= 0x1,

	GLOBAL_REQ_STATE_DONE	= 0xF,
	GLOBAL_REQ_STATE_FAIL	= 0x10,
};

struct global_queue_req {
	struct nvme_pipe_req			*nvme_req;
	struct spdk_nvmf_pipe_req		*nvmf_req;
	struct nvme_tcp_pdu			*pdu;
	enum global_req_state			state;
	STAILQ_ENTRY(global_queue_req)		link;
};

struct global_queue {
	struct global_queue_req		*h2c_reqs;
	STAILQ_HEAD(, global_queue_req)	h2c_queue;
	STAILQ_HEAD(, global_queue_req)	h2c_queue_free;
	STAILQ_HEAD(, global_queue_req)	h2c_queue_running;

	struct global_queue_req		*c2h_reqs;
	STAILQ_HEAD(, global_queue_req)	c2h_queue;
	STAILQ_HEAD(, global_queue_req)	c2h_queue_free;
	STAILQ_HEAD(, global_queue_req)	c2h_queue_running;
};

//struct global_queue *spdk_pipe_get_global(void);

inline bool spdk_pipe_h2c_queue_empty(struct global_queue *queue) {
	return STAILQ_EMPTY(&queue->h2c_queue);
}

inline bool spdk_pipe_c2h_queue_empty(struct global_queue *queue) {
	return STAILQ_EMPTY(&queue->c2h_queue);
}

struct global_queue_req *spdk_pipe_get_free_h2c_req(struct global_queue *queue);
void spdk_pipe_put_h2c_req(struct global_queue *queue, struct global_queue_req *req);
struct global_queue_req *spdk_pipe_get_recv_h2c_req(struct global_queue *queue);
int spdk_pipe_submit_h2c_req(struct global_queue *queue, struct global_queue_req *req);

struct global_queue_req *spdk_pipe_get_free_c2h_req(struct global_queue *queue);
void spdk_pipe_put_c2h_req(struct global_queue *queue, struct global_queue_req *req);
struct global_queue_req *spdk_pipe_get_recv_c2h_req(struct global_queue *queue);
int spdk_pipe_submit_c2h_req(struct global_queue *queue, struct global_queue_req *req);

int spdk_pipe_listen();
struct global_queue *spdk_pipe_connect();
struct global_queue *spdk_pipe_accept();
bool spdk_pipe_pending_connection();

#endif /* SPDK_INTERNAL_GLOBAL_PIPE_H */
