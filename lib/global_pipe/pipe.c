/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
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

#include "spdk/env.h"
#include "spdk/log.h"
#include "spdk/pipe.h"
#include "spdk/util.h"
#include "spdk/global_queue.h"

#define SPDK_PIPE_BUF_SZ	(256)

struct global_queue *g_global_queue = NULL;

static bool g_global_quque_pending_connection = false;
static pthread_mutex_t g_global_queue_lock;

static struct global_queue *
spdk_pipe_get_global()
{
	struct global_queue *gq;

	if (g_global_queue == NULL) {
		int i;

		g_global_queue = calloc(1, sizeof(struct global_queue));

		STAILQ_INIT(&g_global_queue->h2c_queue_free);
		STAILQ_INIT(&g_global_queue->h2c_queue);
		STAILQ_INIT(&g_global_queue->h2c_queue_running);
		STAILQ_INIT(&g_global_queue->c2h_queue_free);
		STAILQ_INIT(&g_global_queue->c2h_queue);
		STAILQ_INIT(&g_global_queue->c2h_queue_running);

		g_global_queue->h2c_reqs = calloc(SPDK_PIPE_BUF_SZ,
				sizeof(struct global_queue_req));
		if (g_global_queue->h2c_reqs == NULL) {
			return NULL;
		}

		for (i = 0; i < SPDK_PIPE_BUF_SZ; i++) {
			STAILQ_INSERT_TAIL(&g_global_queue->h2c_queue_free,
					&g_global_queue->h2c_reqs[i], link);
		}

		g_global_queue->c2h_reqs = calloc(SPDK_PIPE_BUF_SZ,
				sizeof(struct global_queue_req));
		if (g_global_queue->c2h_reqs == NULL) {
			return NULL;
		}
		for (i = 0; i < SPDK_PIPE_BUF_SZ; i++) {
			STAILQ_INSERT_TAIL(&g_global_queue->c2h_queue_free,
					&g_global_queue->c2h_reqs[i], link);
		}
	}

	return g_global_queue;
}

struct global_queue_req *
spdk_pipe_get_free_h2c_req(struct global_queue *queue)
{
	struct global_queue_req *req;

	while (STAILQ_EMPTY(&queue->h2c_queue_free));

	req = STAILQ_FIRST(&queue->h2c_queue_free);
	STAILQ_REMOVE(&queue->h2c_queue_free, req, global_queue_req, link);

	return req;
}

struct global_queue_req *
spdk_pipe_get_recv_h2c_req(struct global_queue *queue)
{
	struct global_queue_req *req;

	while (STAILQ_EMPTY(&queue->h2c_queue));

	req = STAILQ_FIRST(&queue->h2c_queue);
	STAILQ_REMOVE(&queue->h2c_queue, req, global_queue_req, link);
	STAILQ_INSERT_TAIL(&queue->h2c_queue_running, req, link);

	return req;
}

int spdk_pipe_submit_h2c_req(struct global_queue *queue, struct global_queue_req *req)
{
	SPDK_NOTICELOG("Sending out h2c global_req %p\n", req);
	STAILQ_INSERT_TAIL(&queue->h2c_queue, req, link);
	return 0;
}

struct global_queue_req *
spdk_pipe_get_free_c2h_req(struct global_queue *queue)
{
	struct global_queue_req *req;

	while (STAILQ_EMPTY(&queue->c2h_queue_free));

	req = STAILQ_FIRST(&queue->c2h_queue_free);
	STAILQ_REMOVE(&queue->c2h_queue_free, req, global_queue_req, link);

	return req;
}

struct global_queue_req *
spdk_pipe_get_recv_c2h_req(struct global_queue *queue)
{
	struct global_queue_req *req;

	while (STAILQ_EMPTY(&queue->c2h_queue));

	req = STAILQ_FIRST(&queue->c2h_queue);
	STAILQ_REMOVE(&queue->c2h_queue, req, global_queue_req, link);
	STAILQ_INSERT_TAIL(&queue->c2h_queue_running, req, link);

	return req;
}

int spdk_pipe_submit_c2h_req(struct global_queue *queue, struct global_queue_req *req)
{
	SPDK_NOTICELOG("Sending out c2h global_req %p\n", req);
	STAILQ_INSERT_TAIL(&queue->c2h_queue, req, link);
	return 0;
}


int spdk_pipe_listen()
{
	pthread_mutex_init(&g_global_queue_lock, NULL);

	return 0;
}

struct global_queue *spdk_pipe_connect()
{
	struct global_queue *gp;
	while (spdk_pipe_pending_connection())
		// spin on pending connection
		SPDK_NOTICELOG("| %s (%s:%d) wait for pending connection\n",
				__func__, __FILE__, __LINE__);
	pthread_mutex_lock(&g_global_queue_lock);

	gp = spdk_pipe_get_global();
	if (gp == NULL) {
		SPDK_ERRLOG("| %s (%s:%d) failed to get global queue\n",
				__func__, __FILE__, __LINE__);
		assert(0);
	}

	g_global_quque_pending_connection = true;
	pthread_mutex_unlock(&g_global_queue_lock);
	return gp;
}

struct global_queue *spdk_pipe_accept()
{
	struct global_queue *gp;
	if (!spdk_pipe_pending_connection()) {
		return NULL;
	}

	pthread_mutex_lock(&g_global_queue_lock);

	gp = spdk_pipe_get_global();

	if (gp == NULL) {
		SPDK_ERRLOG("| %s (%s:%d) failed to get global queue\n",
				__func__, __FILE__, __LINE__);
		assert(0);
	}

	// FIXME keep track of allocated global pipes?
	g_global_queue = NULL;

	g_global_quque_pending_connection = false;
	pthread_mutex_unlock(&g_global_queue_lock);

	return gp;
}
bool spdk_pipe_pending_connection()
{
	return g_global_quque_pending_connection;
}
