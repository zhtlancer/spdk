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

struct spdk_pipe {
	uint8_t	*buf;
	uint32_t sz;

	uint32_t write;
	uint32_t read;
};

#define SPDK_PIPE_BUF_SZ	(32*1024*1024)

struct spdk_pipe *g_spdk_pipe = NULL;
void *g_spdk_pipe_buf = NULL;

struct spdk_pipe *
spdk_pipe_get_global()
{
	if (g_spdk_pipe == NULL) {
		g_spdk_pipe_buf = spdk_zmalloc(SPDK_PIPE_BUF_SZ,
				0x1000, NULL,
				SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
		if (g_spdk_pipe_buf == NULL) {
			SPDK_ERRLOG("Failed to create buffer for spdk_pipe\n");
			return NULL;
		}
		g_spdk_pipe = spdk_pipe_create(g_spdk_pipe_buf, SPDK_PIPE_BUF_SZ);
		if (g_spdk_pipe == NULL) {
			SPDK_ERRLOG("Failed to create buffer for spdk_pipe\n");
			spdk_free(g_spdk_pipe_buf);
			return NULL;
		}
	}

	return g_spdk_pipe;
}

