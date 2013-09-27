/*
	Copyright (c) 2013 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of Shorthair nor the names of its contributors may be
	  used to endorse or promote products derived from this software without
	  specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

#include "ShorthairAPI.h"
#include "Shorthair.hpp"
using namespace cat;
using namespace shorthair;

struct SHContext : IShorthair {
	Shorthair sh;

	SHCall on_data, on_oob, sendr;

	CAT_INLINE virtual ~SHContext() {
	}

	CAT_INLINE virtual void OnPacket(u8 *packet, int bytes) {
		on_data((char*)packet, bytes);
	}

	CAT_INLINE virtual void OnOOB(u8 *packet, int bytes) {
		on_oob((char*)packet, bytes);
	}

	CAT_INLINE virtual void SendData(u8 *packet, int bytes) {
		sendr((char*)packet, bytes);
	}
};

// Create/destroy Shorthair context
extern "C" SHCtx *SHCreate(char *key, int key_len, bool initiator, int max_data_len, SHCall on_data, SHCall on_oob, SHCall sendr) {
	CAT_ENFORCE(key && key_len == SKEY_BYTES && max_data_len > 0 && on_data && on_oob && sendr);

	SHContext *ctx = new SHContext;

	Settings settings;
	settings.initiator = initiator;
	settings.target_loss = 0.001;
	settings.min_loss = 0.03;
	settings.max_loss = 0.5;
	settings.min_delay = 100;
	settings.max_delay = 2000;
	settings.max_data_size = max_data_len;
	settings.interface = ctx;

	ctx->on_data = on_data;
	ctx->on_oob = on_oob;
	ctx->sendr = sendr;

	if (!ctx->sh.Initialize((u8*)key, settings)) {
		delete ctx;
		return 0;
	}

	return (SHCtx*)ctx;
}

extern "C" void SHDestroy(SHCtx *ctx) {
	if (ctx) {
		SHContext *shctx = (SHContext*)ctx;

		shctx->sh.Finalize();
	}
}

// Call this function somewhat often (10-20ms interval)
extern "C" void SHTick(SHCtx *ctx) {
	if (ctx) {
		SHContext *shctx = (SHContext*)ctx;

		shctx->sh.Tick();
	}
}

// Call this function when UDP data is received
extern "C" void SHRecv(SHCtx *ctx, void *data, int len) {
	if (ctx) {
		SHContext *shctx = (SHContext*)ctx;

		shctx->sh.Recv(data, len);
	}
}

// Call this function to send protected data
extern "C" void SHSend(SHCtx *ctx, const void *data, int len) {
	if (ctx) {
		SHContext *shctx = (SHContext*)ctx;

		shctx->sh.Send((const u8*)data, len);
	}
}

// Call this function to send unprotected data
extern "C" void SHSendOOB(SHCtx *ctx, const void *data, int len) {
	if (ctx) {
		SHContext *shctx = (SHContext*)ctx;

		shctx->sh.SendOOB((const u8*)data, len);
	}
}

