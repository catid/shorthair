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

#ifndef CAT_SHORTHAIR_API_H
#define CAT_SHORTHAIR_API_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*SHCall)(char *data, int len);

typedef void *SHCtx;

// Create/destroy Shorthair context
extern SHCtx *SHCreate(char *key, int key_len, bool initiator, int max_data_len, SHCall on_data, SHCall on_oob, SHCall sendr);
extern void SHDestroy(SHCtx *ctx);

// Call this function somewhat often (10-20ms interval)
extern void SHTick(SHCtx *ctx);

// Call this function when UDP data is received
extern void SHRecv(SHCtx *ctx, void *data, int len);

// Call this function to send protected data
extern void SHSend(SHCtx *ctx, const void *data, int len);

// Call this function to send unprotected data
extern void SHSendOOB(SHCtx *ctx, const void *data, int len);

#ifdef __cplusplus
} // extern C
#endif

#endif // CAT_SHORTHAIR_API_H

