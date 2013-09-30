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

/*
 * SHCreate(key, key_len, initiator, max_data_len, on_data, on_oob, sendr)
 *
 * Create a Shorthair context object.
 *
 * Security parameters:
 *
 * key: 32-byte encryption key
 * key_len: = 32
 * initiator: Set to true if this is a client, or false if it is a server
 *
 * Networking parameters:
 *
 * max_data_len: Largest number of bytes that will be passed to SHSend()
 * on_data: Callback for when data is decoded by Shorthair and passed to you
 * on_oob: Callback for when your OOB data types arrive
 * sendr: Callback for when Shorthair wants to send a packet
 *
 * Shorthair only performs math, so it does not have a UDP socket wrapper
 * internally.  You will need to implement the callback interface to allow
 * the library to transmit and receive data.
 *
 * Returns a Shorthair context object to pass to the other API functions.
 */
extern SHCtx *SHCreate(char *key, int key_len, bool initiator, int max_data_len, SHCall on_data, SHCall on_oob, SHCall sendr);

/*
 * SHDestroy(ctx)
 *
 * Destroy a Shorthair context object.
 */
extern void SHDestroy(SHCtx *ctx);

/*
 * SHTick(ctx)
 *
 * Tick the Shorthair object.
 *
 * Call this function somewhat often (10-20ms interval).  The library uses this
 * function to transmit the redundant data at a steady rate and will call sendr
 * with each data packet to send.
 */
extern void SHTick(SHCtx *ctx);

/*
 * SHRecv(ctx, data, len)
 *
 * Pass received encoded data into Shorthair.
 *
 * When UDP data is received on the socket, it should be passed into this
 * function to be decoded.  Recovered data will be passed to on_data, and
 * OOB data will be passed to on_oob.
 */
extern void SHRecv(SHCtx *ctx, void *data, int len);

/*
 * SHSend(ctx, data, len)
 *
 * Submit data to be protected by Shorthair.  It will call sendr to transmit
 * the encoded data packets.
 */
extern void SHSend(SHCtx *ctx, const void *data, int len);

/*
 * SHSendOOB(ctx, data, len)
 *
 * Submit data out-of-band.  This data is not protected by Shorthair but is
 * still encrypted.  This is useful for time synchronization and other messages
 * that are related to measuring actual round-trip-time without any error
 * correction.
 *
 * The only reason I can think of for using this off-hand would be during
 * time synchronization for an online game that sends timestamps on data to
 * know when an event occurred on the originating computer.
 *
 * If you need to know the round-trip time, this is already provided in the
 * statistics in the form of estimated one-way delay.
 */
extern void SHSendOOB(SHCtx *ctx, const void *data, int len);

struct SHStats {
	float loss;		// Probability [0..1] of a packet loss event without FEC.
	int delay;		// Average one-way packet transmission delay.
};

/*
 * SHGetStats(ctx, stats)
 *
 * Request filling an SHStats object with the latest statistics.
 */
extern void SHGetStats(SHCtx *ctx, SHStats *stats);

#ifdef __cplusplus
} // extern C
#endif

#endif // CAT_SHORTHAIR_API_H

