/*
	Copyright (c) 2009-2012 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of LibCat nor the names of its contributors may be used
	  to endorse or promote products derived from this software without
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

#ifndef CAT_SPHYNX_CLIENT_HPP
#define CAT_SPHYNX_CLIENT_HPP

#include <cat/sphynx/Transport.hpp>
#include <cat/crypt/tunnel/KeyAgreementInitiator.hpp>
#include <cat/threads/Thread.hpp>
#include <cat/threads/WaitableFlag.hpp>

namespace cat {


namespace sphynx {


// Base class for a Sphynx client
class CAT_EXPORT Client : public UDPEndpoint, public Transport
{
	static const int MIN_KERNEL_RECV_BUFFER = 1000000;
	static const int DEFAULT_KERNEL_RECV_BUFFER = 8000000;
	static const int MAX_KERNEL_RECV_BUFFER = 32000000;

	char _session_key[SESSION_KEY_BYTES];

	KeyAgreementInitiator _key_agreement_initiator;
	TunnelPublicKey _server_public_key;
	u8 _cached_challenge[CHALLENGE_BYTES];

	WaitableFlag _kill_flag;

#if defined(CAT_SPHYNX_ROAMING_IP)
	u16 _my_id;
#endif

	u32 _last_send_msec;
	NetAddr _server_addr;
	bool _connected;
	AuthenticatedEncryption _auth_enc;
	u32 _worker_id;

	// Last time a packet was received from the server -- for disconnect timeouts
	u32 _last_recv_tsc;

	u32 _first_hello_post;
	u32 _last_hello_post;
	s32 _hello_post_interval;

	u32 _mtu_discovery_time;
	int _mtu_discovery_attempts;
	u32 _next_sync_time;
	u32 _sync_attempts;

	Clock *_clock;
	struct TimesPingSample {
		u32 rtt;
		s32 delta;
	} _ts_samples[TS_MAX_SAMPLES];
	u32 _ts_sample_count, _ts_next_index;

	u32 _ts_delta; // Milliseconds clock difference between server and client: server_time = client_time + _ts_delta

	void UpdateTimeSynch(u32 rtt, s32 delta);

	bool WriteHello();
	bool WriteTimePing();

	// Return false to remove resolve from cache
	bool OnDNSResolve(const char *hostname, const NetAddr *array, int array_length);

	virtual s32 WriteDatagrams(const BatchSet &buffers, u32 count);
	virtual void OnInternal(u32 recv_time, BufferStream msg, u32 bytes);
	virtual void OnDisconnectComplete();

	void ConnectFail(SphynxError err);

	bool InitialConnect(TunnelTLS *tls, TunnelPublicKey &public_key, const char *session_key);
	bool FinalConnect(const NetAddr &addr);

	virtual void OnRecvRouting(const BatchSet &buffers);
	virtual void OnRecv(ThreadLocalStorage &tls, const BatchSet &buffers);
	virtual void OnTick(ThreadLocalStorage &tls, u32 now);

public:
	Client();
	CAT_INLINE virtual ~Client() {}

	CAT_INLINE const char *GetRefObjectName() { return "Client"; }

	// Once you call Connect(), the object may be deleted at any time.  If you want to keep a reference to it, AddRef() before calling
	bool Connect(const char *hostname, Port port, TunnelPublicKey &public_key, const char *session_key, ThreadLocalStorage *tls = 0);
	bool Connect(const NetAddr &addr, TunnelPublicKey &public_key, const char *session_key, ThreadLocalStorage *tls = 0);

#if defined(CAT_SPHYNX_ROAMING_IP)
	// After connection, will return the user id of the client
	CAT_INLINE u16 getMyId() { return _my_id; }
#endif

	// Current local time
	CAT_INLINE u32 getLocalTime() { return _clock->msec(); }

	// Convert from local time to server time
	CAT_INLINE u32 toServerTime(u32 local_time) { return local_time + _ts_delta; }

	// Convert from server time to local time
	CAT_INLINE u32 fromServerTime(u32 server_time) { return server_time - _ts_delta; }

	// Current server time
	CAT_INLINE u32 getServerTime() { return toServerTime(getLocalTime()); }

	// Compress timestamp on client for delivery to server; byte order must be fixed before writing to message
	CAT_INLINE u16 encodeClientTimestamp(u32 local_time) { return (u16)toServerTime(local_time); }

	// Decompress a timestamp on client from server
	CAT_INLINE u32 decodeServerTimestamp(u32 local_time, u16 timestamp) { return fromServerTime(BiasedReconstructCounter<16>(toServerTime(local_time), TS_COMPRESS_FUTURE_TOLERANCE, timestamp)); }

protected:
	virtual bool OnInitialize();
	//virtual void OnDestroy();
	//virtual bool OnFinalize();

	CAT_INLINE bool IsConnected() { return _connected; }
	CAT_INLINE u32 GetWorkerID() { return _worker_id; }

	virtual void OnConnectFail(sphynx::SphynxError err) = 0;
	virtual void OnConnect() = 0;
	virtual void OnMessages(IncomingMessage msgs[], u32 count) = 0;
	virtual void OnCycle(u32 now) = 0;
	virtual void OnDisconnectReason(u8 reason) = 0; // Called to help explain why a disconnect is happening
};


} // namespace sphynx


} // namespace cat

#endif // CAT_SPHYNX_CLIENT_HPP
