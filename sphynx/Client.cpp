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

#include <cat/sphynx/Client.hpp>
#include <cat/mem/AlignedAllocator.hpp>
#include <cat/io/Log.hpp>
#include <cat/net/DNSClient.hpp>
#include <cat/io/Settings.hpp>
#include <cat/parse/BufferStream.hpp>
#include <cat/time/Clock.hpp>
#include <cat/crypt/SecureEqual.hpp>
#include <cat/hash/Murmur.hpp>
#include <ext/lz4/lz4.h>
#include <fstream>
using namespace std;
using namespace cat;
using namespace sphynx;

static WorkerThreads *m_worker_threads = 0;
static Settings *m_settings = 0;
static DNSClient *m_dns_client = 0;
static UDPSendAllocator *m_udp_send_allocator = 0;
static TLSInstance<TunnelTLS> m_tunnel_tls;
static TLSInstance<TransportTLS> m_transport_tls;


//// Client

bool Client::OnInitialize()
{
	Use(_clock, m_worker_threads, m_settings, m_dns_client, m_udp_send_allocator);

	return m_worker_threads->InitializeTLS<TransportTLS>() && UDPEndpoint::OnInitialize();
}

void Client::OnDisconnectComplete()
{
	Destroy(CAT_REFOBJECT_TRACE);
}

void Client::OnRecvRouting(const BatchSet &buffers)
{
	u32 garbage_count = 0;

	// If worker id is not assigned yet,
	u32 worker_id = GetWorkerID();
	if (worker_id == INVALID_WORKER_ID)
	{
		// For each buffer in the set,
		for (BatchHead *node = buffers.head; node; node = node->batch_next)
			++garbage_count;

		ReleaseRecvBuffers(buffers, garbage_count);
		return;
	}

	BatchSet garbage, delivery;
	garbage.Clear();
	delivery.Clear();

	// For each buffer in the set,
	for (BatchHead *next, *node = buffers.head; node; node = next)
	{
		next = node->batch_next;
		RecvBuffer *buffer = static_cast<RecvBuffer*>( node );

		SetRemoteAddress(buffer);

		// If packet source is the server,
		if (_server_addr == buffer->addr || buffer->data_bytes == 0)
		{
			buffer->callback.SetMember<Client, &Client::OnRecv>(this);
			delivery.PushBack(buffer);
		}
		else
		{
			garbage.PushBack(buffer);
			++garbage_count;
		}
	}

	// If delivery set is not empty,
	if (delivery.head)
		m_worker_threads->DeliverBuffers(WQPRIO_HI, GetWorkerID(), delivery);

	// If free set is not empty,
	if (garbage_count > 0)
		ReleaseRecvBuffers(garbage, garbage_count);
}

void Client::OnRecv(ThreadLocalStorage &tls, const BatchSet &buffers)
{
	u8 compress_buffer[IOTHREADS_BUFFER_READ_BYTES];
	u32 buffer_count = 0;
	BatchHead *node = buffers.head;

	if (!_connected)
	{
		for (; node; node = node->batch_next)
		{
			++buffer_count;
			RecvBuffer *buffer = static_cast<RecvBuffer*>( node );
			u32 bytes = buffer->data_bytes;
			u8 *data = GetTrailingBytes(buffer);

			if (bytes == 0)
			{
				ConnectFail(ERR_CLIENT_BROKEN_PIPE);
			}
			else if (bytes == S2C_COOKIE_LEN && data[0] == S2C_COOKIE)
			{
				u8 *pkt = m_udp_send_allocator->Acquire(C2S_CHALLENGE_LEN);
				if (!pkt)
				{
					ConnectFail(ERR_CLIENT_OUT_OF_MEMORY);
					continue;
				}

				// Start ignoring ICMP unreachable messages now that we've seen a pkt from the server
				if (!IgnoreUnreachable())
				{
					CAT_WARN("Client") << "ICMP ignore unreachable failed";
				}

				// Construct challenge
				pkt[0] = C2S_CHALLENGE;

				u32 *in_cookie = reinterpret_cast<u32*>( data + 1 );
				u32 *out_cookie = reinterpret_cast<u32*>( pkt + 1 );
				*out_cookie = *in_cookie;

				memcpy(pkt + 1 + 4, _cached_challenge, CHALLENGE_BYTES);

				// Zero the padding
				const int pad_offset = 1 + 4 + CHALLENGE_BYTES;
				memset(pkt + pad_offset, 0, C2S_CHALLENGE_LEN - pad_offset - sizeof(PROTOCOL_MAGIC));

				// Pinch of magic
				u64 *magic = reinterpret_cast<u64*>( pkt + C2S_CHALLENGE_LEN - sizeof(PROTOCOL_MAGIC) );
				*magic = getLE(PROTOCOL_MAGIC);

				// Attempt to post a pkt
				if (!Write(pkt, C2S_CHALLENGE_LEN, _server_addr))
				{
					ConnectFail(ERR_CLIENT_BROKEN_PIPE);
				}
				else
				{
					CAT_INFO("Client") << "Accepted cookie and posted challenge";
				}
			}
			else if (bytes == S2C_ANSWER_LEN && data[0] == S2C_ANSWER)
			{
				Skein key_hash;
				TunnelTLS *tunnel_tls = m_tunnel_tls.Ref(tls);

				// Process answer from server, ignore invalid
				if (_key_agreement_initiator.ProcessAnswer(tunnel_tls, data + 1, ANSWER_BYTES, &key_hash) &&
					_key_agreement_initiator.KeyEncryption(&key_hash, &_auth_enc, _session_key) &&
					InitializeTransportSecurity(true, _auth_enc))
				{
					_last_recv_tsc = _next_sync_time = _mtu_discovery_time = _clock->msec();
					_mtu_discovery_attempts = 2;
					_sync_attempts = 0;

#if defined(CAT_SPHYNX_ROAMING_IP)
					// Set ID
					u16 *id = reinterpret_cast<u16*>( data + 1 + ANSWER_BYTES );
					_my_id = getLE(*id);
#endif

					WriteTimePing();

					if (!DontFragment())
					{
						CAT_WARN("Client") << "Unable to detect MTU: Unable to set DF bit";

						_mtu_discovery_attempts = 0;
					}
					else if (!PostMTUProbe(MAXIMUM_MTU) ||
							 !PostMTUProbe(MEDIUM_MTU))
					{
						CAT_WARN("Client") << "Unable to detect MTU: First probe post failure";
					}

					_connected = true;
					OnConnect();

					// If we have already received the first encrypted message, keep processing
					node = node->batch_next;
					break;
				}
				else
				{
					CAT_INANE("Client") << "!!!! Ignored invalid server answer !!!!";
				}
			}
			else if (bytes == S2C_ERROR_LEN && data[0] == S2C_ERROR)
			{
				ConnectFail((SphynxError)data[1]);
			}
		}
	}

	// If connected datagrams exist,
	if (node)
	{
		BatchSet delivery;
		delivery.Clear();

		for (BatchHead *next; node; node = next)
		{
			next = node->batch_next;
			++buffer_count;
			RecvBuffer *buffer = static_cast<RecvBuffer*>( node );
			u8 *data = GetTrailingBytes(buffer);
			u32 data_bytes = buffer->data_bytes;

			if (data_bytes == 0)
			{
				Disconnect(ERR_CLIENT_BROKEN_PIPE);
				break;
			}
			else if (data_bytes > SPHYNX_S2C_OVERHEAD &&
					 _auth_enc.Decrypt(data, data_bytes))
			{
				data_bytes -= SPHYNX_S2C_OVERHEAD;

				// If needs to be decompressed,
				if (data[data_bytes])
				{
					// Decompress the buffer
					int compress_size = LZ4_uncompress_unknownOutputSize((const char*)data, (char*)compress_buffer, data_bytes, sizeof(compress_buffer));

					if (compress_size <= 0)
					{
						CAT_WARN("Client") << "!!!! Ignored invalid compressed data !!!!";
						continue;
					}

					// Copy compressed data back into the buffer
					memcpy(data, compress_buffer, compress_size);
					data_bytes = compress_size;
				}

				buffer->data_bytes = data_bytes;

				delivery.PushBack(buffer);
			}
			else
			{
				CAT_WARN("Client") << "!!!! Ignored invalid encrypted data !!!!";
			}
		}

		// Process all datagrams that decrypted properly
		if (delivery.head)
		{
			OnTransportDatagrams(delivery);
			_last_recv_tsc = Clock::msec_fast();;
		}
	}

	ReleaseRecvBuffers(buffers, buffer_count);
}

void Client::OnTick(ThreadLocalStorage &tls, u32 now)
{
	if (!_connected)
	{
		if ((s32)(now - _first_hello_post) >= CONNECT_TIMEOUT)
		{
			// NOTE: Connection can complete before or after OnConnectFail()
			ConnectFail(ERR_CLIENT_TIMEOUT);
			return;
		}

		if ((s32)(now - _last_hello_post) >= _hello_post_interval)
		{
			if (!WriteHello())
			{
				ConnectFail(ERR_CLIENT_BROKEN_PIPE);
				return;
			}

			_last_hello_post = now;
			_hello_post_interval *= 2;
		}

		OnCycle(now);
	}
	else
	{
		// If in graceful disconnect,
		if (IsDisconnected())
		{
			// Still tick transport layer because it is delivering IOP_DISCO messages
			TickTransport(now);
		}
		else
		{
			// If it is time for time sync,
			if ((s32)(now - _next_sync_time) >= 0)
			{
				WriteTimePing();

				// Increase sync interval after the first few data points
				if (_sync_attempts >= TS_FAST_COUNT)
					_next_sync_time = now + TS_INTERVAL;
				else
				{
					_next_sync_time = now + TS_FAST_PERIOD;
					++_sync_attempts;
				}
			}

			// If MTU discovery attempts continue,
			if (_mtu_discovery_attempts > 0)
			{
				// If it is time to re-probe the MTU,
				if ((s32)(now - _mtu_discovery_time) >= MTU_PROBE_INTERVAL)
				{
					// If payload bytes already maxed out,
					if (_max_payload_bytes >= MAXIMUM_MTU - _udpip_bytes - SPHYNX_C2S_OVERHEAD ||
						_mtu_discovery_attempts <= 0)
					{
						// Stop posting probes
						_mtu_discovery_attempts = 0;

						// On final attempt set DF=0
						DontFragment(false);
					}
					else
					{
						if (!PostMTUProbe(MAXIMUM_MTU))
						{
							CAT_WARN("Client") << "Unable to detect MTU: Probe post failure";
						}

						if (_max_payload_bytes < MEDIUM_MTU - _udpip_bytes - SPHYNX_C2S_OVERHEAD &&
							!PostMTUProbe(MEDIUM_MTU))
						{
							CAT_WARN("Client") << "Unable to detect MTU: Probe post failure";
						}

						_mtu_discovery_time = now;
						--_mtu_discovery_attempts;
					}
				}
			}

			// Do derived class tick event so any messages posted do not need to wait for the next tick
			OnCycle(now);

			TickTransport(now);

			// Send a keep-alive after the silence limit expires
			if ((s32)(now - _last_send_msec) >= SILENCE_LIMIT)
			{
				WriteTimePing();

				_next_sync_time = now + TS_INTERVAL;
			}

			// If no packets have been received,
			if ((s32)(now - _last_recv_tsc) >= TIMEOUT_DISCONNECT)
				Disconnect(DISCO_TIMEOUT);
		}
	}
}

Client::Client()
{
	_connected = false;
	_last_send_msec = 0;

	// Clock synchronization
	_ts_next_index = 0;
	_ts_sample_count = 0;

	_worker_id = INVALID_WORKER_ID;
}

bool Client::InitialConnect(TunnelTLS *tls, TunnelPublicKey &public_key, const char *session_key)
{
	if (!public_key.Valid())
	{
		CAT_WARN("Client") << "Failed to connect: Invalid server public key provided";
		return false;
	}

	// Verify public key and initialize crypto library with it
	if (!_key_agreement_initiator.Initialize(tls, public_key))
	{
		CAT_WARN("Client") << "Failed to connect: Corrupted server public key provided";
		return false;
	}

	// Generate a challenge for the server
	if (!_key_agreement_initiator.GenerateChallenge(tls, _cached_challenge, CHALLENGE_BYTES))
	{
		CAT_WARN("Client") << "Failed to connect: Cannot generate crypto-challenge";
		return false;
	}

	// Copy session key
	CAT_STRNCPY(_session_key, session_key, SESSION_KEY_BYTES);

	// Copy public key
	_server_public_key = public_key;

	// Get settings
	bool request_ip6 = m_settings->getInt("Sphynx.Client.RequestIPv6", 1) != 0;
	bool require_ip4 = m_settings->getInt("Sphynx.Client.RequireIPv4", 1) != 0;
	int kernelReceiveBufferBytes = m_settings->getInt("Sphynx.Client.KernelReceiveBuffer",
		DEFAULT_KERNEL_RECV_BUFFER, MIN_KERNEL_RECV_BUFFER, MAX_KERNEL_RECV_BUFFER);

	// Attempt to bind to any port and accept ICMP errors initially
	if (!Initialize(0, true, request_ip6, require_ip4, kernelReceiveBufferBytes))
	{
		CAT_WARN("Client") << "Failed to connect: Unable to bind to any port";
		return false;
	}

	// Initialize max payload bytes
	InitializePayloadBytes(SupportsIPv6());

	return true;
}

bool Client::FinalConnect(const NetAddr &addr)
{
	if (!addr.Valid())
	{
		ConnectFail(ERR_CLIENT_SERVER_ADDR);
		return false;
	}

	_server_addr = addr;

	// Convert server address if needed
	if (!_server_addr.Convert(SupportsIPv6()))
	{
		ConnectFail(ERR_CLIENT_SERVER_ADDR);
		return false;
	}

	_first_hello_post = _last_hello_post = Clock::msec_fast();
	_hello_post_interval = INITIAL_HELLO_POST_INTERVAL;

	// Assign to a worker
	u32 worker_id = m_worker_threads->FindLeastPopulatedWorker();

	TransportTLS *remote_tls = m_transport_tls.Peek(m_worker_threads->GetTLS(worker_id));
	if (!remote_tls)
	{
		ConnectFail(ERR_CLIENT_OUT_OF_MEMORY);
		return false;
	}

	struct 
	{
		u16 port;
		double time;
		u32 cycles;
	} entropy_source;

	entropy_source.port = GetPort();
	entropy_source.time = _clock->usec();
	entropy_source.cycles = _clock->cycles();

	//u32 lock_rv = MurmurHash(&entropy_source, sizeof(entropy_source), 0).Get32();
	InitializeTLS(remote_tls);

	// Attempt to post hello message
	if (!WriteHello())
	{
		ConnectFail(ERR_CLIENT_BROKEN_PIPE);
		return false;
	}

	if (!m_worker_threads->AssignTimer(worker_id, this, WorkerTimerDelegate::FromMember<Client, &Client::OnTick>(this)))
	{
		ConnectFail(ERR_CLIENT_OUT_OF_MEMORY);
		return false;
	}

	_worker_id = worker_id;

	return true;
}

bool Client::Connect(const char *hostname, Port port, TunnelPublicKey &public_key, const char *session_key, ThreadLocalStorage *tls)
{
	TunnelTLS *tunnel_tls = 0;
	if (!tls) tls = SlowTLS::ref()->Get();
	if (tls) tunnel_tls = m_tunnel_tls.Ref(*tls);
	if (!tunnel_tls) return false;

	if (!InitialConnect(tunnel_tls, public_key, session_key))
	{
		ConnectFail(ERR_CLIENT_INVALID_KEY);
		return false;
	}

	_server_addr.SetPort(port);

	if (!m_dns_client->Resolve(hostname, DNSDelegate::FromMember<Client, &Client::OnDNSResolve>(this), this))
	{
		ConnectFail(ERR_CLIENT_SERVER_ADDR);
		return false;
	}

	return true;
}

bool Client::Connect(const NetAddr &addr, TunnelPublicKey &public_key, const char *session_key, ThreadLocalStorage *tls)
{
	TunnelTLS *tunnel_tls = 0;
	if (!tls) tls = SlowTLS::ref()->Get();
	if (tls) tunnel_tls = m_tunnel_tls.Ref(*tls);
	if (!tunnel_tls) return false;

	if (!InitialConnect(tunnel_tls, public_key, session_key) ||
		!FinalConnect(addr))
	{
		return false;
	}

	return true;
}

bool Client::OnDNSResolve(const char *hostname, const NetAddr *addrs, int count)
{
	// If resolve failed,
	if (count <= 0)
	{
		ConnectFail(ERR_CLIENT_SERVER_ADDR);
		return false;
	}
	else
	{
		struct 
		{
			u16 port;
			int count;
			double time;
			u32 cycles;
		} entropy_source;

		entropy_source.port = GetPort();
		entropy_source.time = _clock->usec();
		entropy_source.cycles = _clock->cycles();
		entropy_source.count = count;

		u32 n = MurmurGenerateUnbiased(&entropy_source, sizeof(entropy_source), 0, count - 1);

		NetAddr addr = addrs[n];
		addr.SetPort(_server_addr.GetPort());

		CAT_INFO("Client") << "Connecting: Resolved '" << hostname << "' to " << addr.IPToString();

		if (!FinalConnect(addr))
			return false;
	}

	return true;
}

bool Client::WriteHello()
{
	if (_connected)
	{
		CAT_WARN("Client") << "Refusing to post hello after connected";
		return false;
	}

	u8 *pkt = m_udp_send_allocator->Acquire(C2S_HELLO_LEN);

	// If unable to allocate,
	if (!pkt)
	{
		CAT_WARN("Client") << "Cannot allocate a post buffer for hello packet";
		return false;
	}

	// Construct packet
	pkt[0] = C2S_HELLO;

	memcpy(pkt + 1, _server_public_key.GetPublicKey(), PUBLIC_KEY_BYTES);

	// Pinch of magic
	u64 *magic = reinterpret_cast<u64*>( pkt + 1 + PUBLIC_KEY_BYTES );
	*magic = getLE(PROTOCOL_MAGIC);

	// Attempt to post packet
	if (!Write(pkt, C2S_HELLO_LEN, _server_addr))
	{
		CAT_WARN("Client") << "Unable to post hello packet";
		return false;
	}

	CAT_INANE("Client") << "Posted hello packet";
	return true;
}

bool Client::WriteTimePing()
{
	u32 timestamp = _clock->msec();

	// Write it out-of-band to avoid delays in transmission
	return WriteOOB(IOP_C2S_TIME_PING, &timestamp, 4, SOP_INTERNAL);
}

s32 Client::WriteDatagrams(const BatchSet &buffers, u32 count)
{
	u64 iv = _auth_enc.GrabIVRange(count);
	s32 write_count = 0;

	/*
		The format of each buffer:

		[TRANSPORT(X)] [ENCRYPTION(11)] [USERID(2)] <- user id only in roaming ip mode

		The encryption overhead is not filled in yet.
		Each buffer's data_bytes is the transport layer data length.
		We need to add the 11 bytes of overhead to this before writing it.
	*/

#if defined(CAT_SPHYNX_ROAMING_IP)
	u16 my_id = getLE((u16)_my_id);
#endif

	// For each datagram to send,
	for (BatchHead *node = buffers.head; node; node = node->batch_next)
	{
		// Unwrap the message data
		SendBuffer *buffer = static_cast<SendBuffer*>( node );
		u8 *msg_data = GetTrailingBytes(buffer);
		u32 msg_bytes = buffer->data_bytes;

#if !defined(CAT_SPHYNX_ROAMING_IP)
		// Encrypt the message
		_auth_enc.Encrypt(iv, msg_data, msg_bytes);
#else
		// Encrypt the message
		_auth_enc.Encrypt(iv, msg_data, msg_bytes - 2);

		// Write ID to the end of packets
		u16 *msg_id = reinterpret_cast<u16*>( msg_data + msg_bytes - 2 );
		*msg_id = my_id;
#endif // CAT_SPHYNX_ROAMING_IP

		//INFO("Client") << "Transmitting datagram with " << msg_bytes << " data bytes";

		write_count += msg_bytes;
	}

	// If write fails,
	if (!Write(buffers, count, _server_addr))
		return 0;

	// Update the last send time to make sure we keep the channel occupied
	_last_send_msec = Clock::msec_fast();
	return write_count;
}

void Client::OnInternal(u32 recv_time, BufferStream data, u32 bytes)
{
	switch (data[0] & 3)
	{
	case IOP_S2C_MTU_SET:
		if (bytes == IOP_S2C_MTU_SET_LEN)
		{
			u16 max_payload_bytes = getLE(*reinterpret_cast<u16*>( data + 1 ));

#if defined(CAT_SPHYNX_ROAMING_IP)
			// Subtract 2 off for the extra c2s overhead
			max_payload_bytes -= 2;
#endif

			// If new maximum payload is greater than the previous one,
			if (max_payload_bytes > _max_payload_bytes)
			{
				// Set max payload bytes
				_max_payload_bytes = max_payload_bytes;
			}

			CAT_WARN("Client") << "Got IOP_S2C_MTU_SET.  Max payload bytes = " << max_payload_bytes;
		}
		break;

	case IOP_S2C_TIME_PONG:
		if (bytes == IOP_S2C_TIME_PONG_LEN)
		{
			u32 *timestamps = reinterpret_cast<u32*>( data + 1 );
			u32 client_ping_send_time = timestamps[0];
			u32 server_ping_recv_time = getLE(timestamps[1]);
			u32 server_pong_send_time = getLE(timestamps[2]);
			u32 client_pong_recv_time = recv_time;

			// RTT = Overall transmit time c2s s2c without the processing time on the server
			// Indicates quality of the delta measurement because lower RTT tends to happen
			// when both legs are about the same trip time
			u32 server_processing_time = server_pong_send_time - server_ping_recv_time;
			u32 rtt = client_pong_recv_time - client_ping_send_time - server_processing_time;

			// First leg = Delta(Server-Client) + One-way c2s Trip Time
			s32 first_leg = server_ping_recv_time - client_ping_send_time;

			// Second leg = Delta(Server-Client) - One-way s2c Trip Time
			s32 second_leg = server_pong_send_time - client_pong_recv_time;

			s32 delta = (s32)(((s64)first_leg + (s64)second_leg) / 2);

			UpdateTimeSynch(rtt, delta);

			CAT_WARN("Client") << "Got IOP_S2C_TIME_PONG.  rtt=" << rtt << " first leg = " << first_leg << " second leg = " << second_leg << " delta = " << delta << " running delta = " << (s32)_ts_delta;
		}
		break;

	case IOP_HUGE:
		if (bytes >= IOP_HUGE_MINLEN)
		{
			if (_huge_endpoint)
				_huge_endpoint->OnHuge(data, bytes);
		}
		break;

	case IOP_DISCO:
		if (bytes == IOP_DISCO_LEN)
		{
			CAT_WARN("Client") << "Got IOP_DISCO reason = " << (int)data[1];

			Disconnect(data[1]);
		}
		break;
	}
}

void Client::ConnectFail(SphynxError err)
{
	OnConnectFail(err);
	Destroy(CAT_REFOBJECT_TRACE);
}

/*
	Clock Synchronization

	--Definition of Clock Delta:

	There is a roughly linear relationship between server and client time
	because both clocks are trying to tick once per millisecond.

	Clock Delta = (Server Remote Time) - (Client Local Time)

	--Measurements:

	Clients are responsible for synchronizing their clocks with the server,
	so that the server does not need to store this state for each user.

	At least every 10 seconds the client will ping the server to collect a
	timing sample (IOP_C2S_TIME_PING and IOP_S2C_TIME_PONG).

	After initial connection, the first 8 measurements are performed at 5
	second intervals to build up confidence in the time synchronization faster.

	T0 = Client ping send time (in client units)
	T1 = Server pong send time (in server units)
	T1' = Client time when server sent the pong (in client units)
	T2 = Client pong receive time (in client units)

	Round trip time (RTT) = T2 - T0
	Clock Delta = T1 - T1'

	--Calculation of Clock Delta:

	Assuming balanced ping and pong delays:

	T1' ~= T0 + RTT / 2
	Clock Delta = T1 - ((T2 - T0) / 2 + T0)

	--Incorporating Measurement Quality:

	Not all deltas are of equal quality.  When the ping and/or pong delays
	are higher for various practical reasons, the delays become unbalanced
	and this estimate of clock delta loses accuracy.  Fortunately the RTT
	will also increase when this occurs, and so measurements with lower RTT
	may be considered more accurate.

	Throwing away 75% of the measurements, keeping the lowest RTT samples,
	should prevent bad data from affecting the clock synchronization.

	Averaging the remaining 25% seems to provide good, stable values for delta.

	--Incorporating 1st Order Drift:

	This is a bad idea.  I did take the time to try it out.  It requires a lot
	more bandwidth to collect enough data, and if the data is ever bad the
	drift calculations will amplify the error.

	Accounting for drift will defeat naive speed cheats since the increased
	clock tick rate will be corrected out just like normal drift.  However that
	only fixes timestamps and not increased rate of movement or other effects.

	The other problem is that by taking drift into account it takes a lot more
	processing time to do the calculations, and it requires a mutex to protect
	the calculated coefficients since they are no longer atomically updated.

	Furthermore, doing first order calculations end up requiring some
	consideration of timestamp rollover, where all the timestamps in the
	equations need to be taken relative to some base value.

	Incorporating drift is overkill and will cause more problems than it solves.
*/
void Client::UpdateTimeSynch(u32 rtt, s32 delta)
{
	// Increment the sample count if we haven't exhausted the array space yet
	if (_ts_sample_count < TS_MAX_SAMPLES)
		_ts_sample_count++;

	// Insert sample
	_ts_samples[_ts_next_index].delta = delta;
	_ts_samples[_ts_next_index].rtt = rtt;

	// Increment write address to next oldest entry or next empty space
	_ts_next_index = (_ts_next_index + 1) % TS_MAX_SAMPLES;

	// Find the lowest 25% RTT samples >= TS_MIN_SAMPLES
	TimesPingSample *BestSamples[TS_MAX_SAMPLES / 4 + TS_MIN_SAMPLES];
	u32 num_samples = _ts_sample_count / 4;
	if (num_samples < TS_MIN_SAMPLES) num_samples = TS_MIN_SAMPLES;

	// Find the highest RTT sample so far
	u32 highest_rtt = _ts_samples[0].rtt, highest_index = 0;
	BestSamples[0] = &_ts_samples[0];
	u32 best_count = 1;

	// Calculate the average delta and assume no drift
	s64 sum_delta = _ts_samples[0].delta;

	// While still trying to fill a minimum number of samples,
	u32 ii;
	for (ii = 1; ii < _ts_sample_count && best_count < num_samples; ++ii)
	{
		u32 rtt = _ts_samples[ii].rtt;
		sum_delta += _ts_samples[ii].delta;

		if (rtt > highest_rtt)
		{
			highest_rtt = rtt;
			highest_index = ii;
		}

		BestSamples[best_count++] = &_ts_samples[ii];
	}

	// For the remainder of the samples, fight over spots
	for (; ii < _ts_sample_count; ++ii)
	{
		u32 sample_rtt = _ts_samples[ii].rtt;

		// Replace highest RTT if the new sample has lower RTT
		if (sample_rtt >= highest_rtt)
			continue;

		// Replace it in the average calculation
		sum_delta -= BestSamples[highest_index]->delta;
		sum_delta += _ts_samples[ii].delta;

		BestSamples[highest_index] = &_ts_samples[ii];

		// Find new highest RTT entry
		highest_rtt = sample_rtt;

		for (u32 jj = 0; jj < best_count; ++jj)
		{
			u32 rtt = BestSamples[jj]->rtt;

			if (rtt <= highest_rtt)
				continue;

			highest_rtt = rtt;
			highest_index = jj;
		}
	}

	// Finalize the average, best delta
	_ts_delta = (u32)(sum_delta / best_count);
}
