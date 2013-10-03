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

#include <cat/sphynx/Connexion.hpp>
#include <cat/sphynx/Server.hpp>
#include <cat/io/Log.hpp>
#include <cat/crypt/SecureEqual.hpp>
#include <ext/lz4/lz4.h>
using namespace cat;
using namespace sphynx;

static Clock *m_clock = 0;
static TLSInstance<TunnelTLS> m_tunnel_tls;


//// Connexion

u32 Connexion::getLocalTime()
{
	return m_clock->msec();
}

bool Connexion::OnInitialize()
{
	Use(m_clock);

	return true;
}

void Connexion::OnDestroy()
{
	if (_parent) _parent->_conn_map.Remove(this);
}

bool Connexion::OnFinalize()
{
	if (_parent) _parent->ReleaseRef(CAT_REFOBJECT_TRACE);

	return true;
}

void Connexion::OnDisconnectComplete()
{
	Destroy(CAT_REFOBJECT_TRACE);
}

#if !defined(CAT_SPHYNX_ROAMING_IP)

void Connexion::RetransmitAnswer(RecvBuffer *buffer)
{
	// Handle lost s2c answer by retransmitting it
	// And only do this for the first packet we get
	u8 *data = GetTrailingBytes(buffer);
	u32 bytes = buffer->data_bytes;

	if (bytes == C2S_CHALLENGE_LEN && data[0] == C2S_CHALLENGE)
	{
		u8 *challenge = data + sizeof(PROTOCOL_MAGIC) + 1 + 4;

		// Only need to check that the challenge is the same, since we
		// have already validated the cookie and protocol magic to get here
		if (_first_challenge_hash == MurmurHash(challenge, CHALLENGE_BYTES).Get64())
		{
			CAT_WARN("Connexion") << "Ignoring challenge: Replay challenge in bad state";
			return;
		}

		u8 *pkt = UDPSendAllocator::ref()->Acquire(S2C_ANSWER_LEN);
		if (!pkt)
		{
			CAT_WARN("Connexion") << "Ignoring challenge: Unable to allocate post buffer";
			return;
		}

		// Construct packet
		pkt[0] = S2C_ANSWER;

		memcpy(pkt + 1, _cached_answer, ANSWER_BYTES);

		_parent->Write(pkt, S2C_ANSWER_LEN, buffer->GetAddr());

		CAT_INANE("Connexion") << "Replayed lost answer to client challenge";
	}
}

#endif // CAT_SPHYNX_ROAMING_IP

void Connexion::OnRecv(ThreadLocalStorage &tls, const BatchSet &buffers)
{
	u8 compress_buffer[IOTHREADS_BUFFER_READ_BYTES];
	u32 buffer_count = 0;

	BatchSet delivery;
	delivery.Clear();

	// For each connected datagram,
	for (BatchHead *next, *node = buffers.head; node; node = next)
	{
		next = node->batch_next;
		RecvBuffer *buffer = static_cast<RecvBuffer*>( node );
		++buffer_count;

		u8 *data = GetTrailingBytes(buffer);
		u32 data_bytes = buffer->data_bytes;

		CAT_INFO("Connexion") << "Decrypting " << data_bytes << " bytes in " << this;

		// If the data could be decrypted,
		if (data_bytes > SPHYNX_C2S_OVERHEAD &&
#if defined(CAT_SPHYNX_ROAMING_IP)
			_auth_enc.Decrypt(data, data_bytes - 2))
#else
			_auth_enc.Decrypt(data, data_bytes))
#endif
		{
			data_bytes -= SPHYNX_C2S_OVERHEAD;

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
#if !defined(CAT_SPHYNX_ROAMING_IP)
		else if (buffer_count <= 1 && !_seen_encrypted)
		{
			RetransmitAnswer(buffer);
		}
#endif
	}

	// Process all datagrams that decrypted properly
	if (delivery.head)
	{/*
		// TODO: Simulating out of order packets
		if (delivery.tail && delivery.tail != delivery.head)
		{
			BatchHead *old_head = delivery.head;
			BatchHead *old_next = old_head->batch_next;

			old_head->batch_next = old_next->batch_next;
			old_next->batch_next = old_head;

			delivery.head = old_next;

			if (old_next == delivery.tail)
				delivery.tail = old_head;
		}
		*/
		OnTransportDatagrams(delivery);
		_seen_encrypted = true;
		_last_recv_tsc = Clock::msec_fast();

#if defined(CAT_SPHYNX_ROAMING_IP)
		// If client address needs to be updated,
		RecvBuffer *tail = static_cast<RecvBuffer*>( delivery.tail );
		if (_client_addr != tail->GetAddr())
			_client_addr = tail->GetAddr();
#endif
	}

	_parent->ReleaseRecvBuffers(buffers, buffer_count);

	ReleaseRef(CAT_REFOBJECT_TRACE, buffer_count);
}

void Connexion::OnTick(ThreadLocalStorage &tls, u32 now)
{
	// If in graceful disconnect,
	if (IsDisconnected())
	{
		// Still tick transport layer because it is delivering IOP_DISCO messages
		TickTransport(now);
	}
	else
	{
		// Do derived class tick event so any messages posted do not need to wait for the next tick
		OnCycle(now);

		TickTransport(now);

		// If no packets have been received,
		if ((s32)(now - _last_recv_tsc) >= TIMEOUT_DISCONNECT)
		{
			Disconnect(DISCO_TIMEOUT);
		}
	}
}

Connexion::Connexion()
{
	_my_id = ConnexionMap::INVALID_KEY;
	_seen_encrypted = false;

	_worker_id = INVALID_WORKER_ID;
}

s32 Connexion::WriteDatagrams(const BatchSet &buffers, u32 count)
{
	u64 iv = _auth_enc.GrabIVRange(count);
	s32 write_count = 0;

	/*
		The format of each buffer:

		[TRANSPORT(X)] [ENCRYPTION(11)]

		The encryption overhead is not filled in yet.
		Each buffer's data_bytes is the transport layer data length.
		We need to add the 11 bytes of overhead to this before writing it.
	*/

	// For each datagram to send,
	for (BatchHead *node = buffers.head; node; node = node->batch_next)
	{
		// Unwrap the message data
		SendBuffer *buffer = static_cast<SendBuffer*>( node );
		u8 *msg_data = GetTrailingBytes(buffer);
		u32 msg_bytes = buffer->data_bytes;

#if defined(CAT_SPHYNX_ROAMING_IP)
		// Remove extra overhead bytes for s2c stuff
		msg_bytes -= 2;
		buffer->data_bytes = msg_bytes;
#endif

		// Encrypt the message
		_auth_enc.Encrypt(iv, msg_data, msg_bytes);

		write_count += msg_bytes;
	}

	// Do not need to update a "last send" timestamp here because the client is responsible for sending keep-alives
	return _parent->Write(buffers, count, _client_addr) ? write_count : 0;
}

void Connexion::OnInternal(u32 recv_time, BufferStream data, u32 bytes)
{
	switch (data[0] & 3)
	{
	case IOP_C2S_MTU_PROBE:
		if (bytes >= IOP_C2S_MTU_TEST_MINLEN)
		{
#if defined(CAT_SPHYNX_ROAMING_IP)
			// The byte count does not include the 2 byte header and 2 byte user id
			bytes += 2 + 2;
#else
			// The byte count does not include the 2 byte header
			bytes += 2;
#endif

			// If new maximum payload is greater than the previous one,
			if (bytes > _max_payload_bytes)
			{
				// Set max payload bytes
				_max_payload_bytes = bytes;

				u16 mtu = getLE((u16)bytes);
				WriteReliable(STREAM_UNORDERED, IOP_S2C_MTU_SET, &mtu, 2, SOP_INTERNAL);
			}

			CAT_WARN("Connexion") << "Got IOP_C2S_MTU_PROBE.  Max payload bytes = " << bytes;
		}
		break;

	case IOP_C2S_TIME_PING:
		if (bytes == IOP_C2S_TIME_PING_LEN)
		{
			u32 *client_timestamp = reinterpret_cast<u32*>( data + 1 );

			u32 stamps[3] = { *client_timestamp, getLE(recv_time), getLE(m_clock->msec()) };

			WriteOOB(IOP_S2C_TIME_PONG, stamps, sizeof(stamps), SOP_INTERNAL);

			CAT_WARN("Connexion") << "Got IOP_C2S_TIME_PING.  Stamp = " << *client_timestamp;
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
			CAT_WARN("Connexion") << "Got IOP_DISCO reason = " << (int)data[1];

			Disconnect(data[1]);
		}
		break;
	}
}
