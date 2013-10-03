/*
	Copyright (c) 2011 Christopher A. Taylor.  All rights reserved.

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

#include <cat/sphynx/FlowControl.hpp>
#include <cat/time/Clock.hpp>
#include <cat/io/Log.hpp>
#include <cat/sphynx/Transport.hpp>
using namespace cat;
using namespace sphynx;


//// FlowControl

FlowControl::FlowControl()
{
	_bandwidth_low_limit = 3000;
	_bandwidth_high_limit = 100000000;
	_bps = _bandwidth_low_limit;

	_rtt = 3000;

	_last_bw_update = 0;
	_available_bw = 0;

	// Statistics
	_last_stats_update = 0;
	_stats_rtt_acc = 0;
	_stats_rtt_count = 0;
	_stats_loss_count = 0;
	_stats_goodput = 0;
}

s32 FlowControl::GetRemainingBytes(u32 now)
{
	_lock.Enter();

	u32 elapsed = now - _last_bw_update;
	_last_bw_update = now;

	// Need to use 64-bit here because this number can exceed 4 MB
	u32 bytes = (u32)(((u64)elapsed * _bps) / 1000);

	s32 bytes_per_tick_max = _bps / 100;
	if (bytes > (u32)bytes_per_tick_max)
		bytes = bytes_per_tick_max;

	s32 available = _available_bw + bytes;
	if (available > bytes_per_tick_max)
		available = bytes_per_tick_max;

	_available_bw = available;

	_lock.Leave();

	return available;
}

void FlowControl::OnPacketSend(u32 bytes_with_overhead)
{
	_lock.Enter();

	_available_bw -= bytes_with_overhead;

	_lock.Leave();
}

void FlowControl::OnTick(u32 now, u32 timeout_loss_count)
{
	_lock.Enter();

	_stats_loss_count += timeout_loss_count;

	// Tick statistics
	s32 elapsed = now - _last_stats_update;
	s32 period = (_rtt + RTT_FUZZ) * 4;
	if (elapsed >= period)
	{
		u32 rtt_avg = _stats_rtt_count ? (_stats_rtt_acc / _stats_rtt_count) : 0;
		u32 loss_count = _stats_loss_count;
		u32 goodput = _stats_goodput;
		u32 goodrate = (u32)((u64)goodput * 1000 / elapsed);

		// TODO: Disable RTT bump for now
/*
		// If all of the reliable messages were retransmissions but data was
		// delivered successfully,
		if (rtt_avg == 0 && goodput > 0)
		{
			// Double RTT since it seems to have jumped fast!
			_rtt *= 2;

			CAT_FATAL("FlowControl") << "Doubled RTT since RTTavg == 0 && goodput > 0";
		}
*/

		_last_stats_update = now;
		_stats_rtt_acc = 0;
		_stats_rtt_count = 0;
		_stats_loss_count = 0;
		_stats_goodput = 0;

		// If we get a loss,
		if (loss_count >= 2)
		{
			// Halve the bandwidth
			_bps /= 2;

			if (_bps < _bandwidth_low_limit)
				_bps = _bandwidth_low_limit;
		}
		else
		{
			// Increase the bandwidth by the goodput over the period
			if (goodrate >= _bps * 0.8)
			{
				static const s32 MIN_AIMD_INCREMENT = 2000;

				s32 increment = goodrate / 20;

				if (increment < MIN_AIMD_INCREMENT)
					increment = MIN_AIMD_INCREMENT;

				_bps += increment;

				if (_bps > _bandwidth_high_limit)
					_bps = _bandwidth_high_limit;
			}
		}

		if (goodput > 0)
			CAT_FATAL("FlowControl") << "Statistics: RTTavg=" << rtt_avg << " losses=" << loss_count << " goodput=" << goodput << " goodrate=" << goodrate << " BPS=" << _bps << " RTT=" << _rtt;
	}

	_lock.Leave();
}

void FlowControl::OnACK(u32 recv_time, OutgoingMessage *node)
{
	// If no retransmission,
	if (node->ts_firstsend == node->ts_lastsend)
	{
		u32 rtt = recv_time - node->ts_firstsend;

		_lock.Enter();

		// Update statistics
		_stats_rtt_acc += rtt;
		_stats_rtt_count++;

		// Update estimate of RTT
		_rtt = (_rtt * 9 + rtt) / 10;

		_lock.Leave();
	}
}

void FlowControl::OnACKDone(u32 recv_time, u32 nack_loss_count, u32 data_bytes)
{
	_lock.Enter();

	_stats_goodput += data_bytes;
	_stats_loss_count += nack_loss_count;

	_lock.Leave();
}
