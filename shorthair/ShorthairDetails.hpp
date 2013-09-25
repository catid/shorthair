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

#ifndef CAT_SHORTHAIR_DETAILS_HPP
#define CAT_SHORTHAIR_DETAILS_HPP

// Support projects
#include "../wirehair/Wirehair.hpp"
#include "../calico/Calico.hpp"

// Support tools
#include "Clock.hpp"
#include "Enforcer.hpp"

// Memory
#include "ReuseAllocator.hpp"
#include "SmartArray.hpp"

// Multi-threading
#include "Thread.hpp"
#include "WaitableFlag.hpp"
#include "Mutex.hpp"

#include <vector>

namespace cat {

namespace shorthair {


// Protocol constants
static const int SKEY_BYTES = 32;
static const int PROTOCOL_OVERHEAD = 1 + 2 + 2;
static const int ORIGINAL_OVERHEAD = PROTOCOL_OVERHEAD + calico::Calico::OVERHEAD;
static const int RECOVERY_OVERHEAD = PROTOCOL_OVERHEAD + 2 + calico::Calico::OVERHEAD;
static const int BROOK_OVERHEAD = RECOVERY_OVERHEAD; // 18 bytes + longest packet size for recovery packets
static const int MAX_CHUNK_SIZE = 65535; // Largest allowed packet chunk size
static const u8 PAST_GROUP_THRESH = 127; // Group ID wrap threshold
static const int MIN_CODE_DURATION = 100; // Milliseconds

// OOB Pong packet type
static const u8 PONG_TYPE = 0xff;
static const int PONG_SIZE = 1 + 1 + 4 + 4;


//// LossEstimator

class LossEstimator {
	static const int BINS = 32;
	struct {
		u32 seen, count;
	} _bins[BINS];
	int _count, _index;

	// Minimum allowed loss estimate
	float _min_loss;

	// Final massaged value:
	float _loss;

public:
	void Initialize(float min_loss);

	void Insert(u32 seen, u32 count);

	// Pick estimated loss based on history
	void Calculate();

	CAT_INLINE float Get() {
		return _loss;
	}
};


//// DelayEstimator

class DelayEstimator {
	static const int BINS = 32;
	struct {
		int delay;
	} _bins[BINS];
	int _count, _index;

	// Clamp values
	int _min_delay, _max_delay;

	// Final massaged value:
	int _delay;

public:
	void Initialize(int min_delay, int max_delay);

	void Insert(int delay);

	// Pick estimated upper-bound on one-way s2c delay based on history
	void Calculate();

	CAT_INLINE int Get() {
		return _delay;
	}
};


//// Packet

struct Packet : BatchHead {
	// Block ID/Length for this packet
	union {
		u32 id;		// Used by decoder, length is in data
		u16 len;	// Used by encoder, id is in data
	};

	// Data follows
	u8 data[1];
};


//// EncoderThread

/*
 * Run the encoder in a separate thread to avoid adding latency spikes
 * to the original data packet stream.
 *
 * Not thread-safe.  It assumes that only one thread is accessing its
 * interface at a time.
 */
class EncoderThread : public Thread {
protected: // Shared data:
	bool _initialized;
	volatile bool _kill;
	WaitableFlag _wake;

	// Packet buffers are allocated with room for the protocol overhead + data
	ReuseAllocator *_allocator;

	// Workspace to accumulate sent packets
	Packet *_sent_head, *_sent_tail;
	int _block_count;	// Number of blocks 
	int _largest;		// Number of bytes max, excluding 2 byte implied length field

	// Next block id to produce
	u32 _next_block_id;

	// Encoder is ready to produce symbols?
	// Cleared by main thread, set by encoder thread
	volatile bool _encoder_ready;

	// Lock to hold during processing to avoid reentrancy
	Mutex _processing_lock;

	// Indicates previous group can be disposed
	volatile bool _last_garbage;

private: // Thread-Private data:
	wirehair::Encoder _encoder;

	// Code group size
	int _group_largest, _group_count;

	// Fixed code group list
	Packet *_group_head, *_group_tail;

	// Size of block for this group
	int _group_block_size;

	// Large message buffer for code group
	SmartArray<u8> _encode_buffer;

	CAT_INLINE void FreeGarbage() {
		if (_last_garbage) {
			_last_garbage = false;
			// Free packet buffers
			_allocator->ReleaseBatch(BatchSet(_group_head, _group_tail));
		}
	}

	virtual bool Entrypoint(void *param);

	void Process();

public:
	CAT_INLINE EncoderThread() {
		_initialized = false;
	}
	CAT_INLINE virtual ~EncoderThread() {
		Finalize();
	}

	void Initialize(ReuseAllocator *allocator);
	void Finalize();
	Packet *Queue(int len);

	CAT_INLINE int GetCurrentCount() {
		return _block_count;
	}

	void EncodeQueued();

	// Returns 0 if recovery blocks cannot be sent yet
	int GenerateRecoveryBlock(u8 *buffer);
};


//// CodeGroup

struct CodeGroup {
	// Group is open?
	bool open;

	// Timestamp on first packet for this group
	u32 open_time;

	// Largest ID seen for each code group, for decoding the ID
	u32 largest_id;

	// Largest seen data length
	u16 largest_len;

	// Largest seen block count for each code group
	u16 block_count;

	// Received symbol counts
	u16 original_seen;
	u32 total_seen;

	// Original symbols
	Packet *head, *tail;

	// Recovery symbols
	Packet *recovery_head, *recovery_tail;

	CAT_INLINE bool CanRecover() {
		// If block count is still unknown,
		if (largest_id < block_count) {
			return false;
		}

		// If recovery is possible,
		return total_seen >= block_count;
	}

	void Open(u32 ms);
	void Close(ReuseAllocator &allocator);

	void AddRecovery(Packet *p);
	void AddOriginal(Packet *p);
};



//// GroupFlags

class GroupFlags {
	// 256 bits
	u32 _open[8];
	u32 _done[8];

public:
	CAT_INLINE void Clear() {
		CAT_OBJCLR(_open);
		CAT_OBJCLR(_done);
	}

	CAT_INLINE void SetOpen(const u8 group) {
		_open[group >> 5] |= 1 << (group & 31);
	}

	CAT_INLINE void ResetOpen(const u8 group) {
		_open[group >> 5] &= ~(1 << (group & 31));
	}

	CAT_INLINE bool IsOpen(const u8 group) {
		// If bit is set return true
		const u32 mask = 1 << (group & 31);
		return (_open[group >> 5] & mask) != 0;
	}

	CAT_INLINE void SetDone(const u8 group) {
		_done[group >> 5] |= 1 << (group & 31);
	}

	CAT_INLINE void ResetDone(const u8 group) {
		_done[group >> 5] &= ~(1 << (group & 31));
	}

	CAT_INLINE bool IsDone(const u8 group) {
		// If bit is set return true
		const u32 mask = 1 << (group & 31);
		return (_done[group >> 5] & mask) != 0;
	}

protected:
	virtual void OnGroupTimeout(const u8 group) = 0;

	// Calls OnGroupTimeout when a timeout is detected
	void ClearOpposite(const u8 group);
};


/*
 * Loss Statistics from IV holes:
 *
 * As pings are received:
 *          |<---delay-->|<---delay--->|<---delay--->|
 * Bin 0 :  ^START       ^STOP         ^DELIVER
 * Bin 1 :               ^START        ^STOP         ^DELIVER
 * Bin 2 :                             ^START        ^STOP
 * ...
 *
 * Bins have a given start and stop IV range.  IVs in these
 * ranges are counted towards the bin.
 *
 * Whenever a ping is requested, a new bin is started, the last
 * bin is frozen, and the last last bin is delivered.
 *
 * Minor wrinkle: IV values roll over after ~(u32)0, so we need
 * to handle that.
 */

class LossStatistics {
	u32 _frozen_start;	// frozen bin = [start, current)
	u32 _frozen_count;

	u32 _current_start;	// [start, inf)
	u32 _current_count;

	u32 _largest_iv;

	// Stats from last period
	u32 _seen, _total;

public:
	CAT_INLINE u32 GetSeen() {
		return _seen;
	}
	CAT_INLINE u32 GetTotal() {
		return _total;
	}

	// Reset
	void Initialize() {
		_frozen_start = 0;
		_frozen_count = 0;
		_current_start = 0;
		_current_count = 0;
		_largest_iv = 0;
	}

	// Update statistics
	CAT_INLINE void Update(u32 iv) {
		// Update largest IV seen
		if ((s32)(iv - _largest_iv) > 0) {
			_largest_iv = iv;
		}

		// Accumulate into a bin
		if ((s32)(iv - _current_start) >= 0) {
			_current_count++;
		} else if ((s32)(iv - _frozen_start) >= 0) {
			_frozen_count++;
		}
	}

	// Update stats when pings occur
	CAT_INLINE void OnPing() {
		// Calculate frozen stats
		_total = _current_start - _frozen_start; // NOTE: Fixes wrapping
		_seen = _frozen_count;

		// Freeze current
		_frozen_start = _current_start;
		_frozen_count = _current_count;

		// Make new set current
		_current_start = _largest_iv + 1;
		_current_count = 0;
	}
};


} // namespace shorthair

} // namespace cat

#endif // CAT_SHORTHAIR_DETAILS_HPP

