/*
	Copyright (c) 2013-2014 Christopher A. Taylor.  All rights reserved.

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
#include "cauchy_256.h"

// Support tools
#include "Clock.hpp"
#include "Enforcer.hpp"

// Memory
#include "ReuseAllocator.hpp"
#include "SmartArray.hpp"

namespace cat {

namespace shorthair {


/*
 * Shorthair Protocol
 *
 * All packets have:
 *
 * <SeqNo [2 bytes]>
 * <Out-of-Band [1 bit] || codeGroup [7 bits]>
 *
 * OOB=1 packet overhead stops here, but protected data has more overhead:
 *
 * <id [1 byte]> : 0..k-1 = original, k..k+m-1 = recovery
 * <(k - 1) [1 byte]>
 *
 * Recovery packets (id >= blockCount) also have:
 *
 * <(m - 1) [1 byte]> : Parameter required to generate a proper decoding matrix
 * <length [2 bytes]> : Inside encoded section, the original packet length
 *
 * {packet data here, rounded up to next multiple of 8 bytes}
 */

// Protocol constants
static const int PROTOCOL_OVERHEAD = 1 + 1 + 1; // Includes OOB/group, ID, and K
static const int ORIGINAL_OVERHEAD = 2 + PROTOCOL_OVERHEAD; // + SeqNo
static const int RECOVERY_OVERHEAD = 2 + 1 + 2 + PROTOCOL_OVERHEAD; // + seqNo + M + length
static const int SHORTHAIR_OVERHEAD = RECOVERY_OVERHEAD; // 8 bytes + longest packet size for recovery packets
static const int MAX_CHUNK_SIZE = 65535; // Largest allowed packet chunk size
static const int MIN_CODE_DURATION = 100; // Milliseconds
static const int NUM_CODE_GROUPS = 256;
static const u32 GROUP_TIMEOUT = 1000; // 1 second of inactivity until a group is reset

// Loss estimate clamp values
static const float SHORTHAIR_MIN_LOSS_ESTIMATE = 0.03f;
static const float SHORTHAIR_MAX_LOSS_ESTIMATE = 0.5f;
static const int STAT_TRANSMIT_INTERVAL = 1000; // ms

//// LossEstimator

class LossEstimator {
	// Remember 10 seconds of loss stats
	static const int BINS = 10;
	struct {
		u32 seen, count;
	} _bins[BINS];
	int _count, _index;

	// Clamp values
	float _min_loss, _max_loss;

	// Resulting values
	float _real_loss, _clamped_loss;

public:
	void Initialize(float min_loss, float max_loss);

	void Insert(u32 seen, u32 count);

	// Pick estimated loss based on history
	void Calculate();

	CAT_INLINE float GetReal() {
		return _real_loss;
	}

	CAT_INLINE float GetClamped() {
		return _clamped_loss;
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


//// CodeGroup

struct CodeGroup {
	// Last update tick timestamp
	u32 last_update;

	// Largest ID seen for each code group, for decoding the ID
	int largest_id;

	// Largest seen data length
	int largest_len; // -1 indicates recovery completed

	// Largest seen block count for each code group
	int block_count;

	// The number of recovery packets in the code group
	int recovery_count;

	// Received symbol counts
	int original_seen;
	int total_seen; // Nonzero indicates needs to be cleaned

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

	void Clean(ReuseAllocator &allocator);

	CAT_INLINE bool IsDone() {
		return (largest_len == -1);
	}

	CAT_INLINE void MarkDone() {
		largest_len = -1;
	}

	void AddRecovery(Packet *p);
	void AddOriginal(Packet *p);
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
 * Minor wrinkle: IV values roll over after 0xFFFF, so we need
 * to handle that.
 */

class LossStatistics {
	u16 _frozen_start;	// frozen bin = [start, current)
	u32 _frozen_count;

	u16 _current_start;	// [start, inf)
	u32 _current_count;

	u16 _largest_seq;
	bool _no_data;

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
		_largest_seq = 0;
		_no_data = true;
	}

	// Update statistics
	CAT_INLINE void Update(u16 seq) {
		s16 delta = (s16)(seq - _largest_seq);

		// Update largest IV seen
		if (delta > 0) {
			_largest_seq = seq;
		} else {
			delta = -delta;
		}

		// If more than ~3 MB of data gets lost,
		if (_no_data || delta > 2000) {
			_no_data = false;
			// Reset stats to current seq (give up counting packet loss)
			_largest_seq = seq;
			_current_count = 0;
			_current_start = seq;
			_frozen_count = 0;
			_frozen_start = seq;
		}

		// Accumulate into a bin
		if ((s16)(seq - _current_start) >= 0) {
			_current_count++;
		} else if ((s16)(seq - _frozen_start) >= 0) {
			_frozen_count++;
		}
	}

	CAT_INLINE void Calculate() {
		// Calculate frozen stats
		_total = _current_start - _frozen_start; // NOTE: Fixes wrapping
		_seen = _frozen_count;

		// Freeze current
		_frozen_start = _current_start;
		_frozen_count = _current_count;

		// Make new set current
		_current_start = (u16)(_largest_seq + 1);
		_current_count = 0;
	}
};

/*
 * Encoder based on the Longhair CRS codec
 */

class Encoder {
	bool _initialized;

	// Packet buffers are allocated with room for the protocol overhead + data
	ReuseAllocator *_allocator;

	// Workspace to accumulate sent packets
	Packet *_head, *_tail;		// Queued packets
	int _original_count;		// Number of blocks of original data
	int _largest;				// Number of bytes max, excluding 2 byte implied length field

	// Workspace while sending recovery packets
	SmartArray<u8> _buffer;		// Contains all recovery packets
	int _k, _m;					// Codec parameter k, m
	int _next_recovery_block;	// Index into encode buffer to send next
	int _block_bytes;			// Block size in bytes

	CAT_INLINE void FreeGarbage() {
		_allocator->ReleaseBatch(BatchSet(_head, _tail));
		_head = 0;
		_tail = 0;
	}

public:
	CAT_INLINE Encoder() {
		_initialized = false;
	}
	CAT_INLINE virtual ~Encoder() {
		Finalize();
	}

	void Initialize(ReuseAllocator *allocator);
	void Finalize();

	// Add an original packet
	void Queue(Packet *p);

	CAT_INLINE int GetCurrentCount() {
		return _original_count;
	}

	// Encode queued data into recovery blocks
	void EncodeQueued(int recovery_count);

	int GenerateRecoveryBlock(u8 *buffer);
};


} // namespace shorthair

} // namespace cat

#endif // CAT_SHORTHAIR_DETAILS_HPP

