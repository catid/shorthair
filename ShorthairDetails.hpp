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

#pragma once

#include "cauchy_256.h"
#include "PacketAllocator.h"
#include "SiameseTools.h"
#include "Counter.h"

namespace cat {
namespace shorthair {


//------------------------------------------------------------------------------
// POD Serialization

SIAMESE_FORCE_INLINE uint16_t ReadU16_LE(const uint8_t* data)
{
#ifdef GF256_ALIGNED_ACCESSES
    return ((uint16_t)data[1] << 8) | data[0];
#else
    return *(uint16_t*)data;
#endif
}

SIAMESE_FORCE_INLINE uint32_t ReadU24_LE(const uint8_t* data)
{
    return ((uint32_t)data[2] << 16) | ((uint32_t)data[1] << 8) | data[0];
}

/// This version uses one memory read on Intel but requires at least 4 bytes in the buffer
SIAMESE_FORCE_INLINE uint32_t ReadU24_LE_Min4Bytes(const uint8_t* data)
{
#ifdef GF256_ALIGNED_ACCESSES
    return ReadU24_LE(data);
#else
    return *(uint32_t*)data & 0xFFFFFF;
#endif
}

SIAMESE_FORCE_INLINE uint32_t ReadU32_LE(const uint8_t* data)
{
#ifdef GF256_ALIGNED_ACCESSES
    return ((uint32_t)data[3] << 24) | ((uint32_t)data[2] << 16) | ((uint32_t)data[1] << 8) | data[0];
#else
    return *(uint32_t*)data;
#endif
}

SIAMESE_FORCE_INLINE uint64_t ReadU64_LE(const uint8_t* data)
{
#ifdef GF256_ALIGNED_ACCESSES
    return ((uint64_t)data[7] << 56) | ((uint64_t)data[6] << 48) | ((uint64_t)data[5] << 40) |
           ((uint64_t)data[4] << 32) | ((uint64_t)data[3] << 24) | ((uint64_t)data[2] << 16) |
           ((uint64_t)data[1] << 8) | data[0];
#else
    return *(uint64_t*)data;
#endif
}

SIAMESE_FORCE_INLINE void WriteU16_LE(uint8_t* data, uint16_t value)
{
#ifdef GF256_ALIGNED_ACCESSES
    data[1] = (uint8_t)(value >> 8);
    data[0] = (uint8_t)value;
#else
    *(uint16_t*)data = value;
#endif
}

SIAMESE_FORCE_INLINE void WriteU24_LE(uint8_t* data, uint32_t value)
{
    data[2] = (uint8_t)(value >> 16);
    WriteU16_LE(data, (uint16_t)value);
}

SIAMESE_FORCE_INLINE void WriteU24_LE_Min4Bytes(uint8_t* data, uint32_t value)
{
#ifdef GF256_ALIGNED_ACCESSES
    WriteU24_LE(data, value);
#else
    *(uint32_t*)data = value;
#endif
}

SIAMESE_FORCE_INLINE void WriteU32_LE(uint8_t* data, uint32_t value)
{
#ifdef GF256_ALIGNED_ACCESSES
    data[3] = (uint8_t)(value >> 24);
    data[2] = (uint8_t)(value >> 16);
    data[1] = (uint8_t)(value >> 8);
    data[0] = (uint8_t)value;
#else
    *(uint32_t*)data = value;
#endif
}

SIAMESE_FORCE_INLINE void WriteU64_LE(uint8_t* data, uint64_t value)
{
#ifdef GF256_ALIGNED_ACCESSES
    data[7] = (uint8_t)(value >> 56);
    data[6] = (uint8_t)(value >> 48);
    data[5] = (uint8_t)(value >> 40);
    data[4] = (uint8_t)(value >> 32);
    data[3] = (uint8_t)(value >> 24);
    data[2] = (uint8_t)(value >> 16);
    data[1] = (uint8_t)(value >> 8);
    data[0] = (uint8_t)value;
#else
    *(uint64_t*)data = value;
#endif
}


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
static const int MAX_CHUNK_SIZE = 2000; // Largest allowed packet chunk size
static const int MIN_CODE_DURATION = 100; // Milliseconds
static const int NUM_CODE_GROUPS = 256;
static const uint32_t GROUP_TIMEOUT = 1000; // 1 second of inactivity until a group is reset

// Loss estimate clamp values
static const float SHORTHAIR_MIN_LOSS_ESTIMATE = 0.03f;
static const float SHORTHAIR_MAX_LOSS_ESTIMATE = 0.5f;
static const int STAT_TRANSMIT_INTERVAL = 1000; // ms

//// LossEstimator

class LossEstimator {
    // Remember 10 seconds of loss stats
    static const int BINS = 10;
    struct {
        uint32_t seen, count;
    } _bins[BINS];
    int _count, _index;

    // Clamp values
    float _min_loss, _max_loss;

    // Resulting values
    float _real_loss, _clamped_loss;

public:
    void Initialize(float min_loss, float max_loss);

    void Insert(uint32_t seen, uint32_t count);

    // Pick estimated loss based on history
    void Calculate();

    SIAMESE_FORCE_INLINE float GetReal() {
        return _real_loss;
    }

    SIAMESE_FORCE_INLINE float GetClamped() {
        return _clamped_loss;
    }
};


// For batch allocations, this is the header attached to each one.  This header
// allows for the batched objects to be passed around with a BatchSet (below).
// Normal allocations do not use this header.
struct BatchHead
{
    BatchHead *batch_next;
};

// When passing around a batch of allocated space, use this object to represent
// the two ends of the batch for O(1) concatenation to other batches
class BatchSet
{
public:
    BatchHead *head, *tail;

    SIAMESE_FORCE_INLINE BatchSet() {}
    SIAMESE_FORCE_INLINE BatchSet(BatchHead *h, BatchHead *t) { head = h; tail = t; }
    SIAMESE_FORCE_INLINE BatchSet(BatchHead *single)
    {
        head = tail = single;
        single->batch_next = 0;
    }

    SIAMESE_FORCE_INLINE BatchSet(const BatchSet &t)
    {
        head = t.head;
        tail = t.tail;
    }

    SIAMESE_FORCE_INLINE BatchSet &operator=(const BatchSet &t)
    {
        head = t.head;
        tail = t.tail;
        return *this;
    }

    SIAMESE_FORCE_INLINE void Clear()
    {
        head = tail = 0;
    }

    SIAMESE_FORCE_INLINE void PushBack(BatchHead *single)
    {
        if (tail) tail->batch_next = single;
        else head = single;
        tail = single;
        single->batch_next = 0;
    }

    SIAMESE_FORCE_INLINE void PushBack(const BatchSet &t)
    {
        // If parameter is the empty set,
        if (!t.head) return;

        // If we are an empty set,
        if (!head)
            head = t.head;
        else
            tail->batch_next = t.head;

        tail = t.tail;
    }

    /// Release all packets in the batch
    void Release(pktalloc::Allocator* allocatorPtr)
    {
        for (BatchHead* node = head, *next; node; node = next)
        {
            next = node->batch_next;
            allocatorPtr->Free((uint8_t*)node);
        }
    }
};


//// Packet

struct Packet : BatchHead {
    // Block ID/Length for this packet
    union {
        uint32_t id;    // Used by decoder, length is in data
        uint16_t len;    // Used by encoder, id is in data
    };

    // Data follows
    uint8_t data[1];
};


//// CodeGroup

struct CodeGroup {
    // Last update tick timestamp
    uint32_t last_update;

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

    SIAMESE_FORCE_INLINE bool CanRecover() {
        // If block count is still unknown,
        if (largest_id < block_count) {
            return false;
        }

        // If recovery is possible,
        return total_seen >= block_count;
    }

    void Clean(pktalloc::Allocator* allocatorPtr);

    SIAMESE_FORCE_INLINE bool IsDone() {
        return (largest_len == -1);
    }

    SIAMESE_FORCE_INLINE void MarkDone() {
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
    uint16_t _frozen_start;    // frozen bin = [start, current)
    uint32_t _frozen_count;

    uint16_t _current_start;    // [start, inf)
    uint32_t _current_count;

    uint16_t _largest_seq;
    bool _no_data;

    // Stats from last period
    uint32_t _seen, _total;

public:
    SIAMESE_FORCE_INLINE uint32_t GetSeen() {
        return _seen;
    }
    SIAMESE_FORCE_INLINE uint32_t GetTotal() {
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
    SIAMESE_FORCE_INLINE void Update(uint16_t seq) {
        int16_t delta = (int16_t)(seq - _largest_seq);

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
        if ((int16_t)(seq - _current_start) >= 0) {
            _current_count++;
        } else if ((int16_t)(seq - _frozen_start) >= 0) {
            _frozen_count++;
        }
    }

    SIAMESE_FORCE_INLINE void Calculate() {
        // Calculate frozen stats
        _total = _current_start - _frozen_start; // NOTE: Fixes wrapping
        _seen = _frozen_count;

        // Freeze current
        _frozen_start = _current_start;
        _frozen_count = _current_count;

        // Make new set current
        _current_start = (uint16_t)(_largest_seq + 1);
        _current_count = 0;
    }
};

/*
 * Encoder based on the Longhair CRS codec
 */

class Encoder {
    bool _initialized;

    // Packet buffers are allocated with room for the protocol overhead + data
    pktalloc::Allocator *_allocator;

    // Workspace to accumulate sent packets
    Packet *_head, *_tail;        // Queued packets
    int _original_count;        // Number of blocks of original data
    int _largest;                // Number of bytes max, excluding 2 byte implied length field

    // Workspace while sending recovery packets
    siamese::LightVector<uint8_t> _buffer;        // Contains all recovery packets
    int _k, _m;                    // Codec parameter k, m
    int _next_recovery_block;    // Index into encode buffer to send next
    int _block_bytes;            // Block size in bytes

    SIAMESE_FORCE_INLINE void FreeGarbage() {
        BatchSet batch(_head, _tail);
        batch.Release(_allocator);
        _head = 0;
        _tail = 0;
    }

public:
    SIAMESE_FORCE_INLINE Encoder() {
        _initialized = false;
    }
    SIAMESE_FORCE_INLINE virtual ~Encoder() {
        Finalize();
    }

    void Initialize(pktalloc::Allocator *allocator);
    void Finalize();

    // Add an original packet
    void Queue(Packet *p);

    SIAMESE_FORCE_INLINE int GetCurrentCount() {
        return _original_count;
    }

    // Encode queued data into recovery blocks
    void EncodeQueued(int recovery_count);

    int GenerateRecoveryBlock(uint8_t *buffer);
};


} // namespace shorthair
} // namespace cat
