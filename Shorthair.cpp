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

#include "Shorthair.hpp"

//#define CAT_DUMP_SHORTHAIR

#if !defined(CAT_DUMP_SHORTHAIR)
#define LOG(fmt, ...)
#else
#ifdef CAT_OS_ANDROID
#include <android/log.h>
#define LOG(fmt, ...) __android_log_print(ANDROID_LOG_INFO, "shorthair", fmt, __VA_ARGS__);
#else
#include <cstdio>
#define LOG(fmt, ...) printf("{shorthair}" fmt "\r\n", __VA_ARGS__);
#endif
#endif

#include <cmath>
#include <vector>
#include <mutex>

namespace cat {
namespace shorthair {

static std::mutex m_mutex;


/*
 * A visual representation of streaming in general (disregarding FEC):
 *
 * | <---------------------------- buffer size ----> | <- processed ---->
 * | <- in  transit -> |                             |
 * | 11 | 10 | 09 | 08 | 07 | 06 | 05 | 04 | 03 | 02 | 01 | 00 |
 * ^                   ^
 * t=0                 t=max one-way latency expected
 *
 * The perceived latency at the receiver is the buffer size, and each of the
 * numbered bins may contain several packets transmitted together.
 *
 * Some example numbers:
 *
 * Stream data packet(s) every 10 ms
 * t = ~100 ms
 * buffer size = 250 ms
 *
 *
 * ==> Why use FEC?
 *
 * With RTT acknowledgement protocol like TCP this latency cannot be reached.
 * Furthermore head-of-line blocking in TCP can cause huge lag spikes in data.
 *
 * Using a custom "reliable" UDP implementation can avoid some of these problems
 * at the cost of high code complexity.  But latency is still bounded by RTT:
 * At best you could get 300 ms, but packetloss is *twice* as likely to kill
 * the NACK or the data now!
 *
 * But with FEC we can avoid TCP overhead and simply drop data when the link
 * fails beyond an expected rate rather than block subsequent data.
 *
 * Assume there is extra room in the channel for error correction symbols:
 * We could just send as many symbols as the link will allow, which would give
 * the best error correction performance.  In practice we would want to send
 * an amount that is reasonable.
 *
 *
 * ==> What are the design decisions for error correction codes?
 *
 * (1) Code Groups : Which packets are covered by which code?
 * (2) Coding Rate : How many symbols to add for each code group?
 *
 *
 * ==> (2) How many additional symbols should we send?
 *
 * If a packet gets lost, sending one additional symbol can fill in for it with
 * high likelihood.  But it also has a small chance of being lost of course,
 * and packetloss tends to be bursty, so it is better to spread error correction
 * symbols over a longer amount of time.
 *
 * If channel packet drop decision can be modeled as an IID uniform random
 * variable, then the loss rate after FEC is applied can be evaluated using
 * equation (3) from:
 * http://www.eurecom.fr/en/publication/489/download/cm-nikane-000618.pdf
 *
 * It seems like the best redundancy should be selected by evaluating equation
 * (3) with several exponents until the estimated loss rate matches the
 * targetted loss rate.  Faster approaches are feasible.
 *
 *
 * ==> (1) How should we interleave/overlap/etc the codes?
 *
 * Since the data is potentially being read from a receiver in real-time, the
 * original data is sent first, followed by the error correction symbols.
 * This means that the original data has a tail of extra symbols that follow it.
 * These extra error correction symbols are sent along with new data for the
 * next code group, overlapping:
 *
 * | <---------------------------- buffer size ----> |
 * | <- in  transit -> |                             |
 * | 11 | 10 | 09 | 08 | 07 | 06 | 05 | 04 | 03 | 02 | 01 | 00 |
 *                  ..   aa   aa   aa   aa   AA   AA   ..
 *        ..   bb   bb   bb   bb   BB   BB   ..
 *   cc   cc   cc   cc   CC   CC   ..
 *
 * Lower-case letters indicate check symbols, and upper-case letters indicate
 * original packets.
 *
 * The encoder keeps (buffer size in bins) / (code group size in bins) = P
 * encoders running in parallel.  Higher P is less efficient, because check
 * symbols sent are about (P-1)x less likely to be part of the code group.
 *
 * So we choose P = 2 and overlap just two encoders!
 *
 *
 * The next question is how large the code groups should be.  If they are bigger
 * than the after-transit buffer then problems occur as shown below:
 *
 * | <---------------------------- buffer size ----> |
 * | <- in  transit -> |                             |
 * | 11 | 10 | 09 | 08 | 07 | 06 | 05 | 04 | 03 | 02 | 01 | 00 |
 *             !!   !!   aa   aa   AA   AA   AA   AA   ..
 *   bb   bb   BB   BB   BB   BB   !!   !!
 *
 * As you can see there are periods (marked with !!) where no check symbols can
 * be sent, or they would be too late.  This is both wasted bandwidth and
 * reducing the windows in which check symbols can be delivered to help.  This
 * is a very bad case to be in.
 *
 *
 * Another non-ideal case is where the code groups are too short:
 *
 * | <---------------------------- buffer size ----> |
 * | <- in  transit -> |                             |
 * | 11 | 10 | 09 | 08 | 07 | 06 | 05 | 04 | 03 | 02 | 01 | 00 |
 *   DD   DD   cc   cc   CC   CC   aa   aa   AA   AA   gg   gg
 *   ee   ee   EE   EE   bb   bb   BB   BB   ff   ff   FF   FF
 *
 * Now it's clear that bandwidth is not being wasted.  However, if a burst loss
 * occurs, it is more likely to wipe out more symbols than can be recovered by
 * the chosen code rate.  For particularly long bursts, the only protection is
 * to make the code groups longer.
 *
 * So it's best to err on the side of code groups that are too short rather
 * than too long, between these two options.
 *
 *
 * When it is perfectly matched:
 *
 * | <---------------------------- buffer size ----> |
 * | <- in  transit -> |                             |
 * | 11 | 10 | 09 | 08 | 07 | 06 | 05 | 04 | 03 | 02 | 01 | 00 |
 *   cc   CC   CC   CC   aa   aa   aa   AA   AA   AA   ..
 *   ..   bb   bb   bb   BB   BB   BB   dd   dd   dd   DD   DD
 *
 * Knowing the transit time for data is essential in estimating how large the
 * code group size should be.  This allows the encoder to avoid sending data
 * that will be useless at the decoder.  This also allows the encoder to make
 * the most of the buffer to prevent bursty losses from affecting the recovery,
 * assuming that the buffer size has been selected to be much larger than burst
 * loss periods.
 *
 * And again, we want to err on the side of short code groups.
 *
 * let RTT_high be a high estimate of the round-trip time.
 * estimate the one-way transit time by RTT_high/2, and so:
 *
 * (code group length) = ((buffer size) - (RTT_high/2)) / 2.1
 *
 * The 2.1 factor and RTT calculation can be modified for realistic scenarios.
 * 
 *
 * ==> Aside from FEC what else do we need?
 *
 * FEC assumes we have a way to tell if a packet arrived corrupted or not.
 * So we need to add a good checksum.
 *
 * Furthermore, each packet needs to be tagged with a unique ID number so that
 * we can tell which code group it is from, for a start.  And we need a way to
 * check if a packet is corrupted that is stronger than the normal (sometimes
 * optional) 16-bit UDP CRC.
 *
 * Happily, it turns out that an authenticated encryption scheme with a stream-
 * cipher and MAC provides security, integrity, and a useful ID number.
 * This means that almost for free we also get secure data transmission.
 *
 * SSL runs over TCP which makes it impractical for data transmission in our
 * case, but it may be useful for a key exchange handshake.
 *
 *
 * ==> Putting it all together
 *
 * Round-trip time must be measured to calculate the rate at which the sender
 * swaps encoders.  Packetloss must be measured to calculate the number of
 * extra check symbols to send.
 *
 * So, periodically the sender should send a flag in a data packet that
 * indicates a "ping."  The receiver should respond as fast as possible to the
 * ping with a "pong" that includes packet loss information.  It helps to set
 * the "ping" flag at the front of a set of data to avoid queuing delays
 * affecting the measured transit time.
 * 
 * The data is encrypted, so each packet has a unique identifier.  The receiver
 * notes gaps in the packet id sequence that last longer than the buffer size
 * as losses.  The collected loss statistics will be sent in "pong" messages.
 *
 * The sender is only sending recovery symbols for one code group at a time, so
 * only one encoder is needed.
 *
 * The receiver can opportunistically apply the decoder when packets get lost.
 * And it only applies the decoder to the most recent code group, so only one
 * decoder instance is needed.
 */



/*
 * Normal Approximation to Bernoulli RV
 *
 * P(X > r), X ~ B(n+r, p)
 *
 * Recall: E[X] = (n+r)*p, SD(X) = sqrt((n+r)*p*(1-p))
 *
 * X is approximated by Y ~ N(mu, sigma)
 * where mu = E[X], sigma = SD(X).
 *
 * And: P(X > r) ~= P(Y >= r + 0.5)
 *
 * For this to be somewhat accurate, np >= 10 and n(1-p) >= 10.
 */

#define INVSQRT2 0.70710678118655

// Precondition: r > 0
// Returns probability of loss for given configuration
double NormalApproximation(int n, int r, double p) {
    const int m = n + r;

    double u = m * p;
    double s = sqrt(u * (1. - p));

    return 0.5 * erfc(INVSQRT2 * (r - u - 0.5) / s);
}

int CalculateApproximate(double p, int n, double Qtarget) {
    double q;
    uint32_t r;

    if (n <= 0) {
        return 0;
    }

    // O(log(N))-time calculator

    // Identify fast 2^i upper bound on required r
    for (r = 1; r; r <<= 1) {
        q = NormalApproximation(n, r, p);

        // If this approximation is close,
        if (q < Qtarget) {
            break;
        }
    }

    // If r-1 is also good,
    if (NormalApproximation(n, r - 1, p) < Qtarget) {
        // Trial-flip bits off from high to low:
        for (uint32_t s = r-- >> 1; s > 0; s >>= 1) {
            // Flip next bit down
            uint32_t t = r ^ s;

            // If this bit was not needed,
            if (NormalApproximation(n, t, p) < Qtarget) {
                // Shave it off
                r = t;
            }
        }
    }

    ++r;

    return r;
}


//// LossEstimator

void LossEstimator::Initialize(float min_loss, float max_loss) {
    _index = 0;
    _count = 0;
    _min_loss = min_loss;
    _max_loss = max_loss;
    _real_loss = 0;
    _clamped_loss = min_loss;
}

void LossEstimator::Insert(uint32_t seen, uint32_t count) {
    // Insert data
    _bins[_index].seen = seen;
    _bins[_index].count = count;

    // Wrap around
    if (++_index >= BINS) {
        _index = 0;
    }

    // If not full yet,
    if (_count < BINS) {
        _count++;
    }
}

void LossEstimator::Calculate() {
    const int len = _count;
    uint64_t seen = 0, count = 0;

    for (int ii = 0; ii < len; ++ii) {
        seen += _bins[ii].seen;
        count += _bins[ii].count;
    }

    if (count > 0) {
        float loss = (float)((count - seen) / (double)count);
        _real_loss = loss;

        // Clamp value
        if (loss < _min_loss) {
            loss = _min_loss;
        } else if (loss > _max_loss) {
            loss = _max_loss;
        }

        _clamped_loss = loss;
    } else {
        _real_loss = 0;
        _clamped_loss = _min_loss;
    }
}


//// CodeGroup

void CodeGroup::Clean(pktalloc::Allocator* allocatorPtr) {
    // Free allocated packet memory
    BatchSet(head, tail).Release(allocatorPtr);
    BatchSet(recovery_head, recovery_tail).Release(allocatorPtr);

    // Zero out state
    //last_update = 0; Does not need to be cleared
    largest_id = 0;
    largest_len = 0;
    block_count = 0;
    //recovery_count = 0; Does not need to be cleared
    original_seen = 0;
    total_seen = 0;
    head = tail = 0;
    recovery_head = recovery_tail = 0;
}

void CodeGroup::AddRecovery(Packet *p) {
    // Insert at head
    if (!recovery_tail) {
        recovery_tail = p;
    }
    p->batch_next = recovery_head;
    recovery_head = p;
}

void CodeGroup::AddOriginal(Packet *p) {
    // Insert into empty list
    if (!head) {
        head = tail = p;
        p->batch_next = 0;
        return;
    }

    const uint32_t id = p->id;

    // Attempt fast O(1) insertion at end
    if (tail && id > tail->id) {
        // Insert at the end
        tail->batch_next = p;
        p->batch_next = 0;
        tail = p;
        return;
    }

    // Search for insertion point from front, shooting for O(1)
    Packet *prev = 0, *next;
    for (next = head; next; next = (Packet*)next->batch_next) {
        if (id < next->id) {
            break;
        }
    }

    // If inserting after prev,
    if (prev) {
        prev->batch_next = p;
    } else {
        head = p;
    }
    if (!next) {
        tail = p;
    }
    p->batch_next = next;
}


//// Encoder

void Encoder::Initialize(pktalloc::Allocator *allocator) {
    Finalize();

    _allocator = allocator;
    _head = 0;
    _tail = 0;
    _original_count = 0;
    _k = 0;
    _m = 0;
    _next_recovery_block = 0;
    _block_bytes = 0;
    _largest = 0;

    _initialized = true;
}

void Encoder::Finalize() {
    if (_initialized) {
        FreeGarbage();
    }
}

void Encoder::Queue(Packet *p) {
    int len = p->len;

    SIAMESE_DEBUG_ASSERT(len > 0);

    std::lock_guard<std::mutex> locker(m_mutex);

    // If this new packet is larger than the previous ones,
    if (_largest < len) {
        // Remember the largest size for when we start emitting check symbols
        _largest = len;
    }

    // Insert at end of list
    if (_tail) {
        _tail->batch_next = p;
    } else {
        _head = p;
    }
    _tail = p;

    _original_count++;
}

void Encoder::EncodeQueued(int m) {
    std::lock_guard<std::mutex> locker(m_mutex);

    LOG("** Started encoding m=%d and k=%d largest bytes=%d", m, _original_count, _largest);

    // Abort if input is invalid
    SIAMESE_DEBUG_ASSERT(m > 0);
    if (m < 1) {
        _m = 0;
        return;
    }

    const int k = _original_count;
    SIAMESE_DEBUG_ASSERT(k < 256);
    if (k <= 0 || k >= 256) {
        _m = 0;
        return;
    }

    // Truncate recovery count if needed (always possible)
    if (k + m > 256) {
        m = 256 - k;
    }

    // Optimization: If k = 1,
    if (k == 1) {
        int len = _largest;

        LOG("Encoding queued k = 1 special case len=%d", _largest);
        SIAMESE_DEBUG_ASSERT(_head != 0);
        SIAMESE_DEBUG_ASSERT(_head->len == len);

        _k = 1; // Treated specially during generation
        _block_bytes = len;

        _buffer.SetSize_NoCopy(len);

        // Correct for packet that has stats attached
        uint8_t *pkt = _head->data;
        if (pkt[2] == 0x81) {
            pkt += 9;
        }

        memcpy(_buffer.GetPtr(), pkt + ORIGINAL_OVERHEAD, len);
    } else {
        SIAMESE_DEBUG_ASSERT(_largest > 0);

        // Calculate block size
        int block_size = 2 + _largest;

        // Round up to the nearest multiple of 8
        block_size = (uint32_t)(block_size + 7) & ~(uint32_t)7;

        SIAMESE_DEBUG_ASSERT(block_size % 8 == 0);

        const uint8_t *data_ptrs[256];
        int index = 0;

        // Massage data for use in codec
        for (Packet *p = _head; index < k && p; p = (Packet*)p->batch_next, ++index) {
            uint8_t *pkt = p->data + ORIGINAL_OVERHEAD - 2;
            uint16_t len = p->len;

            // Correct for packet that has stats attached
            if (pkt[-1] == 0x81) {
                pkt += 9;
            }

            // Setup data pointer
            data_ptrs[index] = pkt;

            // Prefix data by its length
            WriteU16_LE(pkt, len);

            // Pad message up to the block size with zeroes
            memset(pkt + len + 2, 0, block_size - (len + 2));
        }

        SIAMESE_DEBUG_ASSERT(index == k);

        // Set up encode buffer to receive the recovery blocks
        _buffer.SetSize_NoCopy(m * block_size);

        // Produce recovery blocks
        int encodeResult = cauchy_256_encode(k, m, data_ptrs, _buffer.GetPtr(), block_size);
        SIAMESE_DEBUG_ASSERT(0 == encodeResult);

        // Start from from of encode buffer
        _next_recovery_block = 0;

        // Store block size
        _block_bytes = block_size;

        // Store parameters
        _m = m;
        _k = k;
    }

    // Reset encoder queuing:

    FreeGarbage();

    _original_count = 0;
    _largest = 0;
}

// Returns 0 if recovery blocks cannot be sent yet
int Encoder::GenerateRecoveryBlock(uint8_t *pkt) {
    const int block_bytes = _block_bytes;

    //CAT_IF_DUMP(cout << "<< Generated recovery block id = " << _next_recovery_block << " block_bytes=" << _block_bytes << endl);

    // Optimization: If k = 1,
    if (_k == 1) {
        LOG("Writing k = 1 special form len=%d", block_bytes);

        // Write special form
        pkt[0] = 1;
        pkt[1] = 0;
        memcpy(pkt + 2, _buffer.GetPtr(0), block_bytes);

        return 2 + block_bytes;
    }

    // If ran out of recovery data to send,
    if (_next_recovery_block >= _m) {
        return 0;
    }

    const int index = _next_recovery_block++;

    // Write header
    pkt[0] = (uint8_t)(_k + index);
    pkt[1] = (uint8_t)(_k - 1);
    pkt[2] = (uint8_t)(_m - 1);

    const uint8_t *src = _buffer.GetPtr() + block_bytes * index;

    // Write data
    memcpy(pkt + 3, src, block_bytes);

    // Return bytes written
    return 3 + block_bytes;
}


//// Shorthair : Encoder

// Send a check symbol
bool Shorthair::SendCheckSymbol() {
    uint8_t *pkt = _sym_buffer.GetPtr();
    int len = _encoder.GenerateRecoveryBlock(pkt + 3);

    // If no data to send,
    if (len <= 0) {
        return false;
    }

    // Insert next sequence number
    WriteU16_LE(pkt, _out_seq++);

    // Prepend the code group
    pkt[2] = _code_group & 0x7f;

    _settings.interface_ptr->SendData(pkt, len + 3);

    return true;
}

void Shorthair::UpdateLoss(uint32_t seen, uint32_t count) {
    SIAMESE_DEBUG_ASSERT(seen <= count);
    if (seen > count) {
        // Ignore invalid data
        return;
    }

    if (count > 0) {
        _loss.Insert(seen, count);
        _loss.Calculate();
    }
}

void Shorthair::OnOOB(uint8_t flags, uint8_t *pkt, int len) {
    // If it contains a pong message,
    if (flags & 1) {
        // If truncated,
        SIAMESE_DEBUG_ASSERT(len >= 8);
        if (len < 8) {
            return;
        }

        // Update stats
        uint32_t seen = ReadU32_LE(pkt);
        uint32_t count = ReadU32_LE(pkt + 4);
        UpdateLoss(seen, count);

        LOG("++ Updating loss stats from OOB header: %d / %d", seen, count);

        pkt += 8;
        len -= 8;

        // If it contains other data too,
        if (len > 0) {
            // If out of band,
            if (pkt[0] & 0x80) {
                OnOOB(0, pkt + 1, len - 1);
                // NOTE: Does not allow attacker to cause more recursion
            } else {
                OnData(pkt, len);
            }
        }
    } else {
        LOG("Delivering OOB data of length %d and type = %d", len, (int)pkt[0]);

        // Pass OOB data to the interface
        _settings.interface_ptr->OnOOB(pkt, len);
    }
}


//// Shorthair : Decoder

void Shorthair::RecoverGroup(CodeGroup *group) {
    // The block size will be the largest data chunk we have
    const int block_size = group->largest_len;
    const int k = group->block_count;

    int index = 0;
    Block blocks[256];

    // Add original packets
    for (Packet *op = group->head; op; op = (Packet*)op->batch_next) {
        // We need to pad it out to the block size with zeroes.
        // Get length of original packet
        uint16_t op_len = ReadU16_LE(op->data);

        // Clear everything after length + original data with zeroes
        memset(op->data + 2 + op_len, 0, block_size - (op_len + 2));

        // Fill in block for codec
        blocks[index].data = op->data;
        blocks[index].row = (uint8_t)op->id;

        ++index;
    }

    SIAMESE_DEBUG_ASSERT(index == group->original_seen);

    // Add recovery packets up to k
    for (Packet *rp = group->recovery_head; index < k && rp; rp = (Packet*)rp->batch_next) {
        // Fill in block for codec
        blocks[index].data = rp->data;
        blocks[index].row = (uint8_t)rp->id;

        ++index;
    }

    const int m = group->recovery_count;

    SIAMESE_DEBUG_ASSERT(k + m <= 256);
    SIAMESE_DEBUG_ASSERT(index == k);

    LOG("CRS decode with k=%d, m=%d block_size=%d, #originals=%d", k, m, block_size, group->original_seen);

    // Decode the data
    int decodeResult = cauchy_256_decode(k, m, blocks, block_size);
    SIAMESE_DEBUG_ASSERT(0 == decodeResult);

    // For each recovery packet,
    for (int ii = group->original_seen; ii < k; ++ii) {
        // The data was decoded in-place
        uint8_t *src = blocks[ii].data;
        int len = ReadU16_LE(src);

        SIAMESE_DEBUG_ASSERT(len <= block_size - 2);

        if (len <= block_size - 2) {
            _settings.interface_ptr->OnPacket(src + 2, len);
        }
    }

    group->Clean(&_allocator);
    group->MarkDone();
}

// On receiving a data packet
void Shorthair::OnData(uint8_t *pkt, int len) {
    if (len <= PROTOCOL_OVERHEAD) {
        return;
    }

    // Reconstruct 8-bit group number from 7-bit input
    const Counter<uint8_t, 7> partial_group = pkt[0];
    const Counter8 ref_group = _last_group;
    const Counter8 reconstructed_group = Counter8::ExpandFromTruncated(ref_group, partial_group);

    const int code_group = reconstructed_group.ToUnsigned();
    CodeGroup *group = &_groups[code_group];
    _last_group = code_group;

    // If the group is old,
    if ((uint32_t)(_last_tick - group->last_update) > GROUP_TIMEOUT) {
        group->Clean(&_allocator);

        LOG("~~ Opening group %d", (int)code_group);
    } else if (group->IsDone()) {
        // Group is already finished (ignore remaining)
        LOG("~~ Ignoring extra data for group %d", (int)code_group);
        return;
    }

    // Set last group update time
    group->last_update = _last_tick;

    int id = (uint32_t)pkt[1];
    int block_count = (uint32_t)pkt[2] + 1;

    uint8_t *data = pkt + 3;
    int data_len = len - 3;

    LOG("~~ ACTUAL GOT id %d bc %d cg %d", id, block_count, (int)code_group);

    // If block count is not the largest seen for this group,
    if (block_count < group->block_count) {
        // Use the latest
        block_count = group->block_count;
    } else {
        // Update largest block count seen for group
        group->block_count = block_count;
    }

    // If packet contains original data,
    if (id < block_count) {
        if (data_len > _settings.max_data_size)
        {
            SIAMESE_DEBUG_BREAK(); // Larger than max
            return;
        }

        LOG("~~ GOT id %d bc %d cg %d", id, block_count, (int)code_group);
        // Process it immediately
        _settings.interface_ptr->OnPacket(data, data_len);

        // Increment original seen count
        group->original_seen++;

        // Packet that will contain this data
        Packet *p = (Packet*)_allocator.Allocate(sizeof(Packet) + 2 + _settings.max_data_size);
        p->batch_next = 0;

        // Store ID in id/len field
        p->id = id;

        // Store packet, prepending length.
        // NOTE: We cannot efficiently pad with zeroes yet because we do not
        // necessarily know what the largest packet length is yet.  And anyway
        // we may not need to pad at all if no loss occurs.
        WriteU16_LE(p->data, data_len);
        memcpy(p->data + 2, data, data_len);

        // Insert it into the original packet list
        group->AddOriginal(p);
    } else {
        if (data_len > 2 + 1 + _settings.max_data_size)
        {
            SIAMESE_DEBUG_BREAK(); // Larger than max
            return;
        }

        if (group->original_seen >= block_count) {
            LOG("~~ Closing group %d: Just noticed all originals are received", (int)code_group);

            // See above: Original data gets processed immediately
            group->Clean(&_allocator);
            group->MarkDone();
            return;
        } else if (block_count == 1) {
            LOG("~~ Closing group %d: Special case k = 1 and a redundant packet won", (int)code_group);

            SIAMESE_DEBUG_ASSERT(group->original_seen == 0);

            _settings.interface_ptr->OnPacket(data, data_len);

            group->Clean(&_allocator);
            group->MarkDone();
            return;
        }

        // If ID is the largest seen so far,
        if (id > group->largest_id) {
            // Update largest seen ID for decoding ID in next packet
            group->largest_id = id;
        }

        // Pull in codec parameters
        group->largest_len = data_len - 1;
        group->recovery_count = (uint32_t)data[0] + 1;

        // Packet that will contain this data
        Packet *p = (Packet*)_allocator.Allocate(sizeof(Packet) + 2 + _settings.max_data_size);
        p->batch_next = 0;

        // Store ID in id/len field
        p->id = id;

        // Store recovery packet, which has length included (encoded)
        memcpy(p->data, data + 1, data_len - 1);

        // Insert it into the recovery packet list
        group->AddRecovery(p);
    }

    // Increment total seen count
    group->total_seen++;

    // If recovery is now possible for this group,
    if (group->CanRecover()) {
        LOG("~~ Closing group %d: Recovered!", (int)code_group);

        RecoverGroup(group);
    } // end if group can recover
}


//// Shorthair: Interface

// On startup:
bool Shorthair::Initialize(const Settings &settings) {
    Finalize();

    cauchy_256_init();

    _settings = settings;

    if (_settings.max_data_size > MAX_CHUNK_SIZE)
    {
        SIAMESE_DEBUG_BREAK(); // Invalid input
        return false;
    }

    const int buffer_size = SHORTHAIR_OVERHEAD + _settings.max_data_size;

    // Allocate recovery packet workspace
    _sym_buffer.SetSize_NoCopy(buffer_size);
    _oob_buffer.SetSize_NoCopy(buffer_size);

    _encoder.Initialize(&_allocator);

    _loss.Initialize(SHORTHAIR_MIN_LOSS_ESTIMATE, SHORTHAIR_MAX_LOSS_ESTIMATE);

    _redundant_count = 0;
    _redundant_sent = 0;

    _last_swap_time = 0;
    _code_group = 0;

    _last_group = 0;

    _out_seq = 0;
    _send_stats = false;
    _last_stats = 0;

    _stats.Initialize();

    // Clear group data
    memset(_groups, 0, sizeof(_groups));

    _initialized = true;

    return true;
}

// Cleanup
void Shorthair::Finalize() {
    if (_initialized) {
        // NOTE: The allocator object will free allocated memory in its dtor

        _encoder.Finalize();

        _initialized = false;
    }
}

// Send original data
void Shorthair::Send(const void *data, int len) {
    if (len > _settings.max_data_size)
    {
        SIAMESE_DEBUG_BREAK(); // Invalid input
        return;
    }

    // Allocate sent packet buffer
    Packet *p = (Packet*)_allocator.Allocate(sizeof(Packet) + 2 + _settings.max_data_size);
    p->batch_next = 0;
    p->len = len;

    uint8_t *pkt = p->data;
    int pkt_len = len + ORIGINAL_OVERHEAD;

    // Insert sequence number at the front
    WriteU16_LE(pkt, _out_seq++);

    // If time to send stats,
    if (_send_stats) {
        _send_stats = false;

        // Attach stats to the front
        pkt[2] = 0x81;
        WriteU32_LE(pkt + 3, _stats.GetSeen());
        WriteU32_LE(pkt + 7, _stats.GetTotal());

        pkt += 11;
        pkt_len += 9;
    } else {
        pkt += 2;
    }

    // Add next code group (this is part of the code group after the next swap)
    const uint8_t code_group = _code_group + 1;
    pkt[0] = code_group & 0x7f;

    const uint8_t id = (uint8_t)_encoder.GetCurrentCount();

    // Add check symbol number
    pkt[1] = id; // id of packet

    // For original data send the current block count, which will
    // always be one ahead of the block ID.
    // NOTE: This allows the decoder to know when it has received
    // all the packets in a code group for the zero-loss case.
    pkt[2] = id; // k - 1

    // Copy input data into place
    memcpy(pkt + 3, data, len);

    // Transmit
    _settings.interface_ptr->SendData(p->data, pkt_len);

    // Queue after sending to avoid lock latency
    _encoder.Queue(p);
}

// Send an OOB packet, first byte is type code
void Shorthair::SendOOB(const uint8_t *data, int len) {
    SIAMESE_DEBUG_ASSERT(len > 0);
    SIAMESE_DEBUG_ASSERT(1 + len <= _oob_buffer.GetSize());

    uint8_t *pkt = _oob_buffer.GetPtr();
    uint8_t *pkt_front = pkt;
    int pkt_len = len + 3;

    // Insert sequence number at the front
    WriteU16_LE(pkt, _out_seq++);

    // If time to send stats,
    if (_send_stats) {
        _send_stats = false;

        // Attach stats to the front
        pkt[2] = 0x81;
        WriteU32_LE(pkt + 3, _stats.GetSeen());
        WriteU32_LE(pkt + 7, _stats.GetTotal());

        pkt += 11;
        pkt_len += 9;
    } else {
        pkt += 2;
    }

    // Mark OOB
    pkt[0] = 0x80;

    // Copy input data into place
    memcpy(pkt + 1, data, len);

    // Transmit
    _settings.interface_ptr->SendData(pkt_front, pkt_len);
}

// Called once per tick, about 10-20 ms
void Shorthair::Tick() {
    const uint32_t now = siamese::GetTimeMsec();

    _last_tick = now;

    const int recovery_time = now - _last_swap_time;
    int expected_sent = _redundant_count;
    uint32_t max_delay = _settings.max_delay;

    // If it is time to send stats again,
    if ((uint32_t)(now - _last_stats) > (uint32_t)STAT_TRANSMIT_INTERVAL) {
        _last_stats = now;

        // If stats still not sent from last time,
        if (_send_stats) {
            uint8_t pkt[11];

            // Insert sequence number at the front
            WriteU16_LE(pkt, _out_seq++);

            pkt[2] = 0x81;
            WriteU32_LE(pkt + 3, _stats.GetSeen());
            WriteU32_LE(pkt + 7, _stats.GetTotal());

            // Transmit
            _settings.interface_ptr->SendData(pkt, 11);
        }

        // Calculate new stats
        _stats.Calculate();

        LOG("******** COLLECTED STATS = %d %d", _stats.GetSeen(), _stats.GetTotal());

        _send_stats = true;
    }

    // If not swapping the encoder this tick,
    if ((uint32_t)recovery_time < max_delay) {
        int elapsed = ((_redundant_count + 1) * recovery_time) / max_delay;

        // Pick min(_redundant_count, elapsed)
        if (expected_sent > elapsed) {
            expected_sent = elapsed;
        }
    }

    // Calculate number of redundant symbols to send right now
    const int send_count = expected_sent - _redundant_sent;

    // If there are any new packets to send,
    if (send_count > 0) {
        // For each check packet to send,
        for (int ii = 0; ii < send_count; ++ii) {
            if (!SendCheckSymbol()) {
                break;
            }

            ++_redundant_sent;
        }
    }

    // If it is time to swap the encoder,
    if ((uint32_t)recovery_time >= max_delay) {
        _last_swap_time = now;

        // Packet count
        const int N = _encoder.GetCurrentCount();

        if (N > 0) {
            // Calculate number of redundant packets to send this time

            const float plr = _loss.GetClamped();

            // If in region where approximation works:
            int R;
            if (((N * plr >= 10.f && N * (1 - plr) >= 10.f)))
            {
                R = CalculateApproximate(plr, N, 0.001f);
            }
            else
            {
                R = N * 3 * plr;
            }

            // If there's a reasonable amount of data being sent:
            if (N >= 3)
            {
                float overheadRate = R / (float)N;

                // If trying to send too much:
                if (overheadRate > 0.5f)
                {
                    R = N * 1.5f + 1;
                }
                // If not sending enough:
                else if (overheadRate < _settings.min_fec_overhead)
                {
                    R = N * (1.f + _settings.min_fec_overhead);
                }

                // Send at least two packets per swap interval
                if (R < 2)
                {
                    R = 2;
                }
            }
            else
            {
                // Send no more than 2 for N < 3
                R = 2;
            }

            // NOTE: These packets will be spread out over the swap interval
            _redundant_count = R;
            _redundant_sent = 0;

            // Select next code group
            _code_group++;

            LOG("New code group %d: N = %d R = %d loss=%f[acted on %f]", (int)_code_group, N, R, _loss.GetReal(), _loss.GetClamped());

            // Encode queued data now
            _encoder.EncodeQueued(R);
        }
    }
}

// On packet received
void Shorthair::Recv(void *vpkt, int len) {
    uint8_t *pkt = static_cast<uint8_t*>( vpkt );

    // If the header is not truncated,
    SIAMESE_DEBUG_ASSERT(len >= 3);
    if (len >= 3) {
        // Read 16-bit sequence number from the front
        uint16_t seq = ReadU16_LE(pkt);

        // If out of band,
        if (pkt[2] & 0x80) {
            OnOOB(pkt[2], pkt + 3, len - 3);
        } else {
            OnData(pkt + 2, len - 2);
        }

        // Update stats
        _stats.Update(seq);
    }
}

}} // namespace cat::Shorthair
