#include "wirehair/Wirehair.hpp"
#include "calico/Calico.hpp"
#include "Clock.hpp"
#include "Delegates.hpp"
#include "Enforcer.hpp"
#include "EndianNeutral.hpp"
#include "ReuseAllocator.hpp"
#include "BitMath.hpp"
#include "SmartArray.hpp"
#include "Thread.hpp"
#include "WaitableFlag.hpp"
#include "Mutex.hpp"
using namespace cat;

#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cmath>
using namespace std;


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
 * Using Reed-Solomon codes can achieve high-performance at FIXED code rates.
 * Furthermore they need to be designed with a FIXED number of packets ahead of
 * time, which means that in practice people have been writing *many* RS codes
 * and selecting between them for a single application.  And it all needs to be
 * rewritten when requirements change.
 *
 * Wirehair/RaptorQ improves on this, allowing us to use only as much bandwidth
 * as needed, covering any number of packets required.  These are "rateless"
 * codes that require an acceptable amount of performance loss compared to
 * RS-codes, and offering optimal use of the channel and lower latency compared
 * to ARQ-based approaches.
 *
 *
 * ==> Using UDP means we have to implement flow control right??
 *
 * Thankfully the data is constant-rate so there is no need for a
 * heavy-weight flow control algorithm.  We can just send data on a timer.
 * It doesn't need to be the same number of packets each time.
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
 * Wirehair's encoder uses a roughly linear amount of memory and time based on
 * the size of the input, so running multiple encoders is efficient.
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
 * This gives us the number of packets to include in each group, and the data
 * encoder just alternates between two Wirehair instances, feeding one and
 * generating check symbols from the other.
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
 * Brook Protocol
 *
 * This protocol implements a two-way FEC/UDP stream.  Another control channel
 * must be used for secret key agreement and connection/disconnection events.
 *
 * Brook provides channel modeling, security, and error correction.  It allows
 * you to take any UDP/IP data stream and dial the packet loss rate down as low
 * as you like, while preventing tampering, and providing live numbers for loss
 * and latency.
 *
 * On top of Brook you can build any number of other transport protocols
 * involving ordered-reliable, ordered-unreliable, and unordered-unreliable
 * combinations.  As a black box you can treat Brook as a protocol like UDP/IP.
 * It can still lose packets and they can arrive out of order, but the rate at
 * which the packets are lost is much lower, while introducing no additional
 * latency into the transmission.  When a packet gets lost then the receiver
 * needs to wait for recovery symbols to be provided, but this is much faster
 * than waiting for ARQ-style recovery.
 *
 * ARQ can be built effectively on top of Brook producing a hybrid scheme that
 * has very low average latency and guaranteed delivery.
 *
 * The average extra bandwidth required seems to be roughly +10% for moderate-
 * rate streams, but I need to do formal benchmarking.
 *
 *
 * Source -> Sink data packet format:
 *
 * <OOB[1 bit = 0] | group[7 bits]> (brook-wirehair) : Out of band flag = 0
 * <block count[2 bytes]> (brook-wirehair)
 * <block id[2 bytes]> (brook-wirehair)
 * <block size[2 bytes]> (brook: Only for recovery packets)
 * {...block data...}
 * <MAC[8 bytes]> (calico)
 * <IV[3 bytes]> (calico)
 *
 * MAC+IV are used for Calico encryption (11 bytes overhead).
 * Group: Which code group the data is associated with.
 * N = Block count: Total number of original data packets in this code group.
 * I = Block id: Identifier for this packet.
 *
 * In this scheme,
 * 		I < N are original, and
 * 		I >= N are Wirehair recovery packets.
 *
 * The Block ID uses a wrapping counter that reduces an incrementing 32-bit
 * counter to a 16-bit counter assuming that packet re-ordering does not exceed
 * 32768 consecutive packets.  (IV works similarly to recover a 64-bit ID)
 *
 * Total overhead = 16 bytes per original packet.
 *
 *
 * Sink -> Source out-of-band packet format:
 *
 * <OOB[1 bit = 1] | group[7 bits]> : Out of band flag = 1
 * <packet type[1 byte]>
 *
 * Packet types:
 * group = input group
 * <packet type[1 byte] = 0xff>
 * <seen count[4 bytes]>
 * <total count[4 bytes]>
 *
 * This message is sent in reaction to a new code group on the receipt of the
 * first original data packet to update the source's redundancy in reaction to
 * measured packet loss as seen at the sink and to measure the round-trip time
 * for deciding how often to switch codes.
 *
 *
 * Out of band types are delivered to your callback.
 */


static const int SKEY_BYTES = 32;
static const int PROTOCOL_OVERHEAD = 1 + 2 + 2;
static const int ORIGINAL_OVERHEAD = PROTOCOL_OVERHEAD + calico::Calico::OVERHEAD;
static const int RECOVERY_OVERHEAD = PROTOCOL_OVERHEAD + 2 + calico::Calico::OVERHEAD;
static const int BROOK_OVERHEAD = RECOVERY_OVERHEAD; // 18 bytes + longest packet size for recovery packets
static const int PONG_SIZE = 1 + 1 + 4 + 4;
static const int MAX_CHUNK_SIZE = 65535; // Largest allowed packet chunk size
static const u8 PAST_GROUP_THRESH = 127; // Group ID wrap threshold


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

int CalculateRedundancy(double p, int n, double Qtarget) {
	// TODO: Skip values of r to speed this up
	int r = 0;
	double q;

	do {
		++r;
		q = NormalApproximation(n, r, p);
	} while (q > Qtarget);

	++r;

	// Add one extra symbol to fix error of approximation
	if (n * p < 10. || n * (1 - p) < 10.) {
		++r;
	}

	return r;
}


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
	void Initialize(float min_loss) {
		_index = 0;
		_count = 0;
		_min_loss = min_loss;
		_loss = min_loss;
	}

	void Insert(u32 seen, u32 count) {
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

	// Pick estimated loss based on history
	void Calculate() {
		const int len = _count;
		u64 seen = 0, count = 0;

		for (int ii = 0; ii < len; ++ii) {
			seen += _bins[ii].seen;
			count += _bins[ii].count;
		}

		_loss = (float)((count - seen) / (double)count);

		// Clamp value
		if (_loss < _min_loss) {
			_loss = _min_loss;
		}

		// TODO: Validate that this is a good predictor
	}

	float Get() {
		return _loss;
	}
};


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
	void Initialize(int min_delay, int max_delay) {
		_index = 0;
		_count = 0;
		_min_delay = min_delay;
		_max_delay = max_delay;
		_delay = min_delay;
	}

	void Insert(int delay) {
		// Insert data
		_bins[_index].delay = delay;

		// Wrap around
		if (++_index >= BINS) {
			_index = 0;
		}

		// If not full yet,
		if (_count < BINS) {
			_count++;
		}
	}

	// Pick estimated upper-bound on one-way s2c delay based on history
	void Calculate() {
		u64 sum = 0;
		const int len = _count;

		for (int ii = 0; ii < len; ++ii) {
			int delay = _bins[ii].delay;

			sum += delay;
		}

		_delay = (int)(sum / len);

		if (_delay < _min_delay) {
			_delay = _min_delay;
		} else if (_delay > _max_delay) {
			_delay = _max_delay;
		}

		// TODO: Validate that this is a good predictor
	}

	int Get() {
		return _delay;
	}
};



class IBrookInterface {
public:
	// Called with the latest data packet from remote host
	virtual void OnPacket(void *packet, int bytes) = 0;

	// Called with the latest OOB packet from remote host
	virtual void OnOOB(const u8 *packet, int bytes) = 0;

	// Send raw data to remote host over UDP socket
	virtual void SendData(void *buffer, int bytes) = 0;
};



struct BrookSettings {
	// Did currrent Brook instance initiate the data flow?
	// Each side of the channel needs to pick an opposite role to ensure that
	// the encryption works properly.
	bool initiator;				// true = Client mode, false = Server mode

	// Good default: 0.0001
	double target_loss;			// Target packet loss rate

	// Good default: 0.03
	float min_loss;				// [0..1] packetloss probability lower limit

	// Good default: 100 ms ... 2000 ms
	int min_delay, max_delay;	// Milliseconds clamp values for delay estimation

	// Good default: 1350 bytes
	int max_data_size;			// Maximum data size in bytes

	// Implement this interface to allow Brook to send and deliver packets
	IBrookInterface *interface;	// Interface
};


struct Packet : BatchHead {
	// Block ID/Length for this packet
	u32 id_or_len;

	// Data follows
	u8 data[1];
};


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
			_allocator.ReleaseBatch(BatchSet(_group_head, _group_tail));
		}
	}

	virtual bool Entrypoint(void *param) {
		while (!_kill) {
			_wake.Wait();
			if (!_kill) {
				Process();
			}
		}

		return true;
	}

	void Process() {
		AutoMutex lock(_processing_lock);

		// Byte per data chunk
		int chunk_size = _group_largest;
		int block_count = _group_count;

		CAT_ENFORCE(block_count > 1 && chunk_size > 0);

		// NOTE: Blocks are chunks with 2-byte lengths prepended
		int block_size = 2 + chunk_size;
		_group_block_size = block_size;

		// Calculate size of encoded messages
		u32 message_size = block_count * block_size;

		// Grow buffer
		_encode_buffer.resize(message_size);

		// For each sent packet,
		u8 *buffer = _encode_buffer.get();
		for (Packet *p = _group_head; p; p = (Packet*)p->batch_next) {
			u16 size = p->size;

			// Start each block off with the 16-bit size
			*(u16*)buffer = getLE(size);
			buffer += 2;

			// Add packet data in
			memcpy(buffer, p->data + PROTOCOL_OVERHEAD, size);

			// Zero the high bytes
			CAT_CLR(buffer + size, chunk_size - size);

			// On to the next
			buffer += chunk_size;
		}

		// NOTE: After this function call, the input data can be safely modified so long
		// as Encode() requests come after the original data block count.
		CAT_ENFORCE(!_encoder.BeginEncode(_encode_buffer.get(), message_size, block_size));

		_next_block_id = block_count;

		// Avoid re-ordering writes by optimizer at compile time
		CAT_FENCE_COMPILER;

		_encoder_ready = true;
	}

public:
	CAT_INLINE EncoderThread() {
		_initialized = false;
	}
	CAT_INLINE virtual ~EncoderThread() {
		Finalize();
	}

	void Initialize(ReuseAllocator *allocator) {
		Finalize();

		_allocator = allocator;

		_kill = false;
		_last_garbage = false;
		_encoder_ready = false;
		_next_block_id = 0;
		_largest = 0;
		_block_count = 0;
		_sent_head = _sent_tail = 0;

		StartThread();

		_initialized = true;
	}

	void Finalize() {
		if (_initialized) {
			_kill = true;

			_wake.Set();

			WaitForThread();

			FreeGarbage();

			_initialized = false;
		}
	}

	Packet *Queue(int len) {
		CAT_ENFORCE(len > 0);

		// Allocate sent packet buffer
		Packet *p = _allocator.AcquireObject<Packet>();
		p->id_or_len = len;

		// If this new packet is larger than the previous ones,
		if (_largest < len) {
			// Remember the largest size for when we start emitting check symbols
			_largest = len;
		}

		// Insert at end of list
		if (_sent_tail) {
			_sent_tail->batch_next = p;
		} else {
			_sent_head = p;
		}
		_sent_tail = p;
		p->batch_next = 0;

		++_block_count;

		CAT_ENFORCE(_block_count <= CAT_WIREHAIR_MAX_N);

		return p;
	}

	CAT_INLINE int GetCurrentCount() {
		return _block_count;
	}

	void EncodeQueued() {
		// Hold processing lock to avoid calling this too fast
		AutoMutex lock(_processing_lock);

		// NOTE: After N = 1 case, next time encoding starts it will free the last one
		FreeGarbage();

		// Flag encoder as being busy processing previous data
		_encoder_ready = false;

		// Move code group profile into private memory
		_group_largest = _largest;
		_group_count = _block_count;
		_group_head = _sent_head;
		_group_tail = _sent_tail;

		// Flag garbage for takeout
		_last_garbage = true;

		// Clear the shared workspace for new data
		_largest = 0;
		_block_count = 0;
		_sent_head = _sent_tail = 0;

		// If N = 1,
		if (_block_count <= 1) {
			// Set up for special mode
			_encoder_ready = true;
			_group_block_size = _group_largest;
		} else {
			// Wake up the processing thread
			_wake.Set();
		}
	}

	// Returns false if recovery blocks cannot be sent yet
	int GenerateRecoveryBlock(u8 *buffer) {
		if (!_encoder_ready) {
			return 0;
		}

		// Get next block ID to send
		u32 block_id = _next_block_id++;

		// Add low bits of check symbol number
		*(u16*)buffer = getLE((u16)block_id);

		// Add block count
		*(u16*)(buffer + 2) = getLE((u16)_group_count);

		if (_group_count == 1) {
			// Copy original data directly
			memcpy(buffer + 4, _group_head->data + PROTOCOL_OVERHEAD, _group_block_size);
		} else {
			CAT_ENFORCE(_group_block_size == _encoder.Encode(block_id, buffer + 4));

			FreeGarbage();
		}

		return 4 + _group_block_size;
	}
};


struct CodeGroup {
	// Is code group open?
	bool open;

	// Is code group completely passed?
	bool done;

	// Timestamp on first packet for this group
	u32 open_time;

	// Largest ID seen for each code group, for decoding the ID
	u32 largest_id;

	// Largest seen block count for each code group
	u16 block_count;

	// Received symbol counts
	u16 original_seen;
	u16 total_seen;

	// Recovery symbols
	Packet *head, *tail;

	void Open(u32 ms) {
		open = true;
		done = false;
		open_time = ms;
		largest_id = 0;
		block_count = 0;
		original_seen = 0;
		total_seen = 0;
		head = 0;
		tail = 0;
	}

	bool CanRecover() {
		// If block count is still unknown,
		if (block_count <= 0) {
			return false;
		}

		// If recovery is possible,
		return total_seen >= block_count;
	}

	void Close(ReuseAllocator &allocator) {
		open = false;
		done = true;

		// Free allocated packet memory O(1)
		allocator.ReleaseBatch(BatchSet(head, tail));
	}

	void Add(Packet *p) {
		++total_seen;

		// Insert at head
		if (head) {
			p->batch_next = head;
		} else {
			head = tail = p;
		}
		head = p;
	}
};


class Brook {
	// Initialized flag
	bool _initialized;

	// Timekeeping
	Clock _clock;

	// Settings object
	BrookSettings _settings;

	// Packet buffers are allocated with room for the protocol overhead + data
	ReuseAllocator _allocator;

	// Encryption
	calico::Calico _cipher;

private:
	//// Encoder

	EncoderThread _encoder;

	// Statistics
	DelayEstimator _delay;
	LossEstimator _loss;

	// Code group currently being sent
	u8 _code_group;

	// Swap times for each code group for RTT calculation
	u32 _group_stamps[256];

	// Packet workspace buffer
	SmartArray<u8> _packet_buffer;

	// Rate of swapping and redundant symbol counter
	u32 _swap_interval;
	u32 _last_swap_time;
	int _redundant_count, _redundant_sent;

protected:
	// Send a check symbol
	bool SendCheckSymbol() {
		u8 *buffer = _packet_buffer.get();
		int bytes = _encoder.GenerateRecoveryBlock(buffer + 1);

		// If no data to send,
		if (bytes <= 0) {
			// Abort
			return false;
		}

		// Prepend the code group
		buffer[0] = _code_group;

		// Encrypt
		bytes = _cipher.Encrypt(buffer, 1 + bytes, buffer, _packet_buffer.size());

		// Transmit
		_settings.source->SendData(buffer, bytes);

		return true;
	}

	// Calculate interval from delay
	void CalculateInterval() {
		int delay = _delay.Get();

		// From previous work: Ideal buffer size = delay + swap interval * 2

		// Reasoning: We want to be faster than TCP for recovery, and
		// ARQ recovery speed > 3x delay : data -> ack -> retrans
		// Usually there's a timeout also but let's pretend it's ideal ARQ.

		// Crazy idea:
		// So our buffer size should be 3x delay.
		// So our swap interval should be about equal to delay.

		// Note that if delay is long, we only really need to have a swap
		// interval long enough to cover burst losses so this may be an
		// upper bound for some cases of interest.

		// Idea: Give it at least 100 milliseconds of buffering before a swap
		if (delay < 100) {
			delay = 100;
		}

		_swap_interval = delay;
	}

	// From pong message, round-trip time
	CAT_INLINE void UpdateRTT(int ms) {
		CAT_ENFORCE(ms >= 0);

		// Approximate delay with RTT / 2.
		// TODO: Adjust to match the asymmetry of your channel,
		// or use exact time measurements when available instead.
		int delay = ms / 2;

		_delay.Insert(delay);
		_delay.Calculate();

		CalculateInterval();
	}

	// From pong message, number of packets seen out of count in interval
	CAT_INLINE void UpdateLoss(u32 seen, u32 count) {
		CAT_ENFORCE(seen <= count);

		if (count > 0) {
			_loss.Insert(seen, count);
			_loss.Calculate();
		}
	}

private:
	//// Decoder

	// Is decoder active?
	bool _decoding;

	// NOTE: Using codec directly since we want to regenerate blocks instead of whole messages
	wirehair::Codec _decoder;

	// Next expected code group
	u8 _largest_group;

	// Statistics since the last pong
	u32 _seen, _count;

	// Code groups
	CodeGroup _groups[256];

	// On receiving a data packet
	void OnData(u8 *pkt, int len) {
		// Read packet data
		u8 code_group = ReconstructCounter<7, u8>(_largest_group, pkt[0] & 0x7f);

		u32 id = getLE(*(u16*)(pkt + 1));
		u16 block_count = getLE(*(u16*)(pkt + 1 + 2));
		u8 *data = pkt + PROTOCOL_OVERHEAD;

		// If group is not open yet,
		if (!group->open) {
			// Open group
			group->Open(ms);
		}

		// Update known block count
		if (block_count < group->block_count) {
			block_count = group->block_count;
		} else {
			group->block_count = block_count;
		}

		// Attempt to fill in block count if it is already known
		if (block_count == 0) {
			block_count = group->block_count;
		}

		// Reconstruct block id
		id = ReconstructCounter<16, u32>(group->largest_id, id);

		// Pong first packet of each group as fast as possible
		if (id == 0) {
			SendPong(code_group);
		}

		// If ID is the largest seen so far,
		if (id > group->largest_id) {
			// Update largest seen ID for decoding ID in next packet
			group->largest_id = id;
		}

		// Packet that will contain this data
		Packet *p;

		// If it is next in sequence,
		if (code_group == _next_group && id == _next_id) {
			// Pass it along immediately
			_settings.sink->OnPacket(data);

			// Increment ID
			_next_id++;

			// If just finished the group,
			if ((block_count && _next_id >= block_count) ||
					ProcessOOS(group)) {
				// Zero-loss case.
				// ProcessOOS() can return true and finish the group when
				// all needed packet data was found in OOS list.
				FinishGroup(group);
				return;
			}

			// NOTE: At this point we have not received all the original
			// data yet, so store anything we get for recovery:
			p = AllocatePacket(id, data);

			// Add to passed list since it was already passed along
			group->AddPassed(p);

			// Fall-thru to handle out of sequence case with recovery:
		} else {
			// Zero-loss case: If seen all the original data for this group,
			if (block_count && group->original_seen >= block_count) {
				// Ignore any new data
				return;
			}

			// Otherwise: Store any data we receive until we get a chance
			// to run the decoder on it.
			p = AllocatePacket(id, data);

			// If out of sequence original data,
			if (!block_count || id < block_count) {
				// Add to out of sequence list
				group->AddOOS(p);
			} else {
				// Add to recovery list
				group->AddRecovery(p);
			}

			// Fall-thru to try to recover with the new data
		}

		// If waiting for this group and recovery is possible,
		if (code_group == _next_group && group->CanRecover()) {
			if (AttemptRecovery(group, p)) {
				// Recover and pass all the packets
				RecoverGroup(group);

				// Finish off this group
				FinishGroup(group);

				// Stop here
				return;
			}
		}

		// TODO: Implement IV-based packet-loss estimator
	}

protected:

public:
	CAT_INLINE Brook() {
		_intialized = false;
	}

	CAT_INLINE virtual ~Brook() {
		Finalize();
	}

	// On startup:
	bool Initialize(const u8 key[SKEY_BYTES], const SourceSettings &settings) {
		Finalize();

		_clock.OnInitialize();

		_settings = settings;

		if (_cipher.Initialize(key, "BROOK", _settings.initiator ? calico::INITIATOR : calico::RESPONDER)) {
			return false;
		}

		CAT_ENFORCE(_settings.max_size <= MAX_CHUNK_SIZE);

		_encoder.Initialize(_settings.max_size);

		_delay.Initialize(_settings.min_delay, _settings.max_delay);
		_loss.Initialize(_settings.min_loss);

		_last_swap_time = 0;
		_code_group = 0;

		const int buffer_size = BROOK_OVERHEAD + _settings.max_size;

		// Allocate recovery packet workspace
		_packet_buffer.resize(buffer_size);

		// Initialize packet storage buffer allocator
		_allocator.Initialize(sizeof(Packet) - 1 + buffer_size);

		CAT_OBJCLR(_group_stamps);

		CalculateInterval();

		_intialized = true;
	}

	// Cleanup
	void Finalize() {
		if (_intialized) {
			_encoder.Finalize();

			_clock.OnFinalize();

			_intialized = false;
		}
	}

	// Send a new packet
	void Send(const void *data, int len) {
		CAT_ENFORCE(len < _settings.max_size);

		Sent *p = _encoder.QueueSent();

		// Store length
		p->size = (u16)len;

		u8 *buffer = p->data;

		// Add next code group (this is part of the code group after the next swap)
		buffer[0] = _code_group + 1;

		u16 block_count = _encoder.GetCurrentCount();

		// On first packet of a group,
		if (block_count == 1) {
			// Tag this new group with the start time
			_group_stamps[_code_group + 1] = m_clock.msec();
		}

		// Add check symbol number
		*(u16*)(buffer + 1) = getLE(block_count - 1);

		// For original data send the current block count, which will
		// always be one ahead of the block ID.
		// NOTE: This allows the decoder to know when it has received
		// all the packets in a code group for the zero-loss case.
		*(u16*)(buffer + 1 + 2) = getLE(block_count);

		// Copy input data into place
		memcpy(buffer + PROTOCOL_OVERHEAD, data, len);

		// Encrypt
		bytes = _cipher.Encrypt(buffer, PROTOCOL_OVERHEAD + bytes, _packet_buffer.get(), _packet_buffer.size());

		// Transmit
		_settings.source->SendData(_packet_buffer.get(), bytes);
	}

	// Called once per tick, about 10-20 ms
	void Tick() {
		const u32 ms = _clock.msec();

		const int recovery_time = ms - _last_swap_time;
		int expected_sent = _redundant_count;

		// If not swapping the encoder this tick,
		if (recovery_time < _swap_interval) {
			int elapsed = ((_redundant_count + 1) * recovery_time) / _swap_interval;

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
		if (recovery_time >= _swap_interval) {
			_last_swap_time = ms;

			// Calculate number of redundant packets to send this time
			_redundant_count = CalculateRedundancy(_loss.Get(), _encoder.GetCurrentCount(), _settings.target_loss);
			_redundant_sent = 0;

			// Select next code group
			_code_group++;

			// NOTE: These packets will be spread out over the swap interval

			// Start encoding queued data in another thread
			_encoder.EncodeQueued();
		}
	}

	void OnOOB(u8 *pkt, int len) {
		switch (pkt[1]) {
		case 0xff:
			if (len == PONG_SIZE) {
			}
			break;
		}
	}

	// On packet received
	void Recv(u8 *pkt, int len) {
		u32 ms = _clock.msec();

		u64 iv;
		len = _cipher.Decrypt(pkt, len, iv);

		// If it is a pong,
		if (len >= PROTOCOL_OVERHEAD) {
			// Read packet data
			u8 code_group = pkt[0];

			// If out of band,
			if (code_group & 0x80) {
				OnOOB(pkt, len);
			} else {
				OnData(pkt, len);
			}

			u32 seen = getLE(*(u32*)(pkt + 1));
			u32 count = getLE(*(u32*)(pkt + 1 + 4));

			// Calculate RTT
			int rtt = ms - _group_stamps[code_group];
			if (rtt > 0) {
				// Compute updates
				UpdateRTT(rtt);
				UpdateLoss(seen, count);
			}
		}
	}
};




// TODO: Add startup mode where we accept any code group as the first one

	// Send collected statistics
	void SendPong(int code_group) {
		u8 pkt[PONG_SIZE + calico::Calico::OVERHEAD];

		// Write packet
		pkt[0] = (u8)code_group;
		*(u32*)(pkt + 1) = getLE(_seen);
		*(u32*)(pkt + 1 + 4) = getLE(_count);

		// Reset statistics
		_seen = _count = 0;

		// Encrypt pong
		int len = _cipher.Encrypt(pkt, PONG_SIZE, pkt, sizeof(pkt));

		CAT_DEBUG_ENFORCE(len == sizeof(pkt));

		// Send it
		_settings.sink->SendData(pkt, len);
	}

	Packet *AllocatePacket(u32 id, const void *data) {
		Packet *p = _allocator.AcquireObject<Packet>();
		p->batch_next = 0;
		p->id = id;
		memcpy(p->data, data, _settings.chunk_size);
		return p;
	}

	void FreePacket(Packet *p) {
		_allocator.ReleaseBatch(p);
	}

	void FinishGroup(Group *group) {
		CAT_DEBUG_ENFORCE(group == &_groups[_next_group]);

		for (;;) {
			// If group was open,
			if (group->open) {
				// Close off this group.
				group->Close(_allocator);
			}

			// Decoder is now inactive
			_decoding = false;

			// Set next expected (group, id)
			_next_group++;
			_next_id = 0;

			// The relative group will now be -1 = 255,
			// so further packets for this group will be
			// dropped until the group id rolls back around.

			// Pass as many from the next group as we can now
			group = &_group[_next_group];

			// If not finished another group immediately,
			if (!ProcessOOS(group)) {
				// If group is not recoverable now,
				if (!group->CanRecover() || !AttemptRecovery(group)) {
					break;
				}

				// Recover and pass all the packets
				RecoverGroup(group);
			}
		}
	}

	// Returns true if code group was finished, so packet can be discarded
	bool ProcessOOS(CodeGroup *group) {
		// O(1) Check OOS
		Packet *oos = group->oos_head;
		while (oos && oos->id == _next_id) {
			// Pass along queued data
			_settings.sink->OnPacket(oos->data);

			// Increment ID
			_next_id++;

			// If just finished the group,
			if (block_count && _next_id >= group->block_count) {
				return true;
			}

			// Store next in oos list
			Packet *next = (Packet*)oos->batch_next;

			// Pop off OOS head
			group->PopOOS();

			// Add it to passed list
			group->AddPassed(oos);

			// Continue with next
			oos = next;
		}

		return false;
	}

	// Recover the remaining blocks for a code group and pass them on
	void RecoverGroup(CodeGroup *group) {
		// Acquire some memory temporarily to store the recovered block
		Packet *p = _allocator.AcquireObject<Packet>();

		do {
			// Reconstruct the block for the next expected ID
			_decoder.ReconstructBlock(_next_id, p->data);

			// Pass along queued data
			_settings.sink->OnPacket(p->data);

			// Increment ID
			_next_id++;

			// Process OOS original data until we get stuck again or finish
		while (!ProcessOOS(group));

		// NOTE: Message is now completely delivered

		// Free temporary memory
		FreePacket(p);
	}

	// Returns true if recovery succeeded
	bool AttemptRecovery(CodeGroup *group, Packet *p = 0) {
		wirehair::Result r;

		// If not decoding yet,
		if (!_decoding) {
			r = _decoder.InitializeDecoder(block_count * _settings.chunk_size, _settings.chunk_size);

			// We should always initialize correctly
			CAT_ENFORCE(!r && _decoder.BlockCount() == block_count);

			// Decoding process has started
			_decoding = true;

			// Add Recovery packets
			for (Packet *op = group->head; op; op = (Packet*)op->batch_next) {
				r = _decoder.DecodeFeed(op->id, op->data);
				if (!r) {
					return true;
				}
			}
		} else if (p) {
			// Feed the latest packet
			r = _decoder.DecodeFeed(p->id, p->data);
			if (!r) {
				return true;
			}
		} else {
			// Cannot recover without any new data
			return false;
		}

		return false;
	}

public:
	// On startup:
	bool Initialize(const u8 key[SKEY_BYTES], const SinkSettings &settings) {
		if (_cipher.Initialize(key, "BROOK", calico::INITIATOR)) {
			return false;
		}

		_settings = settings;

		_decoding = false;

		// Expect (0, 0) first
		_next_group = _next_id = 0;

		_group_timeout = 0;

		// Initialize the packet allocator
		_allocator.Initialize(sizeof(Packet)-1 + _settings.chunk_size);

		// Clear group data
		CAT_OBJCLR(_groups);
	}

	// On packet received
	void Recv(u8 *pkt, int len) {
		u32 ms = _clock.msec();

		u64 iv;
		len = _cipher.Decrypt(pkt, len, iv);

		// If packet contains data,
		if (len > PROTOCOL_OVERHEAD) {
			// Read packet data
			u8 code_group = pkt[0];

			// Rotate group id
			u8 relative_group = code_group - _next_group;

			// If received group is in the past,
			if (relative_group > PAST_GROUP_THRESH) {
				// Ignore data in the past, which happens often
				// when there is no packet loss and the error
				// correction codes are not useful.
				return;
			}

			CodeGroup *group = &_groups[code_group];

			u32 id = getLE(*(u16*)(pkt + 1));
			u16 block_count = getLE(*(u16*)(pkt + 1 + 2));
			u8 *data = pkt + PROTOCOL_OVERHEAD;

			// Reconstruct block id
			id = ReconstructCounter<16, u32>(group->largest_id, id);

			// Pong first packet of each group as fast as possible
			if (id == 0) {
				SendPong(code_group);
			}

			// Attempt to fill in block count if it is already known
			if (block_count == 0) {
				block_count = group->block_count;
			}

			// If group is not open yet,
			if (!group->open) {
				// Open group
				group->Open(ms);
			}

			// If ID is the largest seen so far,
			if (id > group->largest_id) {
				// Update largest seen ID for decoding ID in next packet
				group->largest_id = id;
			}

			// Packet that will contain this data
			Packet *p;

			// If it is next in sequence,
			if (code_group == _next_group && id == _next_id) {
				// Pass it along immediately
				_settings.sink->OnPacket(data);

				// Increment ID
				_next_id++;

				// If just finished the group,
				if ((block_count && _next_id >= block_count) ||
					ProcessOOS(group)) {
					// Zero-loss case.
					// ProcessOOS() can return true and finish the group when
					// all needed packet data was found in OOS list.
					FinishGroup(group);
					return;
				}

				// NOTE: At this point we have not received all the original
				// data yet, so store anything we get for recovery:
				p = AllocatePacket(id, data);

				// Add to passed list since it was already passed along
				group->AddPassed(p);

				// Fall-thru to handle out of sequence case with recovery:
			} else {
				// Zero-loss case: If seen all the original data for this group,
				if (block_count && group->original_seen >= block_count) {
					// Ignore any new data
					return;
				}

				// Otherwise: Store any data we receive until we get a chance
				// to run the decoder on it.
				p = AllocatePacket(id, data);

				// If out of sequence original data,
				if (!block_count || id < block_count) {
					// Add to out of sequence list
					group->AddOOS(p);
				} else {
					// Add to recovery list
					group->AddRecovery(p);
				}

				// Fall-thru to try to recover with the new data
			}

			// If waiting for this group and recovery is possible,
			if (code_group == _next_group && group->CanRecover()) {
				if (AttemptRecovery(group, p)) {
					// Recover and pass all the packets
					RecoverGroup(group);

					// Finish off this group
					FinishGroup(group);

					// Stop here
					return;
				}
			}

			// TODO: Implement IV-based packet-loss estimator
		}
	}
};









int main()
{
	return 0;
}


// TODO: Test it!

